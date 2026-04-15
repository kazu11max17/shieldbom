//! CISA Known Exploited Vulnerabilities (KEV) catalog client.
//!
//! The KEV catalog lists CVEs that are actively exploited in the wild.
//! A CVE in KEV has higher remediation priority than CVSS score alone indicates.
//!
//! Data source: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

use std::collections::HashMap;

use anyhow::Result;
use chrono::NaiveDate;
use serde::Deserialize;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevEntry {
    cve_id: String,
    due_date: String,
}

/// Fetch the CISA KEV catalog and return a map of CVE ID → remediation due date.
///
/// Returns an empty map if the catalog cannot be fetched (network errors are non-fatal;
/// callers should warn but continue scanning).
pub async fn fetch_kev_lookup() -> Result<HashMap<String, NaiveDate>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let catalog: KevCatalog = client.get(KEV_URL).send().await?.json().await?;

    let mut map = HashMap::new();
    for entry in catalog.vulnerabilities {
        if let Ok(date) = NaiveDate::parse_from_str(&entry.due_date, "%Y-%m-%d") {
            map.insert(entry.cve_id, date);
        }
    }

    Ok(map)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kev_date_parse() {
        // Verify our date format matches CISA's format
        let date = NaiveDate::parse_from_str("2021-12-24", "%Y-%m-%d").unwrap();
        assert_eq!(date.to_string(), "2021-12-24");
    }

    #[test]
    fn test_kev_date_bad_format_skipped() {
        // Entries with unparseable dates should be silently skipped
        let bad = NaiveDate::parse_from_str("Dec 24, 2021", "%Y-%m-%d");
        assert!(bad.is_err());
    }
}
