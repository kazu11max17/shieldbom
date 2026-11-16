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
    // The feed spells it "cveID"; camelCase renaming would look for "cveId".
    #[serde(rename = "cveID")]
    cve_id: String,
    due_date: String,
}

/// Fetch the CISA KEV catalog and return a map of CVE ID -> remediation due date.
///
/// Returns `Err` when the catalog cannot be fetched or parsed. The caller
/// decides whether that makes the scan incomplete.
pub async fn fetch_kev_lookup() -> Result<HashMap<String, Option<NaiveDate>>> {
    // Identify the client honestly; some servers refuse requests with no User-Agent.
    let client = reqwest::Client::builder()
        .user_agent(concat!("shieldbom/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let catalog: KevCatalog = client
        .get(KEV_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(build_lookup(catalog))
}

/// Every listed CVE is kept even when its due date cannot be read: an
/// unparseable date must not turn a known-exploited CVE into a non-KEV one.
fn build_lookup(catalog: KevCatalog) -> HashMap<String, Option<NaiveDate>> {
    catalog
        .vulnerabilities
        .into_iter()
        .map(|entry| {
            let due = NaiveDate::parse_from_str(&entry.due_date, "%Y-%m-%d").ok();
            (entry.cve_id, due)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: the entry was declared as "cveId", so the real feed never
    // parsed and no vulnerability was ever flagged as known-exploited.
    #[test]
    fn test_kev_catalog_parses_real_feed_shape() {
        let json = r#"{
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.01.01",
            "count": 1,
            "vulnerabilities": [{
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-20"]
            }]
        }"#;
        let catalog: KevCatalog = serde_json::from_str(json).unwrap();
        assert_eq!(catalog.vulnerabilities[0].cve_id, "CVE-2021-44228");
        assert_eq!(catalog.vulnerabilities[0].due_date, "2021-12-24");
    }

    #[test]
    fn test_build_lookup_keeps_entries_with_bad_due_date() {
        let json = r#"{"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dueDate": "2021-12-24"},
            {"cveID": "CVE-2020-0001", "dueDate": "not-a-date"}
        ]}"#;
        let map = build_lookup(serde_json::from_str(json).unwrap());
        assert_eq!(
            map["CVE-2021-44228"],
            Some(NaiveDate::from_ymd_opt(2021, 12, 24).unwrap())
        );
        assert_eq!(map["CVE-2020-0001"], None);
    }

    #[test]
    fn test_kev_date_parse() {
        // Verify our date format matches CISA's format
        let date = NaiveDate::parse_from_str("2021-12-24", "%Y-%m-%d").unwrap();
        assert_eq!(date.to_string(), "2021-12-24");
    }

    #[test]
    fn test_kev_date_bad_format_does_not_parse() {
        // Such an entry keeps its CVE with no due date; see
        // test_build_lookup_keeps_entries_with_bad_due_date.
        let bad = NaiveDate::parse_from_str("Dec 24, 2021", "%Y-%m-%d");
        assert!(bad.is_err());
    }
}
