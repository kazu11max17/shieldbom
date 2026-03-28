use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::errors::ShieldBomError;
use crate::models::{Component, Severity, VulnMatch, VulnSource};

/// Default DB directory and file
const DB_DIR: &str = ".shieldbom";
const DB_FILE: &str = "vuln.db";

/// OSV ecosystem list endpoint for bulk data
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// Key ecosystems for embedded/IoT
const TARGET_ECOSYSTEMS: &[&str] = &[
    "crates.io",
    "npm",
    "PyPI",
    "Linux",
    "OSS-Fuzz",
    "Go",
    "Packagist",
    "Maven",
    "NuGet",
];

/// Well-known embedded packages to seed the DB with vulnerability data
const SEED_PACKAGES: &[(&str, &str)] = &[
    ("pkg:cargo/openssl", "crates.io"),
    ("pkg:cargo/hyper", "crates.io"),
    ("pkg:cargo/tokio", "crates.io"),
    ("pkg:cargo/serde", "crates.io"),
    ("pkg:cargo/reqwest", "crates.io"),
    ("pkg:pypi/cryptography", "PyPI"),
    ("pkg:pypi/requests", "PyPI"),
    ("pkg:pypi/flask", "PyPI"),
    ("pkg:pypi/django", "PyPI"),
    ("pkg:npm/express", "npm"),
    ("pkg:npm/lodash", "npm"),
    ("pkg:npm/axios", "npm"),
    ("pkg:maven/org.apache.logging.log4j/log4j-core", "Maven"),
    (
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
        "Maven",
    ),
    ("pkg:golang/golang.org/x/crypto", "Go"),
    ("pkg:golang/golang.org/x/net", "Go"),
];

// ---------------------------------------------------------------------------
// OSV API types for deserialization
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct OsvEcosystemQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<OsvPackageQuery>,
}

#[derive(serde::Serialize)]
struct OsvPackageQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    published: Option<String>,
    modified: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffected {
    #[serde(default, rename = "package")]
    pkg: Option<OsvAffectedPackage>,
    #[allow(dead_code)]
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedPackage {
    name: Option<String>,
    #[allow(dead_code)]
    ecosystem: Option<String>,
    purl: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct OsvRange {
    #[serde(rename = "type")]
    _range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

// ---------------------------------------------------------------------------
// Database path helpers
// ---------------------------------------------------------------------------

/// Get the default DB file path: ~/.shieldbom/vuln.db
pub fn default_db_path() -> Result<PathBuf> {
    let home = dirs_or_home()?;
    Ok(home.join(DB_DIR).join(DB_FILE))
}

fn dirs_or_home() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("Could not determine home directory (HOME not set)")
}

/// Ensure the DB directory exists
fn ensure_db_dir(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create DB directory: {}", parent.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema initialization
// ---------------------------------------------------------------------------

fn open_db(db_path: &PathBuf) -> Result<Connection> {
    ensure_db_dir(db_path)?;
    let conn = Connection::open(db_path)
        .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to open DB: {e}")))?;
    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id           TEXT NOT NULL,
            aliases      TEXT NOT NULL DEFAULT '',
            summary      TEXT NOT NULL DEFAULT '',
            details      TEXT NOT NULL DEFAULT '',
            severity     TEXT NOT NULL DEFAULT 'UNKNOWN',
            score        REAL,
            published    TEXT,
            modified     TEXT,
            affected_package  TEXT NOT NULL DEFAULT '',
            affected_versions TEXT NOT NULL DEFAULT '',
            purl         TEXT NOT NULL DEFAULT '',
            source       TEXT NOT NULL DEFAULT 'OSV',
            UNIQUE(id, purl)
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_purl ON vulnerabilities(purl);
        CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(affected_package);
        CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(id);

        CREATE TABLE IF NOT EXISTS metadata (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )
    .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to create schema: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API: update
// ---------------------------------------------------------------------------

/// Update the local vulnerability database by fetching data from OSV.dev
pub async fn update() -> Result<()> {
    let db_path = default_db_path()?;
    let conn = open_db(&db_path)?;

    eprintln!("Database location: {}", db_path.display());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut total_inserted: usize = 0;

    // Strategy: query OSV for each seed package to populate the DB
    for (purl, ecosystem) in SEED_PACKAGES {
        eprint!(
            "  Fetching vulnerabilities for {} ({})... ",
            purl, ecosystem
        );

        let query = OsvEcosystemQuery {
            package: Some(OsvPackageQuery {
                purl: Some(purl.to_string()),
                name: None,
                ecosystem: None,
            }),
        };

        match client.post(OSV_QUERY_URL).json(&query).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<OsvResponse>().await {
                Ok(osv_resp) => {
                    let count = osv_resp.vulns.len();
                    for vuln in &osv_resp.vulns {
                        insert_vuln(&conn, vuln)?;
                    }
                    total_inserted += count;
                    eprintln!("{} vulnerabilities", count);
                }
                Err(e) => {
                    eprintln!("parse error: {e}");
                }
            },
            Ok(resp) => {
                eprintln!("HTTP {}", resp.status());
            }
            Err(e) => {
                eprintln!("network error: {e}");
            }
        }
    }

    // Also query by ecosystem for broader coverage
    for ecosystem in TARGET_ECOSYSTEMS {
        eprint!("  Querying ecosystem '{}'... ", ecosystem);

        let query = OsvEcosystemQuery {
            package: Some(OsvPackageQuery {
                purl: None,
                name: Some(String::new()),
                ecosystem: Some(ecosystem.to_string()),
            }),
        };

        match client.post(OSV_QUERY_URL).json(&query).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<OsvResponse>().await {
                Ok(osv_resp) => {
                    let count = osv_resp.vulns.len();
                    for vuln in &osv_resp.vulns {
                        insert_vuln(&conn, vuln)?;
                    }
                    total_inserted += count;
                    eprintln!("{} vulnerabilities", count);
                }
                Err(_) => {
                    eprintln!("skipped (response too large or parse error)");
                }
            },
            Ok(resp) => {
                eprintln!("HTTP {}", resp.status());
            }
            Err(e) => {
                eprintln!("network error: {e}");
            }
        }
    }

    // Update metadata
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', ?1)",
        params![now],
    )
    .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to update metadata: {e}")))?;

    let record_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('record_count', ?1)",
        params![record_count.to_string()],
    )
    .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to update metadata: {e}")))?;

    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('source', 'OSV.dev')",
        [],
    )
    .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to update metadata: {e}")))?;

    eprintln!(
        "\nDone. {} total records fetched, {} records in database.",
        total_inserted, record_count
    );

    Ok(())
}

fn insert_vuln(conn: &Connection, vuln: &OsvVuln) -> Result<()> {
    let aliases = vuln.aliases.join(",");
    let (severity_str, score) = extract_severity_from_osv(vuln);
    let published = vuln.published.as_deref().unwrap_or("");
    let modified = vuln.modified.as_deref().unwrap_or("");

    if vuln.affected.is_empty() {
        // Insert with no specific package info
        conn.execute(
            "INSERT OR REPLACE INTO vulnerabilities
             (id, aliases, summary, details, severity, score, published, modified,
              affected_package, affected_versions, purl, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                vuln.id,
                aliases,
                vuln.summary,
                vuln.details,
                severity_str,
                score,
                published,
                modified,
                "",
                "",
                "",
                "OSV",
            ],
        )
        .map_err(|e| ShieldBomError::DatabaseError(format!("Insert failed: {e}")))?;
    } else {
        for affected in &vuln.affected {
            let pkg_name = affected
                .pkg
                .as_ref()
                .and_then(|p| p.name.as_deref())
                .unwrap_or("");
            let purl = affected
                .pkg
                .as_ref()
                .and_then(|p| p.purl.as_deref())
                .unwrap_or("");
            let versions = affected.versions.join(",");

            conn.execute(
                "INSERT OR REPLACE INTO vulnerabilities
                 (id, aliases, summary, details, severity, score, published, modified,
                  affected_package, affected_versions, purl, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    vuln.id,
                    aliases,
                    vuln.summary,
                    vuln.details,
                    severity_str,
                    score,
                    published,
                    modified,
                    pkg_name,
                    versions,
                    purl,
                    "OSV",
                ],
            )
            .map_err(|e| ShieldBomError::DatabaseError(format!("Insert failed: {e}")))?;
        }
    }

    Ok(())
}

fn extract_severity_from_osv(vuln: &OsvVuln) -> (String, Option<f64>) {
    for sev in &vuln.severity {
        if sev.severity_type.as_deref() == Some("CVSS_V3") {
            if let Some(score_str) = &sev.score {
                if let Ok(score) = score_str.parse::<f64>() {
                    let label = Severity::from_cvss(score).to_string();
                    return (label, Some(score));
                }
            }
        }
    }
    ("UNKNOWN".to_string(), None)
}

// ---------------------------------------------------------------------------
// Public API: info
// ---------------------------------------------------------------------------

/// Show database info (last update, record count, DB file size)
pub fn info() -> Result<String> {
    let db_path = default_db_path()?;

    if !db_path.exists() {
        return Ok(format!(
            "Local vulnerability database: not initialized.\n\
             Expected location: {}\n\
             Run 'shieldbom db update' to download.",
            db_path.display()
        ));
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to open DB: {e}")))?;

    let last_updated = get_metadata(&conn, "last_updated").unwrap_or_else(|| "never".to_string());
    let source = get_metadata(&conn, "source").unwrap_or_else(|| "unknown".to_string());

    let record_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
        .unwrap_or(0);

    let file_size = fs::metadata(&db_path)
        .map(|m| format_size(m.len()))
        .unwrap_or_else(|_| "unknown".to_string());

    let unique_vulns: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT id) FROM vulnerabilities",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let unique_packages: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT affected_package) FROM vulnerabilities WHERE affected_package != ''",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(format!(
        "ShieldBOM Local Vulnerability Database\n\
         ======================================\n\
         Location:          {}\n\
         File size:         {}\n\
         Source:            {}\n\
         Last updated:      {}\n\
         Total records:     {}\n\
         Unique vulns:      {}\n\
         Unique packages:   {}",
        db_path.display(),
        file_size,
        source,
        last_updated,
        record_count,
        unique_vulns,
        unique_packages,
    ))
}

fn get_metadata(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

// ---------------------------------------------------------------------------
// Public API: export / import (air-gapped workflow)
// ---------------------------------------------------------------------------

/// Statistics about a database, returned after export or import operations.
#[derive(Debug, Clone)]
pub struct DbStats {
    pub total_records: i64,
    pub unique_cves: i64,
    pub last_updated: String,
    pub file_size: String,
}

/// Export the local vulnerability database to a portable file.
///
/// Workflow (connected machine):
///   1. `shieldbom db update`
///   2. `shieldbom db export vuln-db.sqlite`
///   3. Transfer file via USB to air-gapped machine
///   4. `shieldbom db import vuln-db.sqlite`
pub fn export(output: &Path) -> Result<DbStats> {
    let db_path = default_db_path()?;

    if !db_path.exists() {
        anyhow::bail!(
            "Local vulnerability database not found at {}.\n\
             Run 'shieldbom db update' first to download vulnerability data.",
            db_path.display()
        );
    }

    // Copy the DB file to the output path
    fs::copy(&db_path, output).with_context(|| {
        format!(
            "Failed to copy database from {} to {}",
            db_path.display(),
            output.display()
        )
    })?;

    // Return stats about the exported file
    collect_db_stats(output)
}

/// Import a vulnerability database file into the local cache.
///
/// Validates that the file is a valid ShieldBOM database before overwriting
/// the existing local cache.
pub fn import(source: &Path) -> Result<DbStats> {
    if !source.exists() {
        anyhow::bail!("Import file not found: {}", source.display());
    }

    // Validate the source file is a valid ShieldBOM database
    validate_shieldbom_db(source)?;

    // Collect stats before copying (for display)
    let stats = collect_db_stats(source)?;

    // Copy to local cache location
    let db_path = default_db_path()?;
    ensure_db_dir(&db_path)?;

    fs::copy(source, &db_path).with_context(|| {
        format!(
            "Failed to copy database from {} to {}",
            source.display(),
            db_path.display()
        )
    })?;

    eprintln!("  Installed to: {}", db_path.display());

    Ok(stats)
}

/// Validate that a file is a valid ShieldBOM SQLite database.
///
/// Checks:
///   1. File is a valid SQLite database (can be opened)
///   2. Contains the `vulnerabilities` table with the expected schema
///   3. Contains the `metadata` table
fn validate_shieldbom_db(path: &Path) -> Result<()> {
    let conn = Connection::open(path).map_err(|e| {
        ShieldBomError::DatabaseError(format!("File is not a valid SQLite database: {e}"))
    })?;

    // Check for vulnerabilities table
    let has_vulns: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='vulnerabilities'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            ShieldBomError::DatabaseError(format!("Failed to query database schema: {e}"))
        })?;

    if !has_vulns {
        anyhow::bail!(
            "Invalid ShieldBOM database: missing 'vulnerabilities' table.\n\
             The file may not be a ShieldBOM database export."
        );
    }

    // Check for metadata table
    let has_metadata: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='metadata'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            ShieldBomError::DatabaseError(format!("Failed to query database schema: {e}"))
        })?;

    if !has_metadata {
        anyhow::bail!(
            "Invalid ShieldBOM database: missing 'metadata' table.\n\
             The file may not be a ShieldBOM database export."
        );
    }

    // Verify the vulnerabilities table has expected columns by running a lightweight query
    conn.query_row(
        "SELECT id, purl, severity FROM vulnerabilities LIMIT 0",
        [],
        |_row| Ok(()),
    )
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(()),
        _ => Err(e),
    })
    .map_err(|e| {
        ShieldBomError::DatabaseError(format!(
            "Invalid ShieldBOM database: 'vulnerabilities' table has unexpected schema: {e}"
        ))
    })?;

    Ok(())
}

/// Collect statistics from a database file.
fn collect_db_stats(path: &Path) -> Result<DbStats> {
    let conn = Connection::open(path)
        .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to open DB: {e}")))?;

    let total_records: i64 = conn
        .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
        .unwrap_or(0);

    let unique_cves: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT id) FROM vulnerabilities",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let last_updated = get_metadata(&conn, "last_updated").unwrap_or_else(|| "unknown".to_string());

    let file_size = fs::metadata(path)
        .map(|m| format_size(m.len()))
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(DbStats {
        total_records,
        unique_cves,
        last_updated,
        file_size,
    })
}

// ---------------------------------------------------------------------------
// Public API: offline vulnerability lookup
// ---------------------------------------------------------------------------

/// Look up vulnerabilities for a list of components using the local SQLite DB.
/// This is the function called from src/vuln/mod.rs when --offline is set.
pub fn lookup_offline(components: &[Component]) -> Result<Vec<VulnMatch>> {
    lookup_offline_with_path(components, &default_db_path()?)
}

/// Look up vulnerabilities using a specific DB path (useful for testing / custom DB location)
pub fn lookup_offline_with_path(
    components: &[Component],
    db_path: &PathBuf,
) -> Result<Vec<VulnMatch>> {
    if !db_path.exists() {
        return Err(ShieldBomError::DatabaseError(format!(
            "Local vulnerability database not found at {}. Run 'shieldbom db update' first.",
            db_path.display()
        ))
        .into());
    }

    let conn = Connection::open(db_path)
        .map_err(|e| ShieldBomError::DatabaseError(format!("Failed to open DB: {e}")))?;

    let mut results = Vec::new();

    for component in components {
        let mut matches = Vec::new();

        // Strategy 1: Match by PURL (most precise)
        if let Some(purl) = &component.purl {
            let purl_prefix = strip_purl_version(purl);
            let mut stmt = conn
                .prepare(
                    "SELECT id, aliases, summary, details, severity, score,
                            affected_versions, purl
                     FROM vulnerabilities
                     WHERE purl LIKE ?1",
                )
                .map_err(|e| ShieldBomError::DatabaseError(format!("Query failed: {e}")))?;

            let rows = stmt
                .query_map(params![format!("{}%", purl_prefix)], |row| {
                    Ok(VulnRow {
                        id: row.get(0)?,
                        aliases: row.get(1)?,
                        summary: row.get(2)?,
                        _details: row.get(3)?,
                        severity: row.get(4)?,
                        score: row.get(5)?,
                        affected_versions: row.get(6)?,
                        _purl: row.get(7)?,
                    })
                })
                .map_err(|e| ShieldBomError::DatabaseError(format!("Query failed: {e}")))?;

            for vr in rows.flatten() {
                if is_version_affected(&component.version, &vr.affected_versions) {
                    matches.push(vuln_row_to_match(&vr, component));
                }
            }
        }

        // Strategy 2: Match by package name (fallback)
        if matches.is_empty() {
            let mut stmt = conn
                .prepare(
                    "SELECT id, aliases, summary, details, severity, score,
                            affected_versions, purl
                     FROM vulnerabilities
                     WHERE affected_package = ?1 OR affected_package LIKE ?2",
                )
                .map_err(|e| ShieldBomError::DatabaseError(format!("Query failed: {e}")))?;

            let name_pattern = format!("%/{}", component.name);
            let rows = stmt
                .query_map(params![component.name, name_pattern], |row| {
                    Ok(VulnRow {
                        id: row.get(0)?,
                        aliases: row.get(1)?,
                        summary: row.get(2)?,
                        _details: row.get(3)?,
                        severity: row.get(4)?,
                        score: row.get(5)?,
                        affected_versions: row.get(6)?,
                        _purl: row.get(7)?,
                    })
                })
                .map_err(|e| ShieldBomError::DatabaseError(format!("Query failed: {e}")))?;

            for vr in rows.flatten() {
                if is_version_affected(&component.version, &vr.affected_versions) {
                    matches.push(vuln_row_to_match(&vr, component));
                }
            }
        }

        results.extend(matches);
    }

    // Deduplicate
    results.sort_by(|a, b| (&a.component_name, &a.cve_id).cmp(&(&b.component_name, &b.cve_id)));
    results.dedup_by(|a, b| a.component_name == b.component_name && a.cve_id == b.cve_id);

    Ok(results)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct VulnRow {
    id: String,
    aliases: String,
    summary: String,
    _details: String,
    severity: String,
    score: Option<f64>,
    affected_versions: String,
    _purl: String,
}

fn vuln_row_to_match(vr: &VulnRow, component: &Component) -> VulnMatch {
    // Use first CVE alias if available, otherwise the OSV id
    let cve_id = vr
        .aliases
        .split(',')
        .find(|a| a.starts_with("CVE-"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| vr.id.clone());

    let severity = match vr.severity.as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        "NONE" => Severity::None,
        _ => Severity::Unknown,
    };

    VulnMatch {
        component_name: component.name.clone(),
        component_version: component.version.clone(),
        cve_id,
        severity,
        cvss_score: vr.score,
        source: VulnSource::LocalDb,
        affected_versions: vr.affected_versions.clone(),
        fixed_version: None,
        description: vr.summary.clone(),
    }
}

/// Strip version from a PURL for prefix matching.
/// e.g. "pkg:cargo/serde@1.0.0" -> "pkg:cargo/serde"
/// Handles scoped packages like "pkg:npm/@scope/pkg@2.0"
fn strip_purl_version(purl: &str) -> &str {
    // Find the last '@' that follows a '/' — that's the version separator.
    // Scoped npm packages have '@' as part of the name (e.g. @scope/pkg).
    if let Some(slash_pos) = purl.rfind('/') {
        if let Some(at_pos) = purl[slash_pos..].rfind('@') {
            return &purl[..slash_pos + at_pos];
        }
    }
    // Fallback: no '/' found, just split on last '@'
    if let Some(at_pos) = purl.rfind('@') {
        &purl[..at_pos]
    } else {
        purl
    }
}

/// Check if the component version appears in the comma-separated affected_versions list.
/// If affected_versions is empty, we consider it a match (conservative: assume affected).
fn is_version_affected(component_version: &str, affected_versions: &str) -> bool {
    if affected_versions.is_empty() {
        // No version info means we conservatively report it
        return true;
    }

    let versions: Vec<&str> = affected_versions.split(',').map(|s| s.trim()).collect();
    versions.contains(&component_version)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_purl_version() {
        assert_eq!(
            strip_purl_version("pkg:cargo/serde@1.0.0"),
            "pkg:cargo/serde"
        );
        assert_eq!(strip_purl_version("pkg:cargo/serde"), "pkg:cargo/serde");
        assert_eq!(
            strip_purl_version("pkg:npm/@scope/pkg@2.0"),
            "pkg:npm/@scope/pkg"
        );
    }

    #[test]
    fn test_is_version_affected() {
        assert!(is_version_affected("1.0.0", "0.9.0,1.0.0,1.1.0"));
        assert!(!is_version_affected("2.0.0", "0.9.0,1.0.0,1.1.0"));
        // Empty affected_versions -> conservative match
        assert!(is_version_affected("1.0.0", ""));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1_572_864), "1.5 MB");
    }

    #[test]
    fn test_schema_creation() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vulnerabilities'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='metadata'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_and_lookup() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Insert a test vulnerability
        conn.execute(
            "INSERT INTO vulnerabilities
             (id, aliases, summary, details, severity, score, published, modified,
              affected_package, affected_versions, purl, source)
             VALUES ('GHSA-test-1234', 'CVE-2024-1234', 'Test vuln', 'Details here',
                     'HIGH', 7.5, '2024-01-01', '2024-01-02',
                     'serde', '1.0.0,1.0.1,1.0.2', 'pkg:cargo/serde', 'OSV')",
            [],
        )
        .unwrap();

        // Verify it was inserted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_validate_shieldbom_db_valid() {
        // Create a valid ShieldBOM DB in a temp file
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("valid.db");
        let conn = Connection::open(&db_path).unwrap();
        init_schema(&conn).unwrap();

        // Insert some test data
        conn.execute(
            "INSERT INTO vulnerabilities
             (id, aliases, summary, details, severity, score, published, modified,
              affected_package, affected_versions, purl, source)
             VALUES ('CVE-2024-0001', '', 'Test', '', 'HIGH', 7.5, '', '', 'pkg', '1.0', 'pkg:cargo/pkg', 'OSV')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('last_updated', '2024-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        drop(conn);

        // Should succeed
        assert!(validate_shieldbom_db(&db_path).is_ok());
    }

    #[test]
    fn test_validate_shieldbom_db_invalid_not_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let bad_file = dir.path().join("not-sqlite.db");
        std::fs::write(&bad_file, b"this is not a sqlite file").unwrap();

        // Should fail — not a valid SQLite file
        // Note: rusqlite may open it but the schema query will fail
        let result = validate_shieldbom_db(&bad_file);
        // It may or may not error on open vs query, but should not succeed validation
        // because the tables won't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shieldbom_db_missing_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("empty.db");
        let conn = Connection::open(&db_path).unwrap();
        // Create an empty SQLite DB (no ShieldBOM tables)
        conn.execute_batch("CREATE TABLE IF NOT EXISTS something (id TEXT);")
            .unwrap();
        drop(conn);

        let result = validate_shieldbom_db(&db_path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("vulnerabilities"));
    }

    #[test]
    fn test_collect_db_stats() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats.db");
        let conn = Connection::open(&db_path).unwrap();
        init_schema(&conn).unwrap();

        // Insert 3 records (2 unique CVE IDs)
        for (id, purl) in &[
            ("CVE-2024-0001", "pkg:cargo/a"),
            ("CVE-2024-0001", "pkg:cargo/b"),
            ("CVE-2024-0002", "pkg:cargo/c"),
        ] {
            conn.execute(
                "INSERT INTO vulnerabilities
                 (id, aliases, summary, details, severity, score, published, modified,
                  affected_package, affected_versions, purl, source)
                 VALUES (?1, '', 'Test', '', 'HIGH', 7.5, '', '', '', '1.0', ?2, 'OSV')",
                params![id, purl],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('last_updated', '2024-06-15T12:00:00Z')",
            [],
        )
        .unwrap();
        drop(conn);

        let stats = collect_db_stats(&db_path).unwrap();
        assert_eq!(stats.total_records, 3);
        assert_eq!(stats.unique_cves, 2);
        assert_eq!(stats.last_updated, "2024-06-15T12:00:00Z");
    }

    #[test]
    fn test_export_and_import_roundtrip() {
        // This test uses explicit paths rather than default_db_path(),
        // so we test the core logic (copy + validate + stats) directly.
        let dir = tempfile::tempdir().unwrap();
        let source_db = dir.path().join("source.db");
        let exported = dir.path().join("exported.db");
        let reimported = dir.path().join("reimported.db");

        // Create source DB
        let conn = Connection::open(&source_db).unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO vulnerabilities
             (id, aliases, summary, details, severity, score, published, modified,
              affected_package, affected_versions, purl, source)
             VALUES ('CVE-2024-9999', 'GHSA-xxxx', 'Export test', 'Details', 'CRITICAL', 9.8,
                     '2024-01-01', '2024-01-02', 'test-pkg', '1.0.0,1.0.1', 'pkg:cargo/test-pkg', 'OSV')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', '2024-07-01T00:00:00Z')",
            [],
        ).unwrap();
        drop(conn);

        // Export = copy + stats
        fs::copy(&source_db, &exported).unwrap();
        let export_stats = collect_db_stats(&exported).unwrap();
        assert_eq!(export_stats.total_records, 1);
        assert_eq!(export_stats.unique_cves, 1);
        assert_eq!(export_stats.last_updated, "2024-07-01T00:00:00Z");

        // Validate the exported file
        assert!(validate_shieldbom_db(&exported).is_ok());

        // Import = validate + copy + stats
        validate_shieldbom_db(&exported).unwrap();
        fs::copy(&exported, &reimported).unwrap();
        let import_stats = collect_db_stats(&reimported).unwrap();

        assert_eq!(import_stats.total_records, export_stats.total_records);
        assert_eq!(import_stats.unique_cves, export_stats.unique_cves);
        assert_eq!(import_stats.last_updated, export_stats.last_updated);

        // Verify data integrity in reimported DB
        let conn = Connection::open(&reimported).unwrap();
        let summary: String = conn
            .query_row(
                "SELECT summary FROM vulnerabilities WHERE id = 'CVE-2024-9999'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary, "Export test");
    }

    #[test]
    fn test_extract_severity() {
        let vuln = OsvVuln {
            id: "TEST-001".to_string(),
            aliases: vec![],
            summary: String::new(),
            details: String::new(),
            severity: vec![OsvSeverity {
                severity_type: Some("CVSS_V3".to_string()),
                score: Some("9.8".to_string()),
            }],
            affected: vec![],
            published: None,
            modified: None,
        };
        let (sev, score) = extract_severity_from_osv(&vuln);
        assert_eq!(sev, "CRITICAL");
        assert_eq!(score, Some(9.8));
    }
}
