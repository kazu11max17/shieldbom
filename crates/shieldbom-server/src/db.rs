use anyhow::Result;
use rand::Rng;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

pub fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            key_hash TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            sbom_filename TEXT NOT NULL,
            format_detected TEXT NOT NULL,
            total_components INTEGER NOT NULL,
            total_vulns INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            license_issues INTEGER NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ",
    )?;
    Ok(())
}

/// Generate a new API key: `sk_live_<40 hex chars>`.
/// Returns `(raw_key, key_prefix, key_hash)`.
pub fn generate_api_key() -> (String, String, String) {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    let secret = hex::encode(bytes);
    let raw_key = format!("sk_live_{secret}");
    let prefix = raw_key[..15].to_string(); // "sk_live_" + 7 hex
    let hash = hash_key(&raw_key);
    (raw_key, prefix, hash)
}

pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Look up an account_id by raw API key. Returns None if key is invalid or revoked.
pub fn verify_api_key(conn: &Connection, raw_key: &str) -> Result<Option<String>> {
    let key_hash = hash_key(raw_key);
    let mut stmt = conn.prepare(
        "SELECT ak.account_id FROM api_keys ak
         WHERE ak.key_hash = ?1 AND ak.revoked_at IS NULL",
    )?;
    let result = stmt.query_row(rusqlite::params![key_hash], |row| row.get::<_, String>(0));
    match result {
        Ok(account_id) => Ok(Some(account_id)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_generate_and_verify_key() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let account_id = "acc_test123";
        conn.execute(
            "INSERT INTO accounts (id, email, plan, created_at) VALUES (?1, ?2, 'free', '2026-01-01T00:00:00Z')",
            rusqlite::params![account_id, "test@example.com"],
        ).unwrap();

        let (raw_key, prefix, key_hash) = generate_api_key();
        assert!(raw_key.starts_with("sk_live_"));
        assert_eq!(prefix.len(), 15);

        conn.execute(
            "INSERT INTO api_keys (id, account_id, key_hash, key_prefix, created_at) VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z')",
            rusqlite::params!["key_1", account_id, key_hash, prefix],
        ).unwrap();

        let result = verify_api_key(&conn, &raw_key).unwrap();
        assert_eq!(result, Some(account_id.to_string()));

        // Invalid key returns None
        let result = verify_api_key(&conn, "sk_live_invalid").unwrap();
        assert_eq!(result, None);
    }
}
