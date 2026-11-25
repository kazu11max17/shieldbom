//! Known-answer regression tests against the live OSV.dev / NVD / CISA KEV APIs.
//!
//! In v0.3.x, unit tests passed while real scans were wrong (a
//! `pkg:generic` component silently returning nothing, OpenSSL letter versions
//! like 1.0.1g not being compared, fixes suggested from another release line,
//! rejected CVEs being reported). These tests scan SBOMs whose answer is known
//! and check that specific CVEs are, or are not, reported. Total counts are not
//! checked: they change whenever NVD is updated.
//!
//! They need network access and are ignored by default. Run them with:
//!
//! ```text
//! cargo test -p shieldbom --test known_answer_live -- --ignored --test-threads=1
//! ```
//!
//! Without an API key NVD allows few requests per 30 seconds; set
//! `SHIELDBOM_NVD_API_KEY` (read by the scanner itself) if lookups fail.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/known-answer");

/// The scan's JSON report and exit code.
struct Scan {
    report: Value,
    exit_code: i32,
}

impl Scan {
    fn vulns(&self) -> &[Value] {
        self.report["vulnerabilities"]
            .as_array()
            .expect("report has a vulnerabilities array")
    }

    fn find(&self, cve: &str) -> Option<&Value> {
        self.vulns().iter().find(|v| v["cve_id"] == cve)
    }

    fn expect(&self, cve: &str) -> &Value {
        self.find(cve)
            .unwrap_or_else(|| panic!("{cve} was not reported"))
    }

    fn expect_absent(&self, cve: &str) {
        if let Some(v) = self.find(cve) {
            panic!("{cve} must not be reported, got: {v}");
        }
    }
}

/// Scans a fixture online (OSV/NVD/KEV) with JSON output. `HOME` points to an
/// empty directory so no local database or user configuration is read.
///
/// An incomplete scan (exit 2) fails the test: a failed lookup is not a known
/// answer, and passing on it would hide exactly the kind of gap these tests
/// exist for. Typically it is NVD rate limiting; set `SHIELDBOM_NVD_API_KEY`
/// or retry later.
fn scan(fixture: &str) -> Scan {
    let home = tempfile::tempdir().expect("create temp HOME");
    let path = PathBuf::from(FIXTURES).join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_shieldbom"))
        .arg("scan")
        .arg(&path)
        .args(["--format", "json"])
        .env("HOME", home.path())
        .env_remove("SHIELDBOM_API_KEY")
        .output()
        .expect("run shieldbom");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().expect("shieldbom exited normally");
    assert_ne!(
        exit_code, 2,
        "scan of {fixture} was incomplete or failed (exit 2); this is not a known answer. \
         If NVD rate limiting is mentioned below, set SHIELDBOM_NVD_API_KEY or retry later.\n\
         stderr:\n{stderr}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!("scan of {fixture} did not print a JSON report ({e})\nstderr:\n{stderr}")
    });
    let gaps = report["scan_gaps"].as_array().expect("scan_gaps array");
    assert!(gaps.is_empty(), "scan_gaps must be empty, got: {gaps:?}");
    Scan { report, exit_code }
}

#[test]
#[ignore = "queries live OSV/NVD; run: cargo test -p shieldbom --test known_answer_live -- --ignored --test-threads=1"]
fn openssl_3_0_8_generic() {
    let scan = scan("openssl-3.0.8-generic.cdx.json");
    assert_eq!(scan.exit_code, 1);

    // pkg:generic must reach NVD rather than return nothing.
    let v = scan.expect("CVE-2023-2650");
    assert_eq!(v["unconfirmed"], false, "CVE-2023-2650: {v}");
    assert_eq!(v["fixed_version"], "3.0.9", "CVE-2023-2650: {v}");

    // Heartbleed affects 1.0.1 through 1.0.1f (and 1.0.2-beta1), not 3.0.8.
    scan.expect_absent("CVE-2014-0160");

    // Rejected CVEs.
    for cve in ["CVE-2006-7248", "CVE-2006-7249", "CVE-2021-3601"] {
        scan.expect_absent(cve);
    }

    // The npm package "openssl.js" only shares the name.
    if let Some(v) = scan.find("CVE-2017-16065") {
        assert_eq!(v["unconfirmed"], true, "CVE-2017-16065: {v}");
    }

    // A confirmed finding must suggest a fix in the 3.0 line, never another line.
    for v in scan.vulns().iter().filter(|v| v["unconfirmed"] == false) {
        if let Some(fixed) = v["fixed_version"].as_str() {
            assert!(
                fixed.starts_with("3.0."),
                "fix from another release line suggested for 3.0.8: {v}"
            );
        }
    }
}

#[test]
#[ignore = "queries live OSV/NVD; run: cargo test -p shieldbom --test known_answer_live -- --ignored --test-threads=1"]
fn openssl_1_1_1k_conan() {
    let scan = scan("openssl-1.1.1k-conan.cdx.json");
    assert_eq!(scan.exit_code, 1);
    // OSV.dev returns nothing for pkg:conan; it must not end as a silent zero.
    assert!(
        !scan.vulns().is_empty(),
        "pkg:conan/openssl@1.1.1k gave 0 findings"
    );
    let v = scan.expect("CVE-2021-3711");
    assert_eq!(v["unconfirmed"], false, "CVE-2021-3711: {v}");
    assert_eq!(v["fixed_version"], "1.1.1l", "CVE-2021-3711: {v}");
}

#[test]
#[ignore = "queries live OSV/NVD; run: cargo test -p shieldbom --test known_answer_live -- --ignored --test-threads=1"]
fn openssl_1_0_1f_generic_heartbleed() {
    let scan = scan("openssl-1.0.1f-generic.cdx.json");
    assert_eq!(scan.exit_code, 1);
    let v = scan.expect("CVE-2014-0160");
    assert_eq!(v["unconfirmed"], false, "CVE-2014-0160: {v}");
    assert_eq!(v["in_kev"], true, "CVE-2014-0160 must be marked KEV: {v}");
    assert_eq!(v["fixed_version"], "1.0.1g", "CVE-2014-0160: {v}");
}

#[test]
#[ignore = "queries live OSV/NVD; run: cargo test -p shieldbom --test known_answer_live -- --ignored --test-threads=1"]
fn openssl_1_0_1g_generic_no_heartbleed() {
    let scan = scan("openssl-1.0.1g-generic.cdx.json");
    assert_eq!(scan.exit_code, 1);
    // A CVE fixed after 1.0.1g must still be found, so this test cannot pass
    // on a scan that silently found nothing.
    let v = scan.expect("CVE-2014-0224");
    assert_eq!(v["unconfirmed"], false, "CVE-2014-0224: {v}");
    assert_eq!(v["fixed_version"], "1.0.1h", "CVE-2014-0224: {v}");
    scan.expect_absent("CVE-2014-0160");
}
