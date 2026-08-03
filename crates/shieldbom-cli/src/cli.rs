use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use shieldbom_core::models::Severity;
use shieldbom_core::report::{OutputFormat, ProductMetadata};

/// ShieldBOM - SBOM vulnerability scanner for embedded/IoT software
#[derive(Parser)]
#[command(
    name = "shieldbom",
    version,
    about,
    long_about = None,
    after_help = "\
EXIT CODES:
    0    No vulnerabilities or license issues found above threshold
    1    Vulnerabilities or license issues found above threshold
    2    Error (invalid input, parse failure, network error)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan an SBOM file for vulnerabilities and license issues
    Scan(Box<ScanArgs>),
    /// Validate SBOM format and completeness
    Validate(ValidateArgs),
    /// Manage local vulnerability database
    Db(DbArgs),
    /// Initialize ShieldBOM in the current project (generate CI config and shieldbom.toml)
    Init(InitArgs),
    /// Show version information
    Version,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Path to the SBOM file (SPDX or CycloneDX)
    pub file: PathBuf,

    /// Output format
    #[arg(long, short, value_enum)]
    pub format: Option<OutputFormat>,

    /// Minimum severity to report (default: medium)
    #[arg(long, default_value = "medium")]
    pub severity: SeverityFilter,

    /// Run in offline mode (use local database only)
    #[arg(long)]
    pub offline: bool,

    /// Also query NVD API 2.0 for vulnerabilities (slower, rate-limited)
    #[arg(long)]
    pub nvd: bool,

    /// Path to local vulnerability database
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Allow scanning with a stale local database (suppresses the >30 day error)
    #[arg(long)]
    pub allow_stale: bool,

    /// Upload scan results to ShieldBOM server
    #[arg(long)]
    pub sync: bool,

    /// API key for server authentication (or set SHIELDBOM_API_KEY env var)
    #[arg(long, env = "SHIELDBOM_API_KEY")]
    pub api_key: Option<String>,

    /// ShieldBOM server URL (or set SHIELDBOM_SERVER_URL env var)
    #[arg(
        long,
        env = "SHIELDBOM_SERVER_URL",
        default_value = "https://api.shieldbom.com"
    )]
    pub server: String,

    /// Write an SVG badge to this path after scanning
    #[arg(long)]
    pub badge: Option<PathBuf>,

    /// Product name for the CRA report (--format cra)
    #[arg(long, help_heading = "CRA report")]
    pub product_name: Option<String>,

    /// Product version for the CRA report (--format cra)
    #[arg(long, help_heading = "CRA report")]
    pub product_version: Option<String>,

    /// Manufacturer name for the CRA report (--format cra)
    #[arg(long, help_heading = "CRA report")]
    pub manufacturer: Option<String>,

    /// Security support period, e.g. "5 years from 2026-01-01" (--format cra)
    #[arg(long, help_heading = "CRA report")]
    pub support_period: Option<String>,

    /// How security updates are delivered to users (--format cra)
    #[arg(long, help_heading = "CRA report")]
    pub update_mechanism: Option<String>,
}

impl ScanArgs {
    pub fn severity_threshold(&self) -> Severity {
        match self.severity {
            SeverityFilter::Critical => Severity::Critical,
            SeverityFilter::High => Severity::High,
            SeverityFilter::Medium => Severity::Medium,
            SeverityFilter::Low => Severity::Low,
            SeverityFilter::None => Severity::None,
        }
    }

    pub fn product_metadata(&self) -> ProductMetadata {
        // ProductMetadata is #[non_exhaustive], so build it from Default and assign.
        let mut meta = ProductMetadata::default();
        meta.product_name = self.product_name.clone();
        meta.product_version = self.product_version.clone();
        meta.manufacturer = self.manufacturer.clone();
        meta.support_period = self.support_period.clone();
        meta.update_mechanism = self.update_mechanism.clone();
        meta
    }
}

#[derive(Clone, ValueEnum)]
pub enum SeverityFilter {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(clap::Args)]
pub struct ValidateArgs {
    /// Path to the SBOM file
    pub file: PathBuf,
}

#[derive(clap::Args)]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommands,
}

#[derive(Subcommand)]
pub enum DbCommands {
    /// Download/update the local vulnerability database
    Update,
    /// Show database info (last updated, entry count)
    Info,
    /// Export the local vulnerability database for transfer to air-gapped environments
    Export(DbExportArgs),
    /// Import a vulnerability database file (e.g., from an air-gapped transfer)
    Import(DbImportArgs),
}

#[derive(clap::Args)]
pub struct DbExportArgs {
    /// Output path for the exported database file
    pub output: PathBuf,
}

#[derive(clap::Args)]
pub struct DbImportArgs {
    /// Path to the database file to import
    pub file: PathBuf,
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// CI platform to generate workflow for
    #[arg(long, value_enum, default_value = "github")]
    pub ci: CiPlatform,

    /// Overwrite existing files
    #[arg(long)]
    pub force: bool,

    /// Skip confirmation (non-interactive)
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Clone, ValueEnum)]
pub enum CiPlatform {
    Github,
    Gitlab,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Catches duplicate long options, bad arg definitions and grouping mistakes
    /// at test time rather than on first run.
    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn product_metadata_carries_every_cra_flag() {
        let cli = Cli::parse_from([
            "shieldbom",
            "scan",
            "sbom.spdx.json",
            "--format",
            "cra",
            "--product-name",
            "Smart Gateway",
            "--product-version",
            "2.4.1",
            "--manufacturer",
            "Acme Industrial GmbH",
            "--support-period",
            "5 years from 2026-01-01",
            "--update-mechanism",
            "Signed OTA over HTTPS",
        ]);

        let Commands::Scan(args) = cli.command else {
            panic!("expected the scan subcommand");
        };
        let meta = args.product_metadata();

        assert_eq!(meta.product_name.as_deref(), Some("Smart Gateway"));
        assert_eq!(meta.product_version.as_deref(), Some("2.4.1"));
        assert_eq!(meta.manufacturer.as_deref(), Some("Acme Industrial GmbH"));
        assert_eq!(
            meta.support_period.as_deref(),
            Some("5 years from 2026-01-01")
        );
        assert_eq!(
            meta.update_mechanism.as_deref(),
            Some("Signed OTA over HTTPS")
        );
        assert!(meta.missing_identification().is_empty());
    }

    #[test]
    fn cra_flags_are_optional_and_report_what_is_missing() {
        let cli = Cli::parse_from(["shieldbom", "scan", "sbom.spdx.json", "--format", "cra"]);
        let Commands::Scan(args) = cli.command else {
            panic!("expected the scan subcommand");
        };

        assert_eq!(
            args.product_metadata().missing_identification(),
            vec!["--product-name", "--product-version", "--manufacturer"]
        );
    }
}
