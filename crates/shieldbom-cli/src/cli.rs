use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use shieldbom::models::Severity;
use shieldbom::report::OutputFormat;

/// ShieldBOM - SBOM vulnerability scanner for embedded/IoT software
#[derive(Parser)]
#[command(name = "shieldbom", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan an SBOM file for vulnerabilities and license issues
    Scan(ScanArgs),
    /// Validate SBOM format and completeness
    Validate(ValidateArgs),
    /// Manage local vulnerability database
    Db(DbArgs),
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
