mod cli;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => commands::scan(args).await,
        Commands::Validate(args) => commands::validate(args),
        Commands::Db(args) => commands::db(args).await,
        Commands::Version => {
            println!("shieldbom {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

mod commands {
    use crate::cli::{DbArgs, DbCommands, ScanArgs, ValidateArgs}; // DbExportArgs, DbImportArgs used via DbCommands
    use anyhow::{bail, Context, Result};
    use shieldbom::license;
    use shieldbom::models::AnalysisReport;
    use shieldbom::parser;
    use shieldbom::report;
    use shieldbom::report::OutputFormat;
    use shieldbom::vuln;

    pub async fn scan(args: ScanArgs) -> Result<()> {
        // Validate --sync requirements upfront
        if args.sync && args.api_key.is_none() {
            bail!(
                "--sync requires an API key. Set --api-key or SHIELDBOM_API_KEY environment variable.\n\
                 Register at your ShieldBOM server: POST /api/v1/auth/register"
            );
        }

        let sbom = match parser::parse_sbom(&args.file) {
            Ok(sbom) => sbom,
            Err(e) => {
                eprintln!("Error: {e:#}");
                std::process::exit(2);
            }
        };
        eprintln!(
            "Parsed {} components from {:?} ({})",
            sbom.components.len(),
            args.file,
            sbom.format_detected
        );

        if sbom.components.is_empty() {
            eprintln!(
                "Warning: No components found in SBOM file. The file may be malformed or empty."
            );
            std::process::exit(2);
        }

        let vulns = if args.offline {
            vuln::match_offline(&sbom.components).await?
        } else {
            vuln::match_vulnerabilities(&sbom.components, args.nvd).await?
        };
        eprintln!("Found {} vulnerabilities", vulns.len());

        let license_issues = license::check(&sbom.components);
        eprintln!("Found {} license issues", license_issues.len());

        let analysis = AnalysisReport::new(
            args.file.clone(),
            sbom.format_detected,
            sbom.components,
            vulns,
            license_issues,
        );

        let severity = args.severity_threshold();
        let format = args.format.unwrap_or(OutputFormat::Table);
        report::render(&analysis, format)?;

        // Upload to server if --sync is enabled
        if args.sync {
            let api_key = args.api_key.as_deref().unwrap();
            sync_to_server(&analysis, api_key, &args.server).await?;
        }

        let exit_code = analysis.exit_code(&severity);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }

        Ok(())
    }

    async fn sync_to_server(
        report: &AnalysisReport,
        api_key: &str,
        server_url: &str,
    ) -> Result<()> {
        eprintln!("Syncing scan results to {}...", server_url);

        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/scans", server_url.trim_end_matches('/'));

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(report)
            .send()
            .await
            .context("Failed to connect to ShieldBOM server")?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!("Authentication failed: invalid API key");
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("Server returned {}: {}", status, body);
        }

        let scan: SyncResponse = response
            .json()
            .await
            .context("Failed to parse server response")?;

        eprintln!(
            "Scan uploaded successfully (id: {}, components: {}, vulns: {})",
            scan.id, scan.total_components, scan.total_vulns
        );

        Ok(())
    }

    #[derive(serde::Deserialize)]
    struct SyncResponse {
        id: String,
        total_components: i64,
        total_vulns: i64,
    }

    pub fn validate(args: ValidateArgs) -> Result<()> {
        match parser::parse_sbom(&args.file) {
            Ok(sbom) => {
                println!(
                    "Valid {} with {} components",
                    sbom.format_detected,
                    sbom.components.len()
                );
                Ok(())
            }
            Err(e) => {
                eprintln!("Validation failed: {e}");
                std::process::exit(2);
            }
        }
    }

    pub async fn db(args: DbArgs) -> Result<()> {
        match args.command {
            DbCommands::Update => {
                eprintln!("Updating vulnerability database...");
                shieldbom::db::update().await?;
                eprintln!("Database updated successfully.");
                Ok(())
            }
            DbCommands::Info => {
                let info = shieldbom::db::info()?;
                println!("{info}");
                Ok(())
            }
            DbCommands::Export(args) => {
                let stats = shieldbom::db::export(&args.output)?;
                eprintln!("Database exported successfully.");
                eprintln!("  Output:       {}", args.output.display());
                eprintln!("  CVE records:  {}", stats.total_records);
                eprintln!("  Unique CVEs:  {}", stats.unique_cves);
                eprintln!("  Last updated: {}", stats.last_updated);
                eprintln!("  File size:    {}", stats.file_size);
                Ok(())
            }
            DbCommands::Import(args) => {
                let stats = shieldbom::db::import(&args.file)?;
                eprintln!("Database imported successfully.");
                eprintln!("  Source:       {}", args.file.display());
                eprintln!("  CVE records:  {}", stats.total_records);
                eprintln!("  Unique CVEs:  {}", stats.unique_cves);
                eprintln!("  Last updated: {}", stats.last_updated);
                eprintln!("  File size:    {}", stats.file_size);
                Ok(())
            }
        }
    }
}
