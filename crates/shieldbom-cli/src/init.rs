use std::fs;
use std::path::Path;

use anyhow::{bail, Result};

use crate::cli::{CiPlatform, InitArgs};

const GITHUB_WORKFLOW: &str = r#"name: ShieldBOM SBOM Scan
on:
  push:
    branches: [master, main]
  pull_request:
jobs:
  shieldbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ShieldBOM
        run: cargo install shieldbom
      - name: Scan SBOM
        run: shieldbom scan sbom.cdx.json --format sarif > shieldbom.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shieldbom.sarif
"#;

const GITLAB_SNIPPET: &str = r#"# Add this job to your .gitlab-ci.yml
shieldbom:
  stage: test
  script:
    - cargo install shieldbom
    - shieldbom scan sbom.cdx.json --format sarif > shieldbom.sarif
  artifacts:
    reports:
      sast: shieldbom.sarif
"#;

const SHIELDBOM_TOML: &str = r#"# ShieldBOM project configuration
# Docs: https://github.com/kazu11max17/shieldbom

[scan]
sbom_file = "sbom.cdx.json"
severity = "medium"

[output]
format = "table"
"#;

pub fn run(args: &InitArgs) -> Result<()> {
    run_in_dir(args, Path::new("."))
}

pub fn run_in_dir(args: &InitArgs, base: &Path) -> Result<()> {
    eprintln!("ShieldBOM init");

    let mut created: Vec<String> = Vec::new();

    // Generate CI workflow file
    match args.ci {
        CiPlatform::Github => {
            let dir = base.join(".github").join("workflows");
            let path = dir.join("shieldbom.yml");
            write_file(&path, GITHUB_WORKFLOW, args.force)?;
            created.push(path.display().to_string());
        }
        CiPlatform::Gitlab => {
            let path = base.join("gitlab-shieldbom.yml");
            write_file(&path, GITLAB_SNIPPET, args.force)?;
            created.push(path.display().to_string());
        }
        CiPlatform::None => {}
    }

    // Always generate shieldbom.toml
    let toml_path = base.join("shieldbom.toml");
    write_file(&toml_path, SHIELDBOM_TOML, args.force)?;
    created.push(toml_path.display().to_string());

    for file in &created {
        eprintln!("  Created: {file}");
    }

    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Generate your SBOM (e.g., cargo-sbom, syft, trivy)");
    eprintln!("  2. Run: shieldbom scan sbom.cdx.json");
    eprintln!("  3. Commit and push to enable CI scanning");

    Ok(())
}

fn write_file(path: &Path, content: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists. Use --force to overwrite.",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CiPlatform;

    fn make_args(ci: CiPlatform, force: bool) -> InitArgs {
        InitArgs {
            ci,
            force,
            yes: false,
        }
    }

    #[test]
    fn test_github_ci_creates_two_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        run_in_dir(&make_args(CiPlatform::Github, false), base).unwrap();

        assert!(base.join(".github/workflows/shieldbom.yml").exists());
        assert!(base.join("shieldbom.toml").exists());
    }

    #[test]
    fn test_force_false_existing_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        // Create file first
        run_in_dir(&make_args(CiPlatform::Github, false), base).unwrap();

        // Second run without --force should fail
        let result = run_in_dir(&make_args(CiPlatform::Github, false), base);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("already exists"));
    }

    #[test]
    fn test_ci_none_creates_only_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        run_in_dir(&make_args(CiPlatform::None, false), base).unwrap();

        assert!(base.join("shieldbom.toml").exists());
        assert!(!base.join(".github").exists());
        assert!(!base.join("gitlab-shieldbom.yml").exists());
    }

    #[test]
    fn test_force_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        run_in_dir(&make_args(CiPlatform::Github, false), base).unwrap();
        // Should not error with --force
        run_in_dir(&make_args(CiPlatform::Github, true), base).unwrap();
    }

    #[test]
    fn test_gitlab_ci_creates_correct_file() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        run_in_dir(&make_args(CiPlatform::Gitlab, false), base).unwrap();

        assert!(base.join("gitlab-shieldbom.yml").exists());
        assert!(base.join("shieldbom.toml").exists());
        assert!(!base.join(".github").exists());
    }
}
