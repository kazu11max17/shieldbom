# Contributing to ShieldBOM

Thank you for your interest in contributing to ShieldBOM! This document explains how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/kazu11max17/shieldbom.git
cd shieldbom

# Build
cargo build

# Run tests
cargo test

# Lint and format
cargo clippy -- -D warnings
cargo fmt --check
```

Requires Rust 1.75+ (2021 edition).

## Making Changes

1. **Open an issue first** if your change is non-trivial. This avoids wasted effort if the change doesn't align with the project direction.
2. Fork the repository and create a feature branch from `main`.
3. Write tests for new functionality.
4. Run the full check suite before submitting:
   ```bash
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```
5. Submit a pull request with a clear description of what and why.

## What We're Looking For

- Bug fixes with regression tests
- New SBOM format support (e.g., SWID tags)
- Vulnerability data source integrations
- Documentation improvements
- Performance optimizations with benchmarks

## Code Style

- Follow standard Rust conventions (`cargo fmt` enforces formatting)
- Keep functions focused and small
- Prefer explicit error handling over `.unwrap()`
- Add doc comments for public APIs

## Reporting Bugs

Open a GitHub issue with:
- ShieldBOM version (`shieldbom --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- The SBOM file that triggered the issue (if possible)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
