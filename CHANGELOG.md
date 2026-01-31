# Changelog

All notable changes to RMA (Rust Monorepo Analyzer) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **IDE Integrations**: VS Code extension, Neovim plugin, JetBrains plugin, Web Dashboard
- **Real-time Watch Mode**: WebSocket-based live updates with file system monitoring
- **Duplicate Function Detection**: `generic/duplicate-function` rule
- **Doctor Command**: `rma doctor` for installation health checks
- **PR Workflow Support**: `--changed-only` flag to only scan changed files
- **Release Drafter**: Auto-generate release notes from PRs

### Changed
- Watch mode now has cleaner terminal output with proper raw mode handling
- `--no-initial-scan` flag to skip initial directory scan in watch mode
- Daemon shows dashboard URL on startup

## [0.6.0] - 2026-02-01

### Added
- WebSocket endpoint for real-time file watching (`/ws/watch`)
- Web dashboard for browser-based monitoring
- Initial scan on watch mode startup
- Interactive keyboard shortcuts in watch mode (q/c/r/s/e/p/?)

### Changed
- Categorized rules into high-confidence sinks vs review hints
- Reduced false positives in security rules

### Fixed
- Clippy warnings for Rust 2024 edition
- Normalized file paths in SARIF and GitHub output

## [0.5.0] - 2026-01-31

### Added
- Rich diagnostics with code snippets and suggestions
- GitHub Actions output format (`--format github`)

### Fixed
- Clippy warnings for Rust 2024 if-let chains

## [0.4.0] - 2026-01-31

### Added
- SARIF output improvements
- Better error messages

## [0.3.0] - 2026-01-31

### Added
- 8 new security rules for Rust, JS/TS, Python, Go, Java
- Automatic Homebrew tap update workflow
- Secret detection (API keys, AWS keys, GitHub tokens, private keys)
- Insecure crypto detection (MD5, SHA-1, DES, RC4, ECB)

## [0.2.0] - 2026-01-31

### Added
- Config versioning (`config_version = 1`)
- Stable fingerprints for baseline comparisons
- Rulesets (security, maintainability)
- Inline suppression (`// rma-ignore-next-line`)
- GitHub Actions integration
- Timer string rule for JS

### Changed
- Updated to Rust edition 2024

## [0.1.0] - 2026-01-31

### Added
- Initial release
- Multi-language support: Rust, JavaScript, TypeScript, Python, Go, Java
- Security and code quality rules
- SARIF output for GitHub Security tab
- Watch mode for real-time analysis
- HTTP API daemon
- Configuration via rma.toml
- Profiles: fast, balanced, strict
