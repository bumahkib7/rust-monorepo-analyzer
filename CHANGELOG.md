# Changelog

All notable changes to RMA (Rust Monorepo Analyzer) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-02-01

### Added
- **Native Oxc Integration**: JS/TS analysis using oxc crates directly (no external binaries)
  - `oxc/no-debugger` - Detect debugger statements
  - `oxc/no-eval` - Detect dangerous code execution
  - `oxc/no-alert` - Detect browser dialogs
  - `oxc/no-empty-pattern` - Detect empty destructuring
  - `oxc/no-with` - Detect deprecated with statements
- **Test File Exclusion**: Secret detection rules now skip test/fixture/example files
  - Skips `/test/`, `/tests/`, `/__tests__/`, `/fixtures/`, `/examples/` directories
  - Skips `*_test.go`, `*.test.js`, `*.spec.ts`, `conftest.py` files
- **Gosec Provider**: Go security analysis via gosec CLI integration
- **65 Total Rules**: Comprehensive coverage across all supported languages

### Changed
- **js/no-cond-assign**: Now only flags actual control flow statements (if/while/for/do)
  - Fixes false positives on ternaries in JSX template literals
  - Skips intentional patterns like `if ((x = getValue()) !== null)`
- **Go Security Scanner**: Single-pass AST traversal for maximum performance
  - Pre-compiled regex patterns with LazyLock
  - Quick content checks to skip unnecessary scanning

### Fixed
- False positive: Private keys in test files no longer flagged
- False positive: Ternary expressions in JSX className props
- Performance: Rule pre-filtering with HashMap for O(1) lookup
- Performance: HashSet for O(1) node kind lookups

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
