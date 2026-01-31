# RMA for VS Code

Security analysis and code quality for Rust, JavaScript, TypeScript, Python, Go, and Java.

## Features

- Real-time security vulnerability detection
- 45+ built-in security rules
- RustSec advisory database integration
- Multi-language support

## Requirements

1. Install the `rma-lsp` binary:

```bash
# From source
cargo install --path /path/to/rust-monorepo-analyzer/crates/lsp

# Or copy the binary
cp target/release/rma-lsp ~/.cargo/bin/
```

2. Install this extension

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `rma.enable` | `true` | Enable/disable RMA |
| `rma.lspPath` | `""` | Path to rma-lsp binary |
| `rma.severity` | `"warning"` | Minimum severity to show |
| `rma.enableRustsec` | `true` | Enable RustSec scanning |
| `rma.debounceMs` | `300` | Analysis debounce delay |

## Commands

- `RMA: Restart Language Server` - Restart the LSP
- `RMA: Analyze Entire Workspace` - Full workspace scan
- `RMA: Show Output` - Show RMA output channel

## Building from Source

```bash
cd editors/vscode
npm install
npm run compile
npm run package  # Creates .vsix file
```

## Installing the Extension

```bash
code --install-extension rma-vscode-0.6.0.vsix
```
