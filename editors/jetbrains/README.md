# RMA for JetBrains IDEs

Security analysis plugin for IntelliJ IDEA, WebStorm, PyCharm, GoLand, and other JetBrains IDEs.

## How It Works

Unlike the VS Code extension which uses LSP, the JetBrains plugin uses **WebSocket** to communicate with the RMA daemon for real-time analysis updates.

```
┌─────────────────┐     WebSocket      ┌─────────────────┐
│  JetBrains IDE  │ ◄─────────────────► │   RMA Daemon    │
│   (Plugin)      │                     │  (rma daemon)   │
└─────────────────┘                     └─────────────────┘
```

## Requirements

1. RMA daemon installed and running
2. JetBrains IDE (2023.3 or later)

## Installation

### 1. Start the RMA Daemon

```bash
# Install RMA
cargo install --path /path/to/rust-monorepo-analyzer

# Start daemon (in a terminal or background)
rma daemon --port 8080
```

### 2. Build the Plugin

```bash
cd editors/jetbrains
./gradlew buildPlugin
```

The plugin ZIP will be in `build/distributions/`.

### 3. Install in IDE

1. Open IDE → Settings → Plugins
2. Click gear icon → "Install Plugin from Disk..."
3. Select the ZIP file

## Features

- **Real-time Analysis**: Files are analyzed as you type
- **Inline Annotations**: Security issues shown directly in editor
- **Project-wide Watching**: Monitors all source files
- **Quick Actions**: Analyze file or project from Tools menu

## Configuration

Settings → Tools → RMA Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Daemon Host | localhost | RMA daemon host |
| Daemon Port | 8080 | RMA daemon port |
| Auto-connect | true | Connect when project opens |

## Usage

### Manual Analysis

1. **Tools → RMA → Analyze Current File** - Analyze open file
2. **Tools → RMA → Analyze Project** - Analyze entire project

### Automatic Analysis

When connected, the plugin automatically:
- Watches all source files in the project
- Re-analyzes files when they change
- Updates inline annotations in real-time

## Troubleshooting

**Plugin not connecting:**
1. Ensure daemon is running: `curl http://localhost:8080/health`
2. Check daemon port matches plugin settings
3. Restart IDE

**No annotations showing:**
1. Check Tools → RMA → Start RMA Daemon
2. Wait for analysis to complete
3. Trigger manual analysis

## Development

```bash
# Run IDE with plugin for testing
./gradlew runIde

# Build plugin
./gradlew buildPlugin

# Run tests
./gradlew test
```
