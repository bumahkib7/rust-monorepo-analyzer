# RMA Web Dashboard

A browser-based real-time dashboard for monitoring RMA analysis.

## Features

- **Real-time Updates**: WebSocket connection for instant feedback
- **Live Statistics**: Track findings by severity
- **Event Log**: Monitor file changes and analysis
- **Findings Panel**: View all security findings

## Usage

### 1. Start the RMA Daemon

```bash
rma daemon --port 8080
```

### 2. Open the Dashboard

Simply open `index.html` in your browser:

```bash
# macOS
open index.html

# Linux
xdg-open index.html

# Or serve with Python
python3 -m http.server 3000
# Then open http://localhost:3000
```

### 3. Connect and Watch

1. Click **Connect** to connect to the daemon
2. Enter a path to watch (default: `.`)
3. Click **Start Watching**
4. Edit files and see real-time analysis!

## Architecture

```
┌─────────────────┐     WebSocket      ┌─────────────────┐
│   Web Browser   │ ◄─────────────────► │   RMA Daemon    │
│   (Dashboard)   │   ws://host/ws/     │  port 8080      │
└─────────────────┘                     └─────────────────┘
        │                                       │
        │ Display                               │ Watch
        ▼                                       ▼
┌─────────────────┐                     ┌─────────────────┐
│  Stats Panel    │                     │  File System    │
│  Events Log     │                     │  (notify)       │
│  Findings List  │                     │                 │
└─────────────────┘                     └─────────────────┘
```

## WebSocket Protocol

### Messages from Server

```typescript
// Connection established
{ type: "Connected", data: { client_id: "abc123" } }

// File change detected
{ type: "FileChanged", data: { path: "./src/main.rs", kind: "Modified" } }

// Analysis complete
{ type: "AnalysisComplete", data: {
    path: "./src/main.rs",
    findings: [{ rule_id: "rust/unsafe", message: "...", severity: "warning", line: 10, column: 5 }],
    duration_ms: 15
}}

// Error occurred
{ type: "Error", data: { message: "Failed to read file" } }

// Watching started
{ type: "WatchingStarted", data: { path: "./src" } }
```

### Commands to Server

```typescript
// Start watching a directory
{ command: "Watch", data: { path: "./src" } }

// Stop watching
{ command: "StopWatch" }

// Analyze specific file
{ command: "Analyze", data: { path: "./src/main.rs" } }
```

## Customization

The dashboard is a single HTML file with embedded CSS and JavaScript. You can easily customize:

- **Colors**: Modify CSS variables in `:root`
- **Layout**: Adjust grid and flexbox in CSS
- **Behavior**: Modify JavaScript handlers

## Integration Ideas

- Embed in CI/CD pipelines
- Add to project documentation
- Create team dashboards
- Build custom IDE integrations
