# RMA for Neovim

Security analysis and code quality for Neovim using LSP.

## Requirements

- Neovim >= 0.9.0
- [nvim-lspconfig](https://github.com/neovim/nvim-lspconfig)
- `rma-lsp` binary installed

## Installation

### 1. Install the LSP binary

```bash
# From cargo
cargo install --path /path/to/rust-monorepo-analyzer/crates/lsp

# Or copy directly
cp target/release/rma-lsp ~/.cargo/bin/
```

### 2. Install the plugin

**lazy.nvim:**
```lua
{
    dir = "/path/to/rust-monorepo-analyzer/editors/neovim",
    config = function()
        require('rma').setup({
            -- optional configuration
        })
    end,
    ft = { "rust", "javascript", "typescript", "python", "go", "java" },
}
```

**packer.nvim:**
```lua
use {
    '/path/to/rust-monorepo-analyzer/editors/neovim',
    config = function()
        require('rma').setup()
    end,
}
```

**Manual:**
```lua
-- In your init.lua
vim.opt.runtimepath:append('/path/to/rust-monorepo-analyzer/editors/neovim')
require('rma').setup()
```

## Configuration

```lua
require('rma').setup({
    -- Path to rma-lsp binary (nil = search PATH)
    lsp_path = nil,

    -- Enable/disable features
    enable_lsp = true,
    enable_diagnostics = true,
    enable_rustsec = true,

    -- Minimum severity: "info", "warning", "error", "critical"
    min_severity = "warning",

    -- Debounce delay in ms
    debounce_ms = 300,

    -- Languages to enable
    filetypes = {
        "rust", "javascript", "typescript",
        "typescriptreact", "javascriptreact",
        "python", "go", "java"
    },

    -- Diagnostic signs
    signs = {
        critical = "",
        error = "",
        warning = "",
        info = "",
    },
})
```

## Keybindings

Default keybindings (when RMA is attached):

| Key | Action |
|-----|--------|
| `<leader>ra` | Code Action |
| `<leader>rd` | Show Diagnostic |
| `[d` | Previous Diagnostic |
| `]d` | Next Diagnostic |

## Commands

| Command | Description |
|---------|-------------|
| `:RMARestart` | Restart the RMA language server |
| `:RMAInfo` | Show RMA status |

## Troubleshooting

**RMA not starting:**
```vim
:LspInfo  " Check LSP status
:LspLog   " View LSP logs
```

**Check if binary is found:**
```lua
:lua print(vim.fn.executable('rma-lsp'))
```
