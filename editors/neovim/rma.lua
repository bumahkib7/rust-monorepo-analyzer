-- RMA (Rust Monorepo Analyzer) Neovim Configuration
--
-- Installation:
-- 1. Install rma-lsp: cargo install --path crates/lsp
-- 2. Add this file to your Neovim config or source it
--
-- Usage with lazy.nvim:
--   { 'your-username/rma', config = function() require('rma').setup() end }
--
-- Usage with packer.nvim:
--   use { 'your-username/rma', config = function() require('rma').setup() end }

local M = {}

-- Default configuration
M.config = {
    -- Path to rma-lsp binary (nil = search PATH)
    lsp_path = nil,

    -- Enable/disable specific features
    enable_lsp = true,
    enable_diagnostics = true,
    enable_rustsec = true,

    -- Minimum severity to show: "info", "warning", "error", "critical"
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
}

-- Find the rma-lsp binary
local function find_lsp_binary()
    -- Check configured path
    if M.config.lsp_path then
        if vim.fn.executable(M.config.lsp_path) == 1 then
            return M.config.lsp_path
        end
    end

    -- Check common locations
    local paths = {
        "rma-lsp",  -- In PATH
        vim.fn.expand("~/.cargo/bin/rma-lsp"),
        "/opt/homebrew/bin/rma-lsp",
        "/usr/local/bin/rma-lsp",
    }

    for _, path in ipairs(paths) do
        if vim.fn.executable(path) == 1 then
            return path
        end
    end

    return nil
end

-- Setup LSP with nvim-lspconfig
local function setup_lsp()
    local lsp_path = find_lsp_binary()
    if not lsp_path then
        vim.notify("RMA: Could not find rma-lsp binary", vim.log.levels.ERROR)
        return false
    end

    local ok, lspconfig = pcall(require, 'lspconfig')
    if not ok then
        vim.notify("RMA: nvim-lspconfig not found", vim.log.levels.ERROR)
        return false
    end

    local configs = require('lspconfig.configs')

    -- Register RMA as a custom LSP server
    if not configs.rma then
        configs.rma = {
            default_config = {
                cmd = { lsp_path },
                filetypes = M.config.filetypes,
                root_dir = lspconfig.util.root_pattern(
                    "Cargo.toml",
                    "package.json",
                    "pyproject.toml",
                    "go.mod",
                    "pom.xml",
                    ".git"
                ),
                settings = {
                    rma = {
                        minSeverity = M.config.min_severity,
                        enableRustsec = M.config.enable_rustsec,
                        debounceMs = M.config.debounce_ms,
                    }
                },
            },
        }
    end

    -- Setup the server
    lspconfig.rma.setup({
        on_attach = function(client, bufnr)
            -- Keybindings for RMA-specific features
            local opts = { buffer = bufnr, silent = true }

            vim.keymap.set('n', '<leader>ra', function()
                vim.lsp.buf.code_action()
            end, vim.tbl_extend('force', opts, { desc = 'RMA: Code Action' }))

            vim.keymap.set('n', '<leader>rd', function()
                vim.diagnostic.open_float()
            end, vim.tbl_extend('force', opts, { desc = 'RMA: Show Diagnostic' }))

            vim.keymap.set('n', '[d', function()
                vim.diagnostic.goto_prev()
            end, vim.tbl_extend('force', opts, { desc = 'RMA: Previous Diagnostic' }))

            vim.keymap.set('n', ']d', function()
                vim.diagnostic.goto_next()
            end, vim.tbl_extend('force', opts, { desc = 'RMA: Next Diagnostic' }))

            vim.notify("RMA attached to buffer", vim.log.levels.INFO)
        end,
        capabilities = vim.lsp.protocol.make_client_capabilities(),
    })

    return true
end

-- Setup diagnostic signs
local function setup_signs()
    local signs = {
        { name = "DiagnosticSignError", text = M.config.signs.error },
        { name = "DiagnosticSignWarn", text = M.config.signs.warning },
        { name = "DiagnosticSignInfo", text = M.config.signs.info },
        { name = "DiagnosticSignHint", text = M.config.signs.info },
    }

    for _, sign in ipairs(signs) do
        vim.fn.sign_define(sign.name, { texthl = sign.name, text = sign.text, numhl = "" })
    end
end

-- Setup diagnostic display
local function setup_diagnostics()
    vim.diagnostic.config({
        virtual_text = {
            prefix = '●',
            source = 'if_many',
        },
        signs = true,
        underline = true,
        update_in_insert = false,
        severity_sort = true,
        float = {
            focusable = false,
            style = 'minimal',
            border = 'rounded',
            source = 'always',
            header = '',
            prefix = '',
        },
    })
end

-- User commands
local function setup_commands()
    vim.api.nvim_create_user_command('RMARestart', function()
        vim.cmd('LspRestart rma')
    end, { desc = 'Restart RMA Language Server' })

    vim.api.nvim_create_user_command('RMAInfo', function()
        local clients = vim.lsp.get_active_clients({ name = 'rma' })
        if #clients == 0 then
            vim.notify("RMA: Not running", vim.log.levels.WARN)
        else
            local client = clients[1]
            vim.notify(string.format(
                "RMA: Running (PID: %s, Root: %s)",
                client.rpc.pid or "unknown",
                client.config.root_dir or "unknown"
            ), vim.log.levels.INFO)
        end
    end, { desc = 'Show RMA status' })
end

-- Main setup function
function M.setup(opts)
    -- Merge user config
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})

    -- Setup components
    setup_signs()
    setup_diagnostics()
    setup_commands()

    if M.config.enable_lsp then
        -- Defer LSP setup to ensure lspconfig is loaded
        vim.schedule(function()
            if setup_lsp() then
                vim.notify("RMA: Ready", vim.log.levels.INFO)
            end
        end)
    end
end

return M
