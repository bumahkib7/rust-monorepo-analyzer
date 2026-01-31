import * as vscode from 'vscode';
import * as path from 'path';
import { spawn, ChildProcess } from 'child_process';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;

export async function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('RMA');
    outputChannel.appendLine('RMA extension activating...');

    const config = vscode.workspace.getConfiguration('rma');
    if (!config.get<boolean>('enable', true)) {
        outputChannel.appendLine('RMA is disabled in settings');
        return;
    }

    // Find the LSP binary
    const lspPath = await findLspBinary(config);
    if (!lspPath) {
        vscode.window.showErrorMessage(
            'RMA: Could not find rma-lsp binary. Please install it or set rma.lspPath in settings.'
        );
        return;
    }

    outputChannel.appendLine(`Using LSP binary: ${lspPath}`);

    // Start the language client
    await startClient(context, lspPath);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rma.restart', async () => {
            await restartClient(context, lspPath);
        }),
        vscode.commands.registerCommand('rma.analyzeWorkspace', () => {
            analyzeWorkspace();
        }),
        vscode.commands.registerCommand('rma.showOutput', () => {
            outputChannel.show();
        })
    );

    // Watch for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (e) => {
            if (e.affectsConfiguration('rma')) {
                const newConfig = vscode.workspace.getConfiguration('rma');
                if (!newConfig.get<boolean>('enable', true)) {
                    await stopClient();
                } else {
                    await restartClient(context, lspPath);
                }
            }
        })
    );

    outputChannel.appendLine('RMA extension activated');
}

async function findLspBinary(config: vscode.WorkspaceConfiguration): Promise<string | null> {
    // Check user-configured path first
    const configuredPath = config.get<string>('lspPath', '');
    if (configuredPath) {
        try {
            await vscode.workspace.fs.stat(vscode.Uri.file(configuredPath));
            return configuredPath;
        } catch {
            outputChannel.appendLine(`Configured LSP path not found: ${configuredPath}`);
        }
    }

    // Try common locations
    const possiblePaths = [
        // In PATH
        'rma-lsp',
        // Cargo install location
        path.join(process.env.HOME || '', '.cargo', 'bin', 'rma-lsp'),
        // Local build
        path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', 'target', 'release', 'rma-lsp'),
        // macOS Homebrew
        '/opt/homebrew/bin/rma-lsp',
        '/usr/local/bin/rma-lsp',
    ];

    for (const p of possiblePaths) {
        if (await binaryExists(p)) {
            return p;
        }
    }

    return null;
}

async function binaryExists(binaryPath: string): Promise<boolean> {
    return new Promise((resolve) => {
        const proc = spawn(binaryPath, ['--version'], { stdio: 'ignore' });
        proc.on('error', () => resolve(false));
        proc.on('exit', (code) => resolve(code === 0));
    });
}

async function startClient(context: vscode.ExtensionContext, lspPath: string) {
    const serverOptions: ServerOptions = {
        run: {
            command: lspPath,
            transport: TransportKind.stdio,
        },
        debug: {
            command: lspPath,
            transport: TransportKind.stdio,
        },
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'typescriptreact' },
            { scheme: 'file', language: 'javascriptreact' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'java' },
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.{rs,js,ts,tsx,jsx,py,go,java}'),
        },
        outputChannel,
    };

    client = new LanguageClient(
        'rma',
        'RMA Language Server',
        serverOptions,
        clientOptions
    );

    await client.start();
    outputChannel.appendLine('RMA Language Server started');
}

async function stopClient() {
    if (client) {
        await client.stop();
        client = undefined;
        outputChannel.appendLine('RMA Language Server stopped');
    }
}

async function restartClient(context: vscode.ExtensionContext, lspPath: string) {
    outputChannel.appendLine('Restarting RMA Language Server...');
    await stopClient();
    await startClient(context, lspPath);
}

function analyzeWorkspace() {
    if (!client) {
        vscode.window.showErrorMessage('RMA: Language server not running');
        return;
    }

    vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'RMA: Analyzing workspace...',
            cancellable: false,
        },
        async () => {
            // Send custom request to analyze entire workspace
            try {
                await client?.sendRequest('rma/analyzeWorkspace');
                vscode.window.showInformationMessage('RMA: Workspace analysis complete');
            } catch (e) {
                outputChannel.appendLine(`Workspace analysis failed: ${e}`);
            }
        }
    );
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
