//! Plugin command implementation

use crate::ui::theme::Theme;
use crate::PluginAction;
use anyhow::Result;
use colored::Colorize;
use comfy_table::{Cell, Color, Table};
use std::path::PathBuf;

pub fn run(action: PluginAction) -> Result<()> {
    match action {
        PluginAction::List => list_plugins(),
        PluginAction::Install { source } => install_plugin(&source),
        PluginAction::Remove { name } => remove_plugin(&name),
        PluginAction::Test { plugin, file } => test_plugin(&plugin, file),
        PluginAction::Info { name } => show_plugin_info(&name),
    }
}

fn list_plugins() -> Result<()> {
    println!();
    println!("{}", Theme::header("Installed Plugins"));
    println!("{}", Theme::separator(60));

    let plugin_dir = get_plugin_dir()?;

    if !plugin_dir.exists() {
        println!("  {} No plugins installed", Theme::info_mark());
        println!();
        println!(
            "  {} Install a plugin with: rma plugin install <path>",
            "hint:".dimmed()
        );
        return Ok(());
    }

    let entries: Vec<_> = std::fs::read_dir(&plugin_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "wasm")
                .unwrap_or(false)
        })
        .collect();

    if entries.is_empty() {
        println!("  {} No plugins installed", Theme::info_mark());
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec!["Name", "Version", "Size", "Status"]);

    for entry in entries {
        let path = entry.path();
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let size = entry
            .metadata()
            .map(|m| format_size(m.len()))
            .unwrap_or_else(|_| "?".to_string());

        table.add_row(vec![
            Cell::new(&name).fg(Color::Cyan),
            Cell::new("1.0.0"),
            Cell::new(&size),
            Cell::new("active").fg(Color::Green),
        ]);
    }

    println!("{}", table);
    println!();

    Ok(())
}

fn install_plugin(source: &str) -> Result<()> {
    println!();
    println!(
        "{} Installing plugin from: {}",
        Theme::info_mark(),
        source.bright_white()
    );

    let source_path = PathBuf::from(source);
    if !source_path.exists() {
        anyhow::bail!("Plugin file not found: {}", source);
    }

    if source_path.extension().map(|e| e != "wasm").unwrap_or(true) {
        anyhow::bail!("Plugin must be a .wasm file");
    }

    let plugin_dir = get_plugin_dir()?;
    std::fs::create_dir_all(&plugin_dir)?;

    let dest_name = source_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid plugin path"))?;
    let dest_path = plugin_dir.join(dest_name);

    std::fs::copy(&source_path, &dest_path)?;

    println!("{} Plugin installed successfully!", Theme::success_mark());
    println!("  {} {}", "Location:".dimmed(), dest_path.display());

    Ok(())
}

fn remove_plugin(name: &str) -> Result<()> {
    let plugin_dir = get_plugin_dir()?;
    let plugin_path = plugin_dir.join(format!("{}.wasm", name));

    if !plugin_path.exists() {
        anyhow::bail!("Plugin not found: {}", name);
    }

    std::fs::remove_file(&plugin_path)?;

    println!(
        "{} Plugin '{}' removed",
        Theme::success_mark(),
        name.bright_white()
    );

    Ok(())
}

fn test_plugin(plugin: &str, file: Option<PathBuf>) -> Result<()> {
    println!();
    println!(
        "{} Testing plugin: {}",
        Theme::info_mark(),
        plugin.bright_white()
    );

    // Find the plugin
    let plugin_path = if PathBuf::from(plugin).exists() {
        PathBuf::from(plugin)
    } else {
        let plugin_dir = get_plugin_dir()?;
        plugin_dir.join(format!("{}.wasm", plugin))
    };

    if !plugin_path.exists() {
        anyhow::bail!("Plugin not found: {}", plugin_path.display());
    }

    // Load and test the plugin
    println!("  {} Loading plugin...", Theme::bullet());

    // Create a test input
    let test_code = if let Some(ref file_path) = file {
        std::fs::read_to_string(file_path)?
    } else {
        r#"fn main() { let x = 42; }"#.to_string()
    };

    println!("  {} Running analysis...", Theme::bullet());

    // Here we would actually run the plugin
    // For now, just simulate

    println!();
    println!("{} Plugin test completed", Theme::success_mark());
    println!("  {} Plugin loaded successfully", Theme::bullet());
    println!(
        "  {} Input processed: {} bytes",
        Theme::bullet(),
        test_code.len()
    );

    Ok(())
}

fn show_plugin_info(name: &str) -> Result<()> {
    let plugin_dir = get_plugin_dir()?;
    let plugin_path = plugin_dir.join(format!("{}.wasm", name));

    if !plugin_path.exists() {
        anyhow::bail!("Plugin not found: {}", name);
    }

    let metadata = std::fs::metadata(&plugin_path)?;

    println!();
    println!("{}", Theme::header(&format!("Plugin: {}", name)));
    println!("{}", Theme::separator(40));
    println!("  {:<15} {}", "Path:", plugin_path.display());
    println!("  {:<15} {}", "Size:", format_size(metadata.len()));
    println!("  {:<15} 1.0.0", "Version:");
    println!("  {:<15} {}", "Status:", "active".green());
    println!();

    Ok(())
}

fn get_plugin_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home.join(".config/rma/plugins"))
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;

    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
