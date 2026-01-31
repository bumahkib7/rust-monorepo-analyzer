//! Config command implementation

use crate::ui::theme::Theme;
use crate::ConfigAction;
use anyhow::Result;
use colored::Colorize;
use rma_common::RmaConfig;
use std::path::PathBuf;

pub fn run(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Get { key } => get_config(&key),
        ConfigAction::Set { key, value } => set_config(&key, &value),
        ConfigAction::List => list_config(),
        ConfigAction::Edit => edit_config(),
        ConfigAction::Path => show_config_path(),
        ConfigAction::Reset { force } => reset_config(force),
    }
}

fn get_config(key: &str) -> Result<()> {
    let config = load_config()?;
    let json = serde_json::to_value(&config)?;

    let value = get_nested_value(&json, key);

    match value {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        None => {
            eprintln!("{} Key not found: {}", Theme::error_mark(), key.yellow());
            std::process::exit(1);
        }
    }

    Ok(())
}

fn set_config(key: &str, value: &str) -> Result<()> {
    let mut config = load_config()?;
    let mut json = serde_json::to_value(&config)?;

    // Parse the value
    let parsed_value: serde_json::Value = serde_json::from_str(value)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));

    set_nested_value(&mut json, key, parsed_value)?;

    // Convert back to config
    config = serde_json::from_value(json)?;
    save_config(&config)?;

    println!(
        "{} Configuration updated: {} = {}",
        Theme::success_mark(),
        key.cyan(),
        value.bright_white()
    );

    Ok(())
}

fn list_config() -> Result<()> {
    let config = load_config()?;

    println!();
    println!("{}", Theme::header("Configuration"));
    println!("{}", Theme::separator(60));
    println!();

    let json = serde_json::to_value(&config)?;
    print_config_tree(&json, "");

    println!();
    println!(
        "  {} {}",
        "Config file:".dimmed(),
        get_config_path()?.display()
    );
    println!();

    Ok(())
}

fn print_config_tree(value: &serde_json::Value, prefix: &str) {
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map {
            let new_prefix = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };

            match val {
                serde_json::Value::Object(_) => {
                    println!("  {}", new_prefix.cyan());
                    print_config_tree(val, &new_prefix);
                }
                _ => {
                    let formatted_val = match val {
                        serde_json::Value::String(s) => format!("\"{}\"", s).green(),
                        serde_json::Value::Bool(b) => b.to_string().yellow(),
                        serde_json::Value::Number(n) => n.to_string().bright_blue(),
                        serde_json::Value::Array(arr) => format!("[{} items]", arr.len()).dimmed(),
                        _ => val.to_string().dimmed(),
                    };
                    println!("    {}: {}", key.bright_white(), formatted_val);
                }
            }
        }
    }
}

fn edit_config() -> Result<()> {
    let config_path = get_config_path()?;

    // Ensure config exists
    if !config_path.exists() {
        let config = RmaConfig::default();
        save_config(&config)?;
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    println!(
        "{} Opening {} in {}...",
        Theme::info_mark(),
        config_path.display(),
        editor.cyan()
    );

    std::process::Command::new(&editor)
        .arg(&config_path)
        .status()?;

    println!("{} Configuration saved", Theme::success_mark());

    Ok(())
}

fn show_config_path() -> Result<()> {
    let path = get_config_path()?;
    println!("{}", path.display());
    Ok(())
}

fn reset_config(force: bool) -> Result<()> {
    if !force {
        println!(
            "{} This will reset all configuration to defaults.",
            Theme::warning_mark()
        );
        print!("Continue? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = RmaConfig::default();
    save_config(&config)?;

    println!("{} Configuration reset to defaults", Theme::success_mark());

    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    // Check current directory first
    let local_config = PathBuf::from(".rma/config.json");
    if local_config.exists() {
        return Ok(local_config);
    }

    // Fall back to global config
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let global_config = home.join(".config/rma/config.json");

    Ok(global_config)
}

fn load_config() -> Result<RmaConfig> {
    let config_path = get_config_path()?;

    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(RmaConfig::default())
    }
}

fn save_config(config: &RmaConfig) -> Result<()> {
    let config_path = get_config_path()?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&config_path, json)?;

    Ok(())
}

fn get_nested_value<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = value;

    for part in parts {
        current = current.get(part)?;
    }

    Some(current)
}

fn set_nested_value(
    value: &mut serde_json::Value,
    key: &str,
    new_value: serde_json::Value,
) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();

    if parts.is_empty() {
        anyhow::bail!("Empty key");
    }

    let mut current = value;

    for part in &parts[..parts.len() - 1] {
        current = current
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid path"))?
            .entry(*part)
            .or_insert(serde_json::json!({}));
    }

    if let Some(obj) = current.as_object_mut() {
        obj.insert(parts[parts.len() - 1].to_string(), new_value);
    }

    Ok(())
}
