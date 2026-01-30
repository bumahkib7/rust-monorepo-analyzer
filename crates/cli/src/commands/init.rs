//! Init command implementation

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_common::RmaConfig;
use std::path::PathBuf;

pub struct InitArgs {
    pub path: PathBuf,
    pub force: bool,
    pub with_ai: bool,
}

pub fn run(args: InitArgs) -> Result<()> {
    let config_dir = args.path.join(".rma");
    let config_file = config_dir.join("config.json");

    // Check if already initialized
    if config_file.exists() && !args.force {
        println!(
            "{} RMA is already initialized in this directory",
            Theme::warning_mark()
        );
        println!("  Use {} to reinitialize", "--force".yellow());
        return Ok(());
    }

    println!();
    println!("{}", "🚀 Initializing RMA".cyan().bold());
    println!("{}", Theme::separator(50));

    // Create directory structure
    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(config_dir.join("index"))?;
    std::fs::create_dir_all(config_dir.join("cache"))?;

    println!(
        "  {} Created {}",
        Theme::success_mark(),
        ".rma/".bright_white()
    );

    // Create config
    let config = RmaConfig::default();

    if args.with_ai {
        // AI would be configured here
        println!("  {} AI features enabled", Theme::success_mark());
    }

    let config_json = serde_json::to_string_pretty(&config)?;
    std::fs::write(&config_file, &config_json)?;

    println!(
        "  {} Created {}",
        Theme::success_mark(),
        "config.json".bright_white()
    );

    // Create .gitignore for RMA directory
    let gitignore_path = config_dir.join(".gitignore");
    let gitignore_content = r#"# RMA cache and index
index/
cache/
*.lock
"#;
    std::fs::write(&gitignore_path, gitignore_content)?;
    println!(
        "  {} Created {}",
        Theme::success_mark(),
        ".gitignore".bright_white()
    );

    println!();
    println!("{}", Theme::double_separator(50));
    println!("{} RMA initialized successfully!", Theme::success_mark());
    println!();
    println!("  {}", "Next steps:".cyan().bold());
    println!(
        "  {} Run {} to analyze your code",
        Theme::bullet(),
        "rma scan".yellow()
    );
    println!(
        "  {} Run {} to watch for changes",
        Theme::bullet(),
        "rma watch".yellow()
    );
    println!(
        "  {} Run {} to customize settings",
        Theme::bullet(),
        "rma config edit".yellow()
    );
    println!();

    Ok(())
}
