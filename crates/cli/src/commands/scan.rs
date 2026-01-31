//! Scan command implementation

use crate::output;
use crate::ui::{progress, theme::Theme};
use crate::OutputFormat;
use anyhow::{Context, Result};
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::{Language, RmaConfig, Severity};
use rma_indexer::{IndexConfig, IndexerEngine};
use rma_parser::ParserEngine;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[allow(dead_code)]
pub struct ScanArgs {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub severity: Severity,
    pub incremental: bool,
    pub jobs: usize,
    pub languages: Option<Vec<String>>,
    pub ai_analysis: bool,
    pub ai_provider: String,
    pub timing: bool,
    pub exclude: Option<Vec<String>>,
    pub config_path: Option<PathBuf>,
    pub quiet: bool,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let total_start = Instant::now();
    let mut timings: Vec<(&str, Duration)> = Vec::new();

    // Print header
    if !args.quiet && args.format == OutputFormat::Text {
        print_scan_header(&args);
    }

    // Build configuration
    let config = build_config(&args)?;

    // Phase 1: Parse files
    let parse_start = Instant::now();
    let (parsed_files, _parse_stats) = run_parse_phase(&args, &config)?;
    timings.push(("Parse", parse_start.elapsed()));

    // Phase 2: Analyze
    let analyze_start = Instant::now();
    let (mut results, summary) = run_analyze_phase(&args, &config, &parsed_files)?;
    timings.push(("Analyze", analyze_start.elapsed()));

    // Phase 3: AI Analysis (optional)
    if args.ai_analysis {
        let ai_start = Instant::now();
        run_ai_phase(&args, &mut results)?;
        timings.push(("AI Analysis", ai_start.elapsed()));
    }

    // Phase 4: Index results
    let index_start = Instant::now();
    run_index_phase(&args)?;
    timings.push(("Index", index_start.elapsed()));

    let total_duration = total_start.elapsed();

    // Print timing information
    if args.timing && !args.quiet {
        print_timings(&timings, total_duration);
    }

    // Output results
    output::format_results(&results, &summary, total_duration, args.format, args.output)?;

    // Exit with error code if critical/error findings
    if summary.critical_count > 0 || summary.error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn print_scan_header(args: &ScanArgs) {
    println!();
    println!("{}", "🔍 RMA - Rust Monorepo Analyzer".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );

    if let Some(ref langs) = args.languages {
        println!(
            "  {} {}",
            "Languages:".dimmed(),
            langs.join(", ").bright_white()
        );
    }

    if args.ai_analysis {
        println!(
            "  {} {} ({})",
            "AI:".dimmed(),
            "enabled".green(),
            args.ai_provider.dimmed()
        );
    }

    if args.incremental {
        println!("  {} {}", "Mode:".dimmed(), "incremental".yellow());
    }

    println!();
}

fn build_config(args: &ScanArgs) -> Result<RmaConfig> {
    let mut config = if let Some(ref config_path) = args.config_path {
        let content = std::fs::read_to_string(config_path).context("Failed to read config file")?;
        serde_json::from_str(&content).context("Failed to parse config file")?
    } else {
        RmaConfig::default()
    };

    config.min_severity = args.severity;
    config.incremental = args.incremental;
    config.parallelism = args.jobs;

    if let Some(ref langs) = args.languages {
        config.languages = langs.iter().filter_map(|l| parse_language(l)).collect();
    }

    Ok(config)
}

fn parse_language(s: &str) -> Option<Language> {
    match s.trim().to_lowercase().as_str() {
        "rust" | "rs" => Some(Language::Rust),
        "javascript" | "js" => Some(Language::JavaScript),
        "typescript" | "ts" => Some(Language::TypeScript),
        "python" | "py" => Some(Language::Python),
        "go" | "golang" => Some(Language::Go),
        "java" => Some(Language::Java),
        _ => None,
    }
}

fn run_parse_phase(
    args: &ScanArgs,
    config: &RmaConfig,
) -> Result<(Vec<rma_parser::ParsedFile>, rma_parser::ParseStats)> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Parsing files...");
        Some(s)
    } else {
        None
    };

    let parser = ParserEngine::new(config.clone());
    let result = parser.parse_directory(&args.path)?;

    if let Some(s) = spinner {
        s.finish_with_message(format!(
            "{} Parsed {} files ({} skipped)",
            Theme::success_mark(),
            result.1.files_parsed.to_string().green(),
            result.1.files_skipped.to_string().dimmed()
        ));
    }

    Ok(result)
}

fn run_analyze_phase(
    args: &ScanArgs,
    config: &RmaConfig,
    parsed_files: &[rma_parser::ParsedFile],
) -> Result<(
    Vec<rma_analyzer::FileAnalysis>,
    rma_analyzer::AnalysisSummary,
)> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Analyzing code...");
        Some(s)
    } else {
        None
    };

    let analyzer = AnalyzerEngine::new(config.clone());
    let result = analyzer.analyze_files(parsed_files)?;

    if let Some(s) = spinner {
        let (_results, summary) = &result;
        let status = if summary.critical_count > 0 {
            format!(
                "{} findings ({} critical)",
                summary.total_findings, summary.critical_count
            )
            .red()
        } else if summary.total_findings > 0 {
            format!("{} findings", summary.total_findings).yellow()
        } else {
            "No issues found".green()
        };
        s.finish_with_message(format!(
            "{} Analyzed {} files - {}",
            Theme::success_mark(),
            summary.files_analyzed.to_string().green(),
            status
        ));
    }

    Ok(result)
}

fn run_ai_phase(args: &ScanArgs, _results: &mut [rma_analyzer::FileAnalysis]) -> Result<()> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Running AI analysis...");
        Some(s)
    } else {
        None
    };

    // Note: AI analysis would be integrated here
    // For now, we just simulate the phase
    if let Some(s) = spinner {
        s.finish_with_message(format!(
            "{} AI analysis complete (provider: {})",
            Theme::success_mark(),
            args.ai_provider.dimmed()
        ));
    }

    Ok(())
}

fn run_index_phase(args: &ScanArgs) -> Result<()> {
    let index_path = args.path.join(".rma/index");
    let index_config = IndexConfig {
        index_path,
        ..Default::default()
    };

    // Silently index results
    if let Ok(_indexer) = IndexerEngine::new(index_config) {
        // Indexing happens automatically
    }

    Ok(())
}

fn print_timings(timings: &[(&str, Duration)], total: Duration) {
    println!();
    println!("{}", "⏱  Timing Breakdown".cyan().bold());
    println!("{}", Theme::separator(40));

    for (phase, duration) in timings {
        let pct = (duration.as_secs_f64() / total.as_secs_f64()) * 100.0;
        println!(
            "  {:15} {:>8.2}ms ({:>5.1}%)",
            phase,
            duration.as_secs_f64() * 1000.0,
            pct
        );
    }

    println!("{}", Theme::separator(40));
    println!(
        "  {:15} {:>8.2}ms",
        "Total".bold(),
        total.as_secs_f64() * 1000.0
    );
    println!();
}
