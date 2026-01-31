//! Text output formatting

use crate::output::diagnostics::{DiagnosticRenderer, RichDiagnosticRenderer, SourceCache};
use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use rma_common::Severity;
use std::time::Duration;

/// Output results in human-readable text format
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
) -> Result<()> {
    print_header();
    print_summary(summary, duration);
    print_findings_summary(summary);
    print_details(results);
    print_footer(summary);
    Ok(())
}

/// Output results in compact single-line format
pub fn output_compact(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
) -> Result<()> {
    for result in results {
        for finding in &result.findings {
            let severity_char = match finding.severity {
                Severity::Critical => "C",
                Severity::Error => "E",
                Severity::Warning => "W",
                Severity::Info => "I",
            };
            println!(
                "{}:{}:{}:{}: [{}] {}",
                finding.location.file.display(),
                finding.location.start_line,
                finding.location.start_column,
                severity_char,
                finding.rule_id,
                finding.message
            );
        }
    }

    eprintln!(
        "\n{} files, {} findings in {:.2}s",
        summary.files_analyzed,
        summary.total_findings,
        duration.as_secs_f64()
    );

    Ok(())
}

fn print_header() {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║           🔍 RMA - Rust Monorepo Analyzer                         ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();
}

fn print_summary(summary: &AnalysisSummary, duration: Duration) {
    println!("{}", Theme::header("SCAN SUMMARY"));
    println!("{}", Theme::separator(60));
    println!();

    let col_width = 20;

    println!(
        "  {:<col_width$} {}",
        "Files analyzed:",
        summary.files_analyzed.to_string().bright_white()
    );
    println!(
        "  {:<col_width$} {}",
        "Total lines:",
        format_number(summary.total_loc).bright_white()
    );
    println!(
        "  {:<col_width$} {}",
        "Complexity score:",
        summary.total_complexity.to_string().bright_white()
    );
    println!(
        "  {:<col_width$} {}",
        "Duration:",
        format_duration(duration).bright_white()
    );
    println!();
}

fn print_findings_summary(summary: &AnalysisSummary) {
    println!("{}", Theme::subheader("FINDINGS"));
    println!("{}", Theme::separator(40));
    println!();

    // Create a visual bar for each severity
    let max_findings = [
        summary.critical_count,
        summary.error_count,
        summary.warning_count,
        summary.info_count,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
    .max(1);

    print_severity_bar(
        "Critical",
        summary.critical_count,
        max_findings,
        Severity::Critical,
    );
    print_severity_bar("Error", summary.error_count, max_findings, Severity::Error);
    print_severity_bar(
        "Warning",
        summary.warning_count,
        max_findings,
        Severity::Warning,
    );
    print_severity_bar("Info", summary.info_count, max_findings, Severity::Info);

    println!();
    println!(
        "  {} Total findings: {}",
        Theme::bullet(),
        if summary.total_findings > 0 {
            summary.total_findings.to_string().yellow().bold()
        } else {
            summary.total_findings.to_string().green().bold()
        }
    );
    println!();
}

fn print_severity_bar(label: &str, count: usize, max: usize, severity: Severity) {
    let bar_width = 30;
    let filled = if max > 0 {
        (count * bar_width) / max
    } else {
        0
    };
    let empty = bar_width - filled;

    let (bar_char, _color) = match severity {
        Severity::Critical => ("█", "red"),
        Severity::Error => ("█", "bright_red"),
        Severity::Warning => ("█", "yellow"),
        Severity::Info => ("█", "blue"),
    };

    let filled_bar = bar_char.repeat(filled);
    let empty_bar = "░".repeat(empty);

    let colored_bar = match severity {
        Severity::Critical => filled_bar.red(),
        Severity::Error => filled_bar.bright_red(),
        Severity::Warning => filled_bar.yellow(),
        Severity::Info => filled_bar.blue(),
    };

    let count_str = if count > 0 {
        match severity {
            Severity::Critical => count.to_string().red().bold(),
            Severity::Error => count.to_string().bright_red(),
            Severity::Warning => count.to_string().yellow(),
            Severity::Info => count.to_string().blue(),
        }
    } else {
        count.to_string().dimmed()
    };

    println!(
        "  {:>10} {} {}{} {}",
        label,
        Theme::severity(severity),
        colored_bar,
        empty_bar.dimmed(),
        count_str
    );
}

fn print_details(results: &[FileAnalysis]) {
    let findings: Vec<_> = results.iter().filter(|r| !r.findings.is_empty()).collect();

    if findings.is_empty() {
        println!("{}", "  ✨ No issues found! Your code looks great.".green());
        return;
    }

    println!("{}", Theme::header("DETAILS"));
    println!("{}", Theme::separator(60));
    println!();

    // Create source cache and renderer for rich diagnostics
    let mut cache = SourceCache::new();
    let renderer = RichDiagnosticRenderer::new();

    for result in findings {
        for finding in &result.findings {
            let output = renderer.render(finding, &mut cache);
            print!("{}", output);
            println!(); // Extra newline between findings
        }
    }
}

/// Legacy finding printer (kept for compact mode or fallback)
#[allow(dead_code)]
fn print_finding_simple(finding: &rma_common::Finding) {
    let severity = Theme::severity(finding.severity);
    let location = format!(
        "{}:{}",
        finding.location.start_line, finding.location.start_column
    )
    .dimmed();

    println!(
        "     {} [{}] {} {}",
        severity,
        finding.rule_id.dimmed(),
        location,
        finding.message
    );

    if let Some(snippet) = &finding.snippet {
        let truncated = if snippet.len() > 70 {
            format!("{}...", &snippet[..67])
        } else {
            snippet.clone()
        };
        println!("        {}", truncated.dimmed());
    }

    if let Some(suggestion) = &finding.suggestion {
        println!("        {} {}", "💡".dimmed(), suggestion.dimmed());
    }
}

fn print_footer(summary: &AnalysisSummary) {
    println!("{}", Theme::double_separator(60));

    if summary.critical_count > 0 || summary.error_count > 0 {
        println!(
            "  {} {} critical/error issues require attention",
            Theme::error_mark(),
            (summary.critical_count + summary.error_count)
                .to_string()
                .red()
                .bold()
        );
    } else if summary.warning_count > 0 {
        println!(
            "  {} {} warnings found - consider reviewing",
            Theme::warning_mark(),
            summary.warning_count.to_string().yellow()
        );
    } else {
        println!("  {} All checks passed!", Theme::success_mark());
    }

    println!();
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining_secs = secs - (mins * 60.0);
        format!("{}m {:.0}s", mins, remaining_secs)
    }
}
