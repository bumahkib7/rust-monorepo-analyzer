//! Output formatting utilities

pub mod json;
pub mod sarif;
pub mod tables;
pub mod text;

use crate::OutputFormat;
use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use std::path::PathBuf;
use std::time::Duration;

/// Format analysis results based on output format
pub fn format_results(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    format: OutputFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    match format {
        OutputFormat::Text => text::output(results, summary, duration),
        OutputFormat::Json => json::output(results, summary, duration, output_file),
        OutputFormat::Sarif => sarif::output(results, output_file),
        OutputFormat::Compact => text::output_compact(results, summary, duration),
        OutputFormat::Markdown => tables::output_markdown(results, summary, duration, output_file),
    }
}

/// Write output to file or stdout
#[allow(dead_code)]
pub fn write_output(content: &str, output_file: Option<PathBuf>) -> Result<()> {
    if let Some(path) = output_file {
        std::fs::write(&path, content)?;
        eprintln!("Output written to: {}", path.display());
    } else {
        println!("{}", content);
    }
    Ok(())
}
