//! GitHub Actions workflow command output format
//!
//! Outputs findings using GitHub Actions workflow commands for annotations:
//! - ::error file=...,line=...,col=...,title=...::message
//! - ::warning file=...,line=...,col=...,title=...::message
//!
//! See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions

use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use rma_common::Severity;
use std::time::Duration;

/// Output results in GitHub Actions workflow command format
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
) -> Result<()> {
    // Group findings by file for better annotation display
    for result in results {
        for finding in &result.findings {
            let level = match finding.severity {
                Severity::Critical | Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };

            let file = finding.location.file.display();
            let line = finding.location.start_line;
            let col = finding.location.start_column;
            let end_line = finding.location.end_line;
            let end_col = finding.location.end_column;
            let title = &finding.rule_id;

            // Escape message for workflow command
            let message = escape_workflow_message(&finding.message);

            println!(
                "::{level} file={file},line={line},col={col},endLine={end_line},endColumn={end_col},title={title}::{message}"
            );
        }
    }

    // Output summary as a group
    println!("::group::RMA Scan Summary");
    println!("Files analyzed: {}", summary.files_analyzed);
    println!("Total findings: {}", summary.total_findings);
    println!("  Critical: {}", summary.critical_count);
    println!("  Error: {}", summary.error_count);
    println!("  Warning: {}", summary.warning_count);
    println!("  Info: {}", summary.info_count);
    println!("Duration: {:.2}s", duration.as_secs_f64());
    println!("::endgroup::");

    // Set output variables for use in workflow
    println!(
        "::set-output name=total_findings::{}",
        summary.total_findings
    );
    println!(
        "::set-output name=critical_count::{}",
        summary.critical_count
    );
    println!("::set-output name=error_count::{}", summary.error_count);
    println!("::set-output name=warning_count::{}", summary.warning_count);

    Ok(())
}

/// Escape special characters in workflow command messages
fn escape_workflow_message(msg: &str) -> String {
    msg.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}
