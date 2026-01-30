//! JSON output formatting

use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use std::path::PathBuf;
use std::time::Duration;

/// Output results in JSON format
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let output = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "files_analyzed": summary.files_analyzed,
            "total_findings": summary.total_findings,
            "total_loc": summary.total_loc,
            "total_complexity": summary.total_complexity,
            "by_severity": {
                "critical": summary.critical_count,
                "error": summary.error_count,
                "warning": summary.warning_count,
                "info": summary.info_count,
            }
        },
        "duration_ms": duration.as_millis(),
        "results": results.iter().map(|r| {
            serde_json::json!({
                "path": r.path,
                "language": format!("{:?}", r.language),
                "metrics": r.metrics,
                "findings": r.findings.iter().map(|f| {
                    serde_json::json!({
                        "rule_id": f.rule_id,
                        "severity": format!("{:?}", f.severity),
                        "message": f.message,
                        "location": {
                            "file": f.location.file.display().to_string(),
                            "start_line": f.location.start_line,
                            "start_column": f.location.start_column,
                            "end_line": f.location.end_line,
                            "end_column": f.location.end_column,
                        },
                        "rule_id": &f.rule_id,
                        "snippet": f.snippet,
                        "suggestion": f.suggestion,
                    })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });

    let json = serde_json::to_string_pretty(&output)?;

    if let Some(path) = output_file {
        std::fs::write(&path, &json)?;
        eprintln!("JSON output written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}
