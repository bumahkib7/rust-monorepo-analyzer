//! SARIF output formatting

use anyhow::Result;
use rma_analyzer::FileAnalysis;
use rma_common::Severity;
use std::path::PathBuf;

/// Normalize a file path for SARIF output
/// Removes ./ prefix and ensures it's a clean relative path
fn normalize_sarif_path(path: &std::path::Path) -> String {
    let path_str = path.display().to_string();
    // Remove leading ./ or ./
    let normalized = path_str
        .strip_prefix("./")
        .or_else(|| path_str.strip_prefix(".\\"))
        .unwrap_or(&path_str);
    normalized.to_string()
}

/// Output results in SARIF 2.1.0 format
pub fn output(results: &[FileAnalysis], output_file: Option<PathBuf>) -> Result<()> {
    let rules: Vec<_> = results
        .iter()
        .flat_map(|r| &r.findings)
        .map(|f| &f.rule_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(|rule_id| {
            serde_json::json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": rule_id
                }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RMA",
                    "fullName": "Rust Monorepo Analyzer",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bumahkib7/rust-monorepo-analyzer",
                    "rules": rules
                }
            },
            "results": results.iter().flat_map(|r| {
                r.findings.iter().map(|f| {
                    let mut result = serde_json::json!({
                        "ruleId": f.rule_id,
                        "ruleIndex": rules.iter().position(|rule| {
                            rule.get("id").and_then(|v| v.as_str()) == Some(&f.rule_id)
                        }).unwrap_or(0),
                        "level": match f.severity {
                            Severity::Critical => "error",
                            Severity::Error => "error",
                            Severity::Warning => "warning",
                            Severity::Info => "note",
                        },
                        "message": {
                            "text": &f.message
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": normalize_sarif_path(&f.location.file),
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "startLine": f.location.start_line,
                                    "startColumn": f.location.start_column,
                                    "endLine": f.location.end_line,
                                    "endColumn": f.location.end_column,
                                    "snippet": f.snippet.as_ref().map(|s| serde_json::json!({
                                        "text": s
                                    }))
                                }
                            }
                        }]
                    });
                    // Only add fixes if there's a suggestion
                    if let Some(suggestion) = &f.suggestion {
                        result["fixes"] = serde_json::json!([{
                            "description": {
                                "text": suggestion
                            }
                        }]);
                    }
                    result
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>(),
            "automationDetails": {
                "id": format!("rma-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"))
            }
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)?;

    if let Some(path) = output_file {
        std::fs::write(&path, &json)?;
        eprintln!("SARIF output written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}
