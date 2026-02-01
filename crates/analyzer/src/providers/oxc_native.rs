//! Native Oxc integration for JS/TS analysis
//!
//! Uses oxc crates directly for parsing and semantic analysis.
//! Provides fast native Rust analysis without external binaries.

use super::AnalysisProvider;
use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use rma_common::{Confidence, Finding, FindingCategory, Language, Severity, SourceLocation};
use std::path::Path;
use tracing::debug;

/// Native Oxc provider using oxc crates directly
///
/// This provider uses oxc's parser and semantic analyzer for fast native
/// JS/TS analysis. It implements a subset of important security and quality
/// rules directly, providing instant results without external binaries.
pub struct OxcNativeProvider;

impl Default for OxcNativeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OxcNativeProvider {
    /// Create a new native Oxc provider
    pub fn new() -> Self {
        Self
    }

    /// Lint a single file using oxc's parser and semantic analyzer
    pub fn lint_file(&self, path: &Path, content: &str) -> Result<Vec<Finding>> {
        let allocator = Allocator::default();

        // Determine source type from file extension
        let source_type = SourceType::from_path(path).unwrap_or_default();

        // Parse the source code
        let parser_ret = Parser::new(&allocator, content, source_type).parse();

        if parser_ret.panicked {
            debug!("oxc parser panicked on {}", path.display());
            return Ok(Vec::new());
        }

        // Build semantic analysis
        let semantic_ret = SemanticBuilder::new().build(&parser_ret.program);

        if !semantic_ret.errors.is_empty() {
            debug!(
                "oxc semantic errors on {}: {}",
                path.display(),
                semantic_ret.errors.len()
            );
        }

        let semantic = semantic_ret.semantic;
        let mut findings = Vec::new();

        // Iterate over AST nodes and check for issues
        for node in semantic.nodes() {
            match node.kind() {
                // Debugger statements
                AstKind::DebuggerStatement(stmt) => {
                    findings.push(create_finding(
                        "oxc/no-debugger",
                        path,
                        content,
                        stmt.span.start as usize,
                        Severity::Warning,
                        "Unexpected 'debugger' statement",
                        source_type,
                        Confidence::High,
                        FindingCategory::Quality,
                    ));
                }

                // Dangerous function calls
                AstKind::CallExpression(call) => {
                    if let oxc_ast::ast::Expression::Identifier(ident) = &call.callee {
                        let name = ident.name.as_str();

                        // Dangerous code execution
                        if name == "eval" {
                            findings.push(create_finding(
                                "oxc/no-eval",
                                path,
                                content,
                                call.span.start as usize,
                                Severity::Error,
                                "Dynamic code execution is dangerous and can lead to injection",
                                source_type,
                                Confidence::High,
                                FindingCategory::Security,
                            ));
                        }

                        // Browser dialogs
                        if name == "alert" || name == "confirm" || name == "prompt" {
                            findings.push(create_finding(
                                "oxc/no-alert",
                                path,
                                content,
                                call.span.start as usize,
                                Severity::Warning,
                                &format!("Unexpected {}() call", name),
                                source_type,
                                Confidence::Medium,
                                FindingCategory::Quality,
                            ));
                        }
                    }
                }

                // Empty destructuring patterns
                AstKind::ObjectPattern(pattern) if pattern.properties.is_empty() => {
                    findings.push(create_finding(
                        "oxc/no-empty-pattern",
                        path,
                        content,
                        pattern.span.start as usize,
                        Severity::Warning,
                        "Empty destructuring pattern",
                        source_type,
                        Confidence::High,
                        FindingCategory::Quality,
                    ));
                }

                AstKind::ArrayPattern(pattern) if pattern.elements.is_empty() => {
                    findings.push(create_finding(
                        "oxc/no-empty-pattern",
                        path,
                        content,
                        pattern.span.start as usize,
                        Severity::Warning,
                        "Empty destructuring pattern",
                        source_type,
                        Confidence::High,
                        FindingCategory::Quality,
                    ));
                }

                // With statements (deprecated, scope issues)
                AstKind::WithStatement(stmt) => {
                    findings.push(create_finding(
                        "oxc/no-with",
                        path,
                        content,
                        stmt.span.start as usize,
                        Severity::Error,
                        "'with' statement is deprecated and causes scope issues",
                        source_type,
                        Confidence::High,
                        FindingCategory::Quality,
                    ));
                }

                _ => {}
            }
        }

        Ok(findings)
    }
}

impl AnalysisProvider for OxcNativeProvider {
    fn name(&self) -> &'static str {
        "oxc-native"
    }

    fn description(&self) -> &'static str {
        "Native Rust JS/TS analysis using oxc parser and semantic"
    }

    fn supports_language(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn is_available(&self) -> bool {
        true // Always available - native dependency
    }

    fn version(&self) -> Option<String> {
        Some("0.111.0".to_string()) // oxc version
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let content = std::fs::read_to_string(path)?;
        self.lint_file(path, &content)
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        use walkdir::WalkDir;

        let mut all_findings = Vec::new();

        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            let ext = file_path.extension().and_then(|e| e.to_str());

            match ext {
                Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts") => {
                    if let Ok(findings) = self.analyze_file(file_path) {
                        all_findings.extend(findings);
                    }
                }
                _ => continue,
            }
        }

        Ok(all_findings)
    }
}

/// Convert byte offset to line/column (1-indexed)
fn byte_offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    let mut current_offset = 0;

    for ch in content.chars() {
        if current_offset >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        current_offset += ch.len_utf8();
    }

    (line, col)
}

/// Create a finding from span offset
#[allow(clippy::too_many_arguments)]
fn create_finding(
    rule_id: &str,
    path: &Path,
    content: &str,
    offset: usize,
    severity: Severity,
    message: &str,
    source_type: SourceType,
    confidence: Confidence,
    category: FindingCategory,
) -> Finding {
    let (line, column) = byte_offset_to_line_col(content, offset);

    let language = if source_type.is_typescript() {
        Language::TypeScript
    } else {
        Language::JavaScript
    };

    let location = SourceLocation::new(path.to_path_buf(), line, column, line, column);

    let mut finding = Finding {
        id: format!("{}:{}:{}", rule_id, path.display(), line),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location,
        language,
        snippet: None,
        suggestion: None,
        confidence,
        category,
        fingerprint: None,
    };
    finding.compute_fingerprint();
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = OxcNativeProvider::new();
        assert!(provider.is_available());
        assert!(provider.supports_language(Language::JavaScript));
        assert!(provider.supports_language(Language::TypeScript));
        assert!(!provider.supports_language(Language::Rust));
    }

    #[test]
    fn test_detect_debugger() {
        let provider = OxcNativeProvider::new();
        let content = "function test() { debugger; return 1; }";
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "oxc/no-debugger");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_detect_alert() {
        let provider = OxcNativeProvider::new();
        let content = r#"alert("Hello!");"#;
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "oxc/no-alert");
    }

    #[test]
    fn test_detect_empty_pattern() {
        let provider = OxcNativeProvider::new();
        let content = "const {} = obj;";
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "oxc/no-empty-pattern");
    }

    #[test]
    fn test_clean_code() {
        let provider = OxcNativeProvider::new();
        let content = r#"
            function add(a, b) {
                return a + b;
            }
            console.log(add(1, 2));
        "#;
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_typescript_support() {
        let provider = OxcNativeProvider::new();
        let content = r#"
            function greet(name: string): void {
                debugger;
                console.log(`Hello, ${name}`);
            }
        "#;
        let findings = provider.lint_file(Path::new("test.ts"), content).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].language, Language::TypeScript);
    }
}
