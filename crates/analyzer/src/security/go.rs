//! Go-specific security vulnerability DETECTION rules
//!
//! Categorized into:
//! - **Sinks (High Confidence)**: Precise detection of dangerous patterns
//! - **Review Hints (Low Confidence)**: Patterns that need human review

use crate::rules::{Rule, create_finding_with_confidence};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

// =============================================================================
// SECTION A: HIGH-CONFIDENCE SINKS
// =============================================================================

/// Detects actual command injection patterns - shell mode with dynamic arguments
///
/// Only flags as CRITICAL when there's evidence of shell mode (-c) with dynamic args.
/// Plain `exec.Command("sh")` without shell mode is NOT injection.
/// Confidence: HIGH (requires evidence of injection pattern)
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "go/command-injection"
    }

    fn description(&self) -> &str {
        "Detects command injection patterns (shell mode with dynamic arguments)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if func_text.ends_with("exec.Command") || func_text == "Command" {
                    let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    // Must have shell + shell mode (-c)
                    let is_shell = args_text.contains("\"sh\"")
                        || args_text.contains("\"bash\"")
                        || args_text.contains("\"/bin/sh\"")
                        || args_text.contains("\"/bin/bash\"");

                    let has_shell_mode = args_text.contains("\"-c\"");

                    // Look for dynamic argument patterns (check wider context - the whole function)
                    let context_start = node.start_byte().saturating_sub(500);
                    let context_end = (node.end_byte() + 300).min(parsed.content.len());
                    let context = &parsed.content[context_start..context_end];
                    let has_dynamic = context.contains("fmt.Sprintf")
                        || context.contains("Sprintf")
                        || context.contains("+ \"")
                        || context.contains("userInput")
                        || context.contains("user_input");

                    if is_shell && has_shell_mode && has_dynamic {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "Command injection: shell -c mode with dynamic arguments - validate input",
                            Language::Go,
                            Confidence::High,
                        ));
                    } else if is_shell && has_shell_mode {
                        // Shell mode without obvious dynamic args - still worth noting
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Shell command with -c mode - ensure arguments are not from untrusted input",
                            Language::Go,
                            Confidence::Medium,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// Detects SQL query building with string concatenation/formatting
/// Confidence: HIGH (in database context with fmt.Sprintf)
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn id(&self) -> &str {
        "go/sql-injection"
    }

    fn description(&self) -> &str {
        "Detects SQL queries built with string formatting that may allow injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check files that import database/sql
        if !parsed.content.contains("database/sql") && !parsed.content.contains("\"sql\"") {
            return findings;
        }

        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                let lower = text.to_lowercase();

                // Check for fmt.Sprintf with SQL keywords followed by db.Query/Exec
                if (lower.contains("fmt.sprintf") || lower.contains("fmt.sprintf"))
                    && (lower.contains("select ")
                        || lower.contains("insert ")
                        || lower.contains("update ")
                        || lower.contains("delete "))
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "SQL query built with fmt.Sprintf - use parameterized queries instead",
                        Language::Go,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

/// Detects unsafe pointer operations
/// Confidence: HIGH (AST-based)
pub struct UnsafePointerRule;

impl Rule for UnsafePointerRule {
    fn id(&self) -> &str {
        "go/unsafe-pointer"
    }

    fn description(&self) -> &str {
        "Detects use of unsafe.Pointer which bypasses Go's type safety"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child_by_field_name("function") {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if func_text.contains("unsafe.Pointer") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "unsafe.Pointer bypasses Go's type safety - ensure this is necessary",
                        Language::Go,
                        Confidence::High,
                    ));
                }
            }
        });

        // Also check type conversions to unsafe.Pointer
        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "type_conversion_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text.contains("unsafe.Pointer")
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Conversion to unsafe.Pointer - requires careful review",
                    Language::Go,
                    Confidence::High,
                ));
            }
        });

        findings
    }
}

/// Detects http.ListenAndServe without TLS
/// Confidence: HIGH (precise pattern)
pub struct InsecureHttpRule;

impl Rule for InsecureHttpRule {
    fn id(&self) -> &str {
        "go/insecure-http"
    }

    fn description(&self) -> &str {
        "Detects HTTP servers without TLS which transmit data in cleartext"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child_by_field_name("function") {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // http.ListenAndServe (not ListenAndServeTLS)
                if func_text.ends_with("ListenAndServe") && !func_text.contains("TLS") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "HTTP server without TLS - consider using ListenAndServeTLS for production",
                        Language::Go,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

// =============================================================================
// SECTION B: REVIEW HINTS (LOW CONFIDENCE)
// =============================================================================

/// Review hint: Error handling that ignores errors
/// Confidence: LOW (code quality)
pub struct IgnoredErrorHint;

impl Rule for IgnoredErrorHint {
    fn id(&self) -> &str {
        "go/ignored-error-hint"
    }

    fn description(&self) -> &str {
        "Review hint: error return value may be ignored"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Look for assignments where error is assigned to _
        find_nodes_by_kind(&mut cursor, "short_var_declaration", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Pattern: result, _ := something() or _, err := (where err is then _)
                if text.contains(", _") && text.contains(":=") {
                    // Check if this looks like ignoring an error
                    if text.contains("err")
                        || parsed.content[..node.start_byte()].ends_with("// ignore error")
                    {
                        return; // Intentionally ignored
                    }

                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Consider handling the error instead of discarding it",
                        Language::Go,
                        Confidence::Low,
                    ));
                }
            }
        });
        findings
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn find_nodes_by_kind<F>(cursor: &mut tree_sitter::TreeCursor, kind: &str, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == kind {
            callback(node);
        }

        if cursor.goto_first_child() {
            continue;
        }

        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[test]
    fn test_command_injection_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // This IS injection: shell + -c mode + dynamic args via fmt.Sprintf
        let content = r#"
package main

import (
    "os/exec"
    "fmt"
)

func runCommand(userInput string) {
    cmd := fmt.Sprintf("echo %s", userInput)
    exec.Command("sh", "-c", cmd).Run()
}
"#;

        let parsed = parser.parse_file(Path::new("test.go"), content).unwrap();
        let rule = CommandInjectionRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty(), "Should detect injection pattern");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_shell_spawn_without_injection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // This is NOT injection - just shell spawn with static args (no -c mode)
        let content = r#"
package main

import "os/exec"

func getVersion() {
    exec.Command("sh", "--version").Run()
}
"#;

        let parsed = parser.parse_file(Path::new("test.go"), content).unwrap();
        let rule = CommandInjectionRule;
        let findings = rule.check(&parsed);

        // Should NOT flag (no -c mode)
        assert!(
            findings.is_empty(),
            "Plain shell spawn without -c is not injection"
        );
    }

    #[test]
    fn test_unsafe_pointer_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "unsafe"

func danger() {
    var x int = 42
    p := unsafe.Pointer(&x)
    _ = p
}
"#;

        let parsed = parser.parse_file(Path::new("test.go"), content).unwrap();
        let rule = UnsafePointerRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty());
    }
}
