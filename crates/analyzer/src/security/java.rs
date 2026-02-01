//! Java-specific security vulnerability DETECTION rules
//!
//! Categorized into:
//! - **Sinks (High Confidence)**: Precise detection of dangerous patterns
//! - **Review Hints (Low Confidence)**: Patterns that need human review

use crate::rules::{Rule, create_finding_with_confidence};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// Case-insensitive substring search without allocation
#[inline]
fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

// =============================================================================
// SECTION A: HIGH-CONFIDENCE SINKS
// =============================================================================

/// Detects actual command injection patterns in Java
///
/// Only flags as CRITICAL when there's evidence of:
/// - Runtime.exec() or ProcessBuilder with shell mode (/c, -c)
/// - AND dynamic argument composition (string concat, variables)
///
/// Plain process execution without dynamic args is NOT injection.
/// Confidence: HIGH (requires evidence of injection pattern)
pub struct CommandExecutionRule;

impl Rule for CommandExecutionRule {
    fn id(&self) -> &str {
        "java/command-injection"
    }

    fn description(&self) -> &str {
        "Detects command injection patterns (shell mode with dynamic arguments)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "method_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Runtime.getRuntime().exec() with dynamic args
                if text.contains("Runtime") && text.contains("getRuntime") {
                    // Check for string concatenation (injection pattern)
                    let has_concat = text.contains(" + ") || text.contains("\" +");

                    if has_concat {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "Command injection: Runtime.exec with string concatenation - use ProcessBuilder with array args",
                            Language::Java,
                            Confidence::High,
                        ));
                    } else {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Runtime.exec detected - prefer ProcessBuilder with explicit arguments",
                            Language::Java,
                            Confidence::Medium,
                        ));
                    }
                }
            }
        });

        // Check ProcessBuilder with shell + dynamic args
        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "object_creation_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text.contains("ProcessBuilder")
            {
                let is_shell = text.contains("\"sh\"")
                    || text.contains("\"bash\"")
                    || text.contains("\"cmd\"")
                    || text.contains("\"/bin/sh\"")
                    || text.contains("\"cmd.exe\"");

                let has_shell_mode =
                    text.contains("\"-c\"") || text.contains("\"/c\"") || text.contains("\"/C\"");

                let has_concat = text.contains(" + ") || text.contains("\" +");

                if is_shell && has_shell_mode && has_concat {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "Command injection: ProcessBuilder with shell mode and string concatenation",
                        Language::Java,
                        Confidence::High,
                    ));
                } else if is_shell && has_shell_mode {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "ProcessBuilder with shell mode - ensure arguments are not from untrusted input",
                        Language::Java,
                        Confidence::Medium,
                    ));
                }
            }
        });

        findings
    }
}

/// Detects SQL queries built with string concatenation
/// Confidence: HIGH (in JDBC context)
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn id(&self) -> &str {
        "java/sql-injection"
    }

    fn description(&self) -> &str {
        "Detects SQL queries built with string concatenation that may allow injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check files that use JDBC
        if !parsed.content.contains("java.sql")
            && !parsed.content.contains("executeQuery")
            && !parsed.content.contains("executeUpdate")
        {
            return findings;
        }

        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "method_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // executeQuery/executeUpdate with string concatenation
                if (text.contains("executeQuery") || text.contains("executeUpdate"))
                    && (text.contains(" + ") || text.contains("\" +"))
                {
                    // Use case-insensitive search without allocation
                    if contains_ignore_case(text, "select ")
                        || contains_ignore_case(text, "insert ")
                        || contains_ignore_case(text, "update ")
                        || contains_ignore_case(text, "delete ")
                    {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "SQL query with string concatenation - use PreparedStatement instead",
                            Language::Java,
                            Confidence::High,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// Detects deserialization of untrusted data
/// Confidence: HIGH (ObjectInputStream is dangerous)
pub struct InsecureDeserializationRule;

impl Rule for InsecureDeserializationRule {
    fn id(&self) -> &str {
        "java/insecure-deserialization"
    }

    fn description(&self) -> &str {
        "Detects ObjectInputStream usage which can lead to remote code execution"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "object_creation_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text.contains("ObjectInputStream")
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Critical,
                    "ObjectInputStream can lead to RCE - use safe alternatives like JSON",
                    Language::Java,
                    Confidence::High,
                ));
            }
        });

        // Also check readObject calls
        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "method_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text.contains(".readObject(")
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "readObject() on untrusted data can lead to RCE - validate input source",
                    Language::Java,
                    Confidence::High,
                ));
            }
        });

        findings
    }
}

/// Detects XXE (XML External Entity) vulnerabilities
/// Confidence: HIGH (XMLInputFactory/DocumentBuilder without secure config)
pub struct XxeVulnerabilityRule;

impl Rule for XxeVulnerabilityRule {
    fn id(&self) -> &str {
        "java/xxe-vulnerability"
    }

    fn description(&self) -> &str {
        "Detects XML parsers that may be vulnerable to XXE attacks"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if file uses XML parsing
        if !parsed.content.contains("XMLInputFactory")
            && !parsed.content.contains("DocumentBuilder")
            && !parsed.content.contains("SAXParser")
        {
            return findings;
        }

        // Check if secure features are disabled
        let has_secure_config = parsed.content.contains("FEATURE_SECURE_PROCESSING")
            || parsed.content.contains("setFeature")
            || parsed.content.contains("disallow-doctype-decl");

        if !has_secure_config {
            let mut cursor = parsed.tree.walk();

            find_nodes_by_kind(&mut cursor, "object_creation_expression", |node: Node| {
                if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                    && (text.contains("DocumentBuilder")
                        || text.contains("SAXParser")
                        || text.contains("XMLInputFactory"))
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        "XML parser without secure configuration - vulnerable to XXE attacks",
                        Language::Java,
                        Confidence::High,
                    ));
                }
            });
        }
        findings
    }
}

/// Detects path traversal vulnerabilities
/// Confidence: HIGH (File with user input patterns)
pub struct PathTraversalRule;

impl Rule for PathTraversalRule {
    fn id(&self) -> &str {
        "java/path-traversal"
    }

    fn description(&self) -> &str {
        "Detects file operations with dynamic paths that may allow directory traversal"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "object_creation_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // new File() with string concatenation
                if text.starts_with("new File(") && (text.contains(" + ") || text.contains("\" +"))
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "File path with concatenation - validate to prevent directory traversal",
                        Language::Java,
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

/// Review hint: Catching generic Exception
/// Confidence: LOW (code quality)
pub struct GenericExceptionHint;

impl Rule for GenericExceptionHint {
    fn id(&self) -> &str {
        "java/generic-exception-hint"
    }

    fn description(&self) -> &str {
        "Review hint: catching generic Exception may hide bugs"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "catch_clause", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Catching Exception or Throwable
                if text.contains("Exception e)") || text.contains("Throwable") {
                    // Skip if it's in a top-level handler (main method, etc.)
                    if parsed.content.contains("public static void main") {
                        return;
                    }

                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Catching generic Exception - consider catching specific exceptions",
                        Language::Java,
                        Confidence::Low,
                    ));
                }
            }
        });
        findings
    }
}

/// Review hint: System.out.println in production code
/// Confidence: LOW (code quality)
pub struct SystemOutHint;

impl Rule for SystemOutHint {
    fn id(&self) -> &str {
        "java/system-out-hint"
    }

    fn description(&self) -> &str {
        "Review hint: System.out.println should use proper logging in production"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Java
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "method_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && (text.contains("System.out.print") || text.contains("System.err.print"))
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Info,
                    "System.out detected - consider using a logging framework",
                    Language::Java,
                    Confidence::Low,
                ));
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
    fn test_deserialization_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
import java.io.ObjectInputStream;

public class Danger {
    public Object deserialize(InputStream is) {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }
}
"#;

        let parsed = parser.parse_file(Path::new("Test.java"), content).unwrap();
        let rule = InsecureDeserializationRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty());
    }
}
