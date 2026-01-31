//! Diagnostic error code registry
//!
//! Maps rule IDs to error codes following the pattern:
//! - RMA-S### for Security issues
//! - RMA-Q### for Quality issues
//! - RMA-T### for Style/lint issues
//!
//! Number ranges:
//! - 001-099: Rust
//! - 101-199: JavaScript/TypeScript
//! - 201-299: Python
//! - 301-399: Go
//! - 401-499: Java
//! - 501-599: Generic (cross-language)

use std::collections::HashMap;
use std::sync::LazyLock;

/// Category of diagnostic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Security vulnerabilities and risks
    Security,
    /// Code quality issues
    Quality,
    /// Style and lint issues
    Style,
}

impl Category {
    /// Get the category prefix letter
    pub fn prefix(&self) -> char {
        match self {
            Category::Security => 'S',
            Category::Quality => 'Q',
            Category::Style => 'T',
        }
    }
}

/// A diagnostic code with metadata
#[derive(Debug, Clone)]
pub struct DiagnosticCode {
    /// The full code string (e.g., "RMA-S001")
    pub code: String,
    /// The category of the diagnostic
    pub category: Category,
    /// Optional documentation URL
    pub docs_url: Option<&'static str>,
}

impl DiagnosticCode {
    /// Create a new diagnostic code
    pub fn new(category: Category, number: u16) -> Self {
        Self {
            code: format!("RMA-{}{:03}", category.prefix(), number),
            category,
            docs_url: None,
        }
    }

    /// Create with a documentation URL
    pub fn with_docs(category: Category, number: u16, docs_url: &'static str) -> Self {
        Self {
            code: format!("RMA-{}{:03}", category.prefix(), number),
            category,
            docs_url: Some(docs_url),
        }
    }
}

/// Registry mapping rule IDs to diagnostic codes
pub struct DiagnosticCodeRegistry {
    codes: HashMap<&'static str, DiagnosticCode>,
}

impl DiagnosticCodeRegistry {
    /// Create a new empty registry
    fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }

    /// Register a rule ID with its diagnostic code
    fn register(&mut self, rule_id: &'static str, category: Category, number: u16) {
        self.codes
            .insert(rule_id, DiagnosticCode::new(category, number));
    }

    /// Get the diagnostic code for a rule ID
    pub fn get(&self, rule_id: &str) -> DiagnosticCode {
        self.codes.get(rule_id).cloned().unwrap_or_else(|| {
            // Generate a deterministic code for unknown rules
            let hash = Self::hash_rule_id(rule_id);
            DiagnosticCode::new(Category::Quality, hash)
        })
    }

    /// Generate a deterministic hash for unknown rule IDs
    fn hash_rule_id(rule_id: &str) -> u16 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        rule_id.hash(&mut hasher);
        // Range 900-999 for unknown rules
        (hasher.finish() % 100 + 900) as u16
    }
}

/// Global diagnostic code registry
pub static REGISTRY: LazyLock<DiagnosticCodeRegistry> = LazyLock::new(|| {
    let mut r = DiagnosticCodeRegistry::new();

    // =========================================
    // Rust Security Rules (S001-S099)
    // =========================================
    r.register("rust/unsafe-block", Category::Security, 1);
    r.register("rust/transmute-used", Category::Security, 2);
    r.register("rust/raw-pointer-deref", Category::Security, 3);
    r.register("rust/command-injection", Category::Security, 4);
    r.register("rust/sql-injection", Category::Security, 5);
    r.register("rust/path-traversal", Category::Security, 6);
    r.register("rust/crypto-weak", Category::Security, 7);
    r.register("rust/deserialization-unsafe", Category::Security, 8);

    // =========================================
    // Rust Quality Rules (Q001-Q099)
    // =========================================
    r.register("rust/unwrap-used", Category::Quality, 1);
    r.register("rust/expect-used", Category::Quality, 2);
    r.register("rust/panic-used", Category::Quality, 3);
    r.register("rust/unchecked-index", Category::Quality, 4);
    r.register("rust/clippy-warnings", Category::Quality, 5);

    // =========================================
    // JavaScript Security Rules (S101-S199)
    // =========================================
    r.register("js/eval-usage", Category::Security, 101);
    r.register("js/dynamic-code-execution", Category::Security, 101);
    r.register("js/function-constructor", Category::Security, 102);
    r.register("js/timer-string-eval", Category::Security, 103);
    r.register("js/innerhtml-xss", Category::Security, 104);
    r.register("js/innerHTML-usage", Category::Security, 104);
    r.register("js/document-write", Category::Security, 105);
    r.register("js/prototype-pollution", Category::Security, 106);
    r.register("js/sql-injection", Category::Security, 107);
    r.register("js/command-injection", Category::Security, 108);
    r.register("js/path-traversal", Category::Security, 109);
    r.register("js/insecure-random", Category::Security, 110);

    // =========================================
    // JavaScript Quality Rules (Q101-Q199)
    // =========================================
    r.register("js/console-log", Category::Style, 101);

    // =========================================
    // TypeScript Rules (same as JS, 101-199)
    // =========================================
    r.register("ts/eval-usage", Category::Security, 101);
    r.register("ts/dynamic-code-execution", Category::Security, 101);
    r.register("ts/innerhtml-xss", Category::Security, 104);

    // =========================================
    // Python Security Rules (S201-S299)
    // =========================================
    r.register("python/exec-usage", Category::Security, 201);
    r.register("python/eval-usage", Category::Security, 202);
    r.register("python/dynamic-execution", Category::Security, 201);
    r.register("python/shell-injection", Category::Security, 203);
    r.register("python/sql-injection", Category::Security, 204);
    r.register("python/unsafe-deserialization", Category::Security, 205);
    r.register("python/yaml-load", Category::Security, 206);
    r.register("python/hardcoded-secret", Category::Security, 207);
    r.register("python/path-traversal", Category::Security, 208);
    r.register("python/insecure-hash", Category::Security, 209);

    // =========================================
    // Go Security Rules (S301-S399)
    // =========================================
    r.register("go/sql-injection", Category::Security, 301);
    r.register("go/command-injection", Category::Security, 302);
    r.register("go/path-traversal", Category::Security, 303);
    r.register("go/insecure-tls", Category::Security, 304);
    r.register("go/weak-crypto", Category::Security, 305);

    // =========================================
    // Java Security Rules (S401-S499)
    // =========================================
    r.register("java/sql-injection", Category::Security, 401);
    r.register("java/command-injection", Category::Security, 402);
    r.register("java/path-traversal", Category::Security, 403);
    r.register("java/deserialization", Category::Security, 404);
    r.register("java/xxe", Category::Security, 405);
    r.register("java/weak-crypto", Category::Security, 406);

    // =========================================
    // Generic Security Rules (S501-S599)
    // =========================================
    r.register("generic/hardcoded-secret", Category::Security, 501);
    r.register("generic/insecure-crypto", Category::Security, 502);
    r.register("generic/sensitive-data-exposure", Category::Security, 503);

    // =========================================
    // Generic Quality Rules (Q501-Q599)
    // =========================================
    r.register("generic/long-function", Category::Quality, 501);
    r.register("generic/high-complexity", Category::Quality, 502);
    r.register("generic/deep-nesting", Category::Quality, 503);
    r.register("generic/too-many-params", Category::Quality, 504);
    r.register("generic/duplicate-code", Category::Quality, 505);

    // =========================================
    // Generic Style Rules (T501-T599)
    // =========================================
    r.register("generic/todo-fixme", Category::Style, 501);
    r.register("generic/missing-docs", Category::Style, 502);
    r.register("generic/inconsistent-naming", Category::Style, 503);

    r
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_rule() {
        let code = REGISTRY.get("rust/unsafe-block");
        assert_eq!(code.code, "RMA-S001");
        assert_eq!(code.category, Category::Security);
    }

    #[test]
    fn test_unknown_rule_generates_code() {
        let code = REGISTRY.get("unknown/some-rule");
        assert!(code.code.starts_with("RMA-Q9"));
    }

    #[test]
    fn test_category_prefix() {
        assert_eq!(Category::Security.prefix(), 'S');
        assert_eq!(Category::Quality.prefix(), 'Q');
        assert_eq!(Category::Style.prefix(), 'T');
    }
}
