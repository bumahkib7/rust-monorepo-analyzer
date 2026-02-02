//! Security vulnerability DETECTION rules for various languages
//!
//! This module contains rules that DETECT dangerous code patterns.
//! These are static analysis rules for finding security issues.
//!
//! Each language module is organized into:
//! - **Section A: High-Confidence Sinks** - Precise detection of dangerous patterns
//! - **Section B: Review Hints** - Patterns that need human verification
//!
//! The `dataflow_rules` module contains rules powered by the dataflow framework:
//! - Dead store detection
//! - Unused variable detection
//! - Cross-function taint flow detection
//! - Command injection via taint tracking
//! - SQL injection via taint tracking
//! - SSRF (Server-Side Request Forgery) via taint tracking
//! - Path traversal via taint tracking
//! - XSS detection via taint tracking
//! - Resource leak detection via CFG path analysis
//!
//! The `typestate_rules` module contains typestate analysis rules:
//! - File resource lifecycle tracking (open/read/write/close)
//! - Detection of use-after-close, double-open, and resource leaks
//! - Language-specific safe patterns (with, defer, try-with-resources, RAII)
//! - Cryptographic API usage tracking (Hash, HMAC, Cipher state machines)
//! - Detection of crypto misuse: update after finalize, missing initialization
//! - Detection of weak algorithms (MD5, SHA1, DES, RC4) and unsafe modes (ECB)
//! - Database connection lifecycle tracking (connect/begin/commit/rollback/close)
//! - Detection of connection leaks, uncommitted transactions, nested transactions
//! - ORM support: SQLAlchemy, Hibernate, GORM, Sequelize

pub mod dataflow_rules;
pub mod generic;
pub mod go;
pub mod java;
pub mod javascript;
pub mod null_pointer;
pub mod python;
pub mod resource_leak;
pub mod rust;
pub mod typestate_rules;
pub mod xss_taint;

// Re-export dataflow rules for easier access
pub use dataflow_rules::{
    CommandInjectionTaintRule, CrossFunctionTaintRule, DeadStoreRule, PathTraversalTaintRule,
    SqlInjectionTaintRule, SsrfTaintRule, UninitializedVariableRule, UnusedVariableRule,
    dataflow_rules,
};

// Re-export null pointer rule
pub use null_pointer::NullPointerRule;

// Re-export resource leak rule
pub use resource_leak::ResourceLeakRule;

// Re-export typestate rules
pub use typestate_rules::{
    CryptoObjectType,
    CryptoState,
    CryptoStateMachine,
    // Crypto typestate
    CryptoTypestateRule,
    CryptoViolationType,
    DatabaseAction,
    DatabaseState,
    DatabaseStateMachine,
    // Database typestate
    DatabaseTypestateRule,
    DatabaseViolation,
    FileOperation,
    FileState,
    FileStateMachine,
    // File typestate
    FileTypestateRule,
    IteratorOperation,
    IteratorState,
    IteratorStateMachine,
    // Iterator typestate
    IteratorTypestateRule,
    LockOperation,
    LockState,
    LockStateMachine,
    // Lock typestate
    LockTypestateRule,
    // Analyzer (from typestate_rules module)
    TypestateAnalyzer,
    ViolationType,
    // Convenience function
    builtin_typestate_rules,
};

// Re-export XSS detection rule
pub use xss_taint::{XssDetectionRule, XssSourceType};
