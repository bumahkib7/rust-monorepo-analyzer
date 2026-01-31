//! Security vulnerability DETECTION rules for various languages
//!
//! This module contains rules that DETECT dangerous code patterns.
//! These are static analysis rules for finding security issues.
//!
//! Each language module is organized into:
//! - **Section A: High-Confidence Sinks** - Precise detection of dangerous patterns
//! - **Section B: Review Hints** - Patterns that need human verification

pub mod generic;
pub mod go;
pub mod java;
pub mod javascript;
pub mod python;
pub mod rust;
