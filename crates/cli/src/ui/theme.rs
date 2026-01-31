//! Color theme definitions for the CLI

#![allow(dead_code)]

use colored::{Color, Colorize};

/// Theme for CLI output
pub struct Theme;

impl Theme {
    // Severity colors
    pub const CRITICAL: Color = Color::Red;
    pub const ERROR: Color = Color::BrightRed;
    pub const WARNING: Color = Color::Yellow;
    pub const INFO: Color = Color::Blue;
    pub const SUCCESS: Color = Color::Green;

    // UI element colors
    pub const HEADER: Color = Color::Cyan;
    pub const DIM: Color = Color::BrightBlack;
    pub const HIGHLIGHT: Color = Color::BrightWhite;
    pub const PATH: Color = Color::BrightWhite;

    /// Format severity with color
    pub fn severity(severity: rma_common::Severity) -> colored::ColoredString {
        match severity {
            rma_common::Severity::Critical => "CRIT".red().bold(),
            rma_common::Severity::Error => "ERR ".bright_red(),
            rma_common::Severity::Warning => "WARN".yellow(),
            rma_common::Severity::Info => "INFO".blue(),
        }
    }

    /// Format severity badge (with background)
    pub fn severity_badge(severity: rma_common::Severity) -> colored::ColoredString {
        match severity {
            rma_common::Severity::Critical => " CRITICAL ".on_red().white().bold(),
            rma_common::Severity::Error => " ERROR ".on_bright_red().white(),
            rma_common::Severity::Warning => " WARNING ".on_yellow().black(),
            rma_common::Severity::Info => " INFO ".on_blue().white(),
        }
    }

    /// Format a count based on whether it's zero or not
    pub fn count(value: usize, zero_color: Color, nonzero_color: Color) -> colored::ColoredString {
        if value == 0 {
            value.to_string().color(zero_color)
        } else {
            value.to_string().color(nonzero_color).bold()
        }
    }

    /// Format a path
    pub fn path(path: &std::path::Path) -> colored::ColoredString {
        path.display().to_string().bright_white()
    }

    /// Format a rule ID
    pub fn rule_id(id: &str) -> colored::ColoredString {
        id.dimmed()
    }

    /// Format a header
    pub fn header(text: &str) -> colored::ColoredString {
        text.cyan().bold()
    }

    /// Format a subheader
    pub fn subheader(text: &str) -> colored::ColoredString {
        text.yellow().bold()
    }

    /// Format a separator line
    pub fn separator(width: usize) -> colored::ColoredString {
        "─".repeat(width).dimmed()
    }

    /// Format a double separator line
    pub fn double_separator(width: usize) -> colored::ColoredString {
        "═".repeat(width).dimmed()
    }

    /// Success checkmark
    pub fn success_mark() -> colored::ColoredString {
        "✓".green()
    }

    /// Error mark
    pub fn error_mark() -> colored::ColoredString {
        "✗".red()
    }

    /// Warning mark
    pub fn warning_mark() -> colored::ColoredString {
        "⚠".yellow()
    }

    /// Info mark
    pub fn info_mark() -> colored::ColoredString {
        "ℹ".blue()
    }

    /// Bullet point
    pub fn bullet() -> colored::ColoredString {
        "●".dimmed()
    }

    /// Arrow
    pub fn arrow() -> colored::ColoredString {
        "→".yellow()
    }
}
