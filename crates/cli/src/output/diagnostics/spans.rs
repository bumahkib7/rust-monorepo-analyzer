//! Span rendering for diagnostic output
//!
//! Handles the rendering of source code spans with:
//! - Line numbers in a gutter
//! - Underline/caret highlighting for the relevant range
//! - Context lines before and after

use super::source::SourceFile;
use colored::Colorize;
use rma_common::Severity;

/// Renders source code spans with highlighting
pub struct SpanRenderer;

impl SpanRenderer {
    /// Render a source span with context and highlighting
    ///
    /// # Arguments
    /// * `source` - The source file
    /// * `start_line` - Starting line number (1-indexed)
    /// * `start_col` - Starting column (1-indexed)
    /// * `end_line` - Ending line number (1-indexed)
    /// * `end_col` - Ending column (1-indexed)
    /// * `severity` - Severity for coloring the underline
    /// * `context` - Number of context lines to show before/after
    /// * `label` - Optional label to show under the span
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        source: &SourceFile,
        start_line: usize,
        start_col: usize,
        end_line: usize,
        end_col: usize,
        severity: Severity,
        context: usize,
        label: Option<&str>,
    ) -> String {
        let mut output = String::new();

        // For multi-line spans (>3 lines), show abbreviated view
        let is_long_span = end_line.saturating_sub(start_line) > 3;

        // Calculate display range
        let first_line = start_line.saturating_sub(context).max(1);
        let last_line = if is_long_span {
            // For long spans, just show first line + label
            start_line
        } else {
            (end_line + context).min(source.line_count())
        };

        // Calculate gutter width (for line numbers)
        let gutter_width = last_line.max(end_line).to_string().len();

        // Render each line
        for line_num in first_line..=last_line {
            if let Some(line) = source.get_line(line_num) {
                // Is this line part of the highlighted span?
                let in_span = line_num >= start_line && line_num <= end_line;

                // Line number gutter
                let gutter = format!("{:>width$}", line_num, width = gutter_width);

                // Separator: bold blue pipe for span lines
                let sep = if in_span {
                    " │ ".blue().bold().to_string()
                } else {
                    " │ ".blue().to_string()
                };

                // Write the line
                output.push_str(&format!("{}{}{}\n", gutter.blue(), sep, line.content));

                // Add underline only for single-line spans or first line of multi-line
                if in_span
                    && (start_line == end_line || line_num == start_line)
                    && let Some(underline) = Self::create_underline_simple(
                        start_col,
                        if start_line == end_line {
                            end_col
                        } else {
                            line.content.len() + 1
                        },
                        severity,
                        label,
                    )
                {
                    let blank_gutter = " ".repeat(gutter_width);
                    output.push_str(&format!("{} │ {}\n", blank_gutter.blue(), underline));
                }
            }
        }

        // For long spans, add ellipsis indicator
        if is_long_span {
            let blank_gutter = " ".repeat(gutter_width);
            let span_lines = end_line - start_line + 1;
            output.push_str(&format!(
                "{} {} {}\n",
                blank_gutter,
                "...".blue(),
                format!("({} more lines)", span_lines - 1).dimmed()
            ));
        }

        output
    }

    /// Create a simple underline without complex multi-line logic
    fn create_underline_simple(
        start_col: usize,
        end_col: usize,
        severity: Severity,
        label: Option<&str>,
    ) -> Option<String> {
        if start_col > end_col || start_col == 0 {
            return None;
        }

        let padding = " ".repeat(start_col.saturating_sub(1));
        let underline_len = end_col.saturating_sub(start_col).max(1);
        let underline = "^".repeat(underline_len);

        let colored_underline = Self::colorize_by_severity(&underline, severity);

        let full_underline = if let Some(label_text) = label {
            let colored_label = Self::colorize_by_severity(label_text, severity);
            format!("{}{} {}", padding, colored_underline, colored_label)
        } else {
            format!("{}{}", padding, colored_underline)
        };

        Some(full_underline)
    }

    /// Create an underline string for a specific line in the span
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn create_underline(
        line_num: usize,
        start_line: usize,
        start_col: usize,
        end_line: usize,
        end_col: usize,
        line_len: usize,
        severity: Severity,
        label: Option<&str>,
    ) -> Option<String> {
        // Calculate the column range for this line
        let (col_start, col_end) = if start_line == end_line {
            // Single line span
            (start_col, end_col)
        } else if line_num == start_line {
            // First line of multi-line span: from start_col to end of line
            (start_col, line_len + 1)
        } else if line_num == end_line {
            // Last line of multi-line span: from start to end_col
            (1, end_col)
        } else {
            // Middle line: entire line
            (1, line_len + 1)
        };

        // Ensure valid range
        if col_start > col_end || col_start == 0 {
            return None;
        }

        // Build the underline
        let padding = " ".repeat(col_start.saturating_sub(1));
        let underline_len = col_end.saturating_sub(col_start).max(1);

        // Use ^ for all underlines
        let underline = "^".repeat(underline_len);

        // Color based on severity
        let colored_underline = Self::colorize_by_severity(&underline, severity);

        // Add label if present
        let full_underline = if let Some(label_text) = label {
            let colored_label = Self::colorize_by_severity(label_text, severity);
            format!("{}{} {}", padding, colored_underline, colored_label)
        } else {
            format!("{}{}", padding, colored_underline)
        };

        Some(full_underline)
    }

    /// Apply severity-based coloring to text
    fn colorize_by_severity(text: &str, severity: Severity) -> String {
        match severity {
            Severity::Critical => text.red().bold().to_string(),
            Severity::Error => text.red().bold().to_string(),
            Severity::Warning => text.yellow().bold().to_string(),
            Severity::Info => text.blue().to_string(),
        }
    }

    /// Render a simple single-line span (convenience method)
    pub fn render_single_line(
        source: &SourceFile,
        line: usize,
        start_col: usize,
        end_col: usize,
        severity: Severity,
        context: usize,
        label: Option<&str>,
    ) -> String {
        Self::render(
            source, line, start_col, line, end_col, severity, context, label,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_test_source() -> SourceFile {
        let content = r#"fn main() {
    let x = 5;
    unsafe { ptr::read(x) }
    println!("done");
}"#;
        SourceFile::new(PathBuf::from("test.rs"), content.to_string())
    }

    #[test]
    fn test_single_line_span() {
        let source = create_test_source();
        let output = SpanRenderer::render(
            &source,
            3,
            5,
            3,
            27,
            Severity::Warning,
            1,
            Some("unsafe block here"),
        );

        // Should contain line numbers and the unsafe line
        assert!(output.contains("unsafe"));
        assert!(output.contains("2"));
        assert!(output.contains("3"));
        assert!(output.contains("4"));
    }

    #[test]
    fn test_multiline_span() {
        let source = SourceFile::new(
            PathBuf::from("test.rs"),
            "line1\nline2\nline3\nline4\nline5".to_string(),
        );

        let output = SpanRenderer::render(&source, 2, 1, 4, 5, Severity::Error, 0, None);

        // Should show lines 2-4
        assert!(output.contains("line2"));
        assert!(output.contains("line3"));
        assert!(output.contains("line4"));
    }

    #[test]
    fn test_context_lines() {
        let source = SourceFile::new(PathBuf::from("test.rs"), "a\nb\nc\nd\ne".to_string());

        let output = SpanRenderer::render(&source, 3, 1, 3, 1, Severity::Info, 1, None);

        // Should show lines 2, 3, 4 (context of 1)
        assert!(output.contains("b"));
        assert!(output.contains("c"));
        assert!(output.contains("d"));
    }
}
