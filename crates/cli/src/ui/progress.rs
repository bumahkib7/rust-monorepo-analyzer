//! Progress bar utilities

use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

/// Create a spinner for indeterminate progress
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("Invalid template")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a progress bar for determinate progress
pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg}\n{wide_bar:.cyan/dim} {pos}/{len} ({percent}%)")
            .expect("Invalid template")
            .progress_chars("█▓▒░"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a progress bar for file processing
pub fn create_file_progress(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/dim} {pos}/{len} files ({per_sec})")
            .expect("Invalid template")
            .progress_chars("━━╸"),
    );
    pb
}

/// Progress tracker for multi-phase operations
pub struct ProgressTracker {
    multi: MultiProgress,
    phases: Vec<(String, ProgressBar)>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            multi: MultiProgress::new(),
            phases: Vec::new(),
        }
    }

    /// Add a new phase with indeterminate progress
    pub fn add_phase(&mut self, name: &str) -> &ProgressBar {
        let pb = self.multi.add(create_spinner(name));
        self.phases.push((name.to_string(), pb));
        &self.phases.last().unwrap().1
    }

    /// Add a new phase with determinate progress
    pub fn add_phase_with_total(&mut self, name: &str, total: u64) -> &ProgressBar {
        let pb = self.multi.add(create_progress_bar(total, name));
        self.phases.push((name.to_string(), pb));
        &self.phases.last().unwrap().1
    }

    /// Complete a phase successfully
    pub fn complete_phase(&self, index: usize, message: &str) {
        if let Some((_, pb)) = self.phases.get(index) {
            pb.finish_with_message(format!("{} {}", "✓".green(), message));
        }
    }

    /// Fail a phase
    pub fn fail_phase(&self, index: usize, message: &str) {
        if let Some((_, pb)) = self.phases.get(index) {
            pb.finish_with_message(format!("{} {}", "✗".red(), message));
        }
    }

    /// Get the multi-progress for custom operations
    pub fn multi(&self) -> &MultiProgress {
        &self.multi
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Print a phase header
pub fn print_phase(phase: &str, description: &str) {
    println!("\n{} {}", format!("[{}]", phase).cyan().bold(), description);
}

/// Print a phase completion
pub fn print_phase_complete(message: &str) {
    println!("  {} {}", "✓".green(), message);
}

/// Print a phase warning
pub fn print_phase_warning(message: &str) {
    println!("  {} {}", "⚠".yellow(), message);
}
