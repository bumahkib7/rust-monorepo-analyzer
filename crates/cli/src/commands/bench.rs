//! Benchmark command implementation

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::RmaConfig;
use rma_parser::ParserEngine;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct BenchArgs {
    pub path: PathBuf,
    pub iterations: usize,
}

pub fn run(args: BenchArgs) -> Result<()> {
    println!();
    println!("{}", "⏱  RMA Benchmark".cyan().bold());
    println!("{}", Theme::separator(60));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );
    println!(
        "  {} {}",
        "Iterations:".dimmed(),
        args.iterations.to_string().bright_white()
    );
    println!();

    let config = RmaConfig::default();

    // Warm up
    println!("{} Warming up...", Theme::info_mark());
    let parser = ParserEngine::new(config.clone());
    let _analyzer = AnalyzerEngine::new(config.clone());
    let _ = parser.parse_directory(&args.path)?;

    // Benchmark parsing
    println!("{} Benchmarking parse phase...", Theme::info_mark());
    let parse_times = benchmark_phase(args.iterations, || {
        let parser = ParserEngine::new(config.clone());
        parser.parse_directory(&args.path).map(|_| ())
    })?;

    // Benchmark analysis
    println!("{} Benchmarking analyze phase...", Theme::info_mark());
    let (parsed_files, _) = parser.parse_directory(&args.path)?;
    let analyze_times = benchmark_phase(args.iterations, || {
        let analyzer = AnalyzerEngine::new(config.clone());
        analyzer.analyze_files(&parsed_files).map(|_| ())
    })?;

    // Full pipeline
    println!("{} Benchmarking full pipeline...", Theme::info_mark());
    let full_times = benchmark_phase(args.iterations, || {
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config.clone());
        let (files, _) = parser.parse_directory(&args.path)?;
        analyzer.analyze_files(&files).map(|_| ())
    })?;

    println!();
    println!("{}", Theme::header("Results"));
    println!("{}", Theme::double_separator(60));
    println!();

    print_bench_results("Parse", &parse_times);
    print_bench_results("Analyze", &analyze_times);
    print_bench_results("Full Pipeline", &full_times);

    // Throughput
    let (files, _) = parser.parse_directory(&args.path)?;
    let total_lines: usize = files.iter().map(|f| f.content.lines().count()).sum();
    let avg_full_time = average(&full_times);

    println!();
    println!("{}", Theme::subheader("Throughput"));
    println!("{}", Theme::separator(40));
    println!(
        "  {} files/s",
        format!("{:.0}", files.len() as f64 / avg_full_time.as_secs_f64())
            .green()
            .bold()
    );
    println!(
        "  {} lines/s",
        format!("{:.0}", total_lines as f64 / avg_full_time.as_secs_f64())
            .green()
            .bold()
    );

    println!();

    Ok(())
}

fn benchmark_phase<F>(iterations: usize, f: F) -> Result<Vec<Duration>>
where
    F: Fn() -> Result<()>,
{
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        f()?;
        times.push(start.elapsed());
    }

    Ok(times)
}

fn print_bench_results(name: &str, times: &[Duration]) {
    let min = times.iter().min().copied().unwrap_or_default();
    let max = times.iter().max().copied().unwrap_or_default();
    let avg = average(times);
    let stddev = std_dev(times, avg);

    println!("  {}", name.cyan().bold());
    println!(
        "    min: {:>10.2}ms  max: {:>10.2}ms",
        min.as_secs_f64() * 1000.0,
        max.as_secs_f64() * 1000.0
    );
    println!(
        "    avg: {:>10.2}ms  stddev: {:>7.2}ms",
        avg.as_secs_f64() * 1000.0,
        stddev.as_secs_f64() * 1000.0
    );
    println!();
}

fn average(times: &[Duration]) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let sum: Duration = times.iter().sum();
    sum / times.len() as u32
}

fn std_dev(times: &[Duration], avg: Duration) -> Duration {
    if times.len() < 2 {
        return Duration::ZERO;
    }

    let avg_nanos = avg.as_nanos() as f64;
    let variance: f64 = times
        .iter()
        .map(|t| {
            let diff = t.as_nanos() as f64 - avg_nanos;
            diff * diff
        })
        .sum::<f64>()
        / (times.len() - 1) as f64;

    Duration::from_nanos(variance.sqrt() as u64)
}
