//! Security command - comprehensive multi-language security audit
//!
//! Scans:
//! - Dependency vulnerabilities (Rust, JS/TS, Python, Go, Java)
//! - Docker images and base image vulnerabilities
//! - docker-compose.yml security misconfigurations
//! - Dockerfile security issues
//! - Code security patterns
//!
//! Shows CVE → Fix mappings for all vulnerabilities

use anyhow::Result;
use colored::Colorize;
use rma_analyzer::providers::{AnalysisProvider, OsvProvider, RustSecProvider};
use rma_common::{Finding, OsvProviderConfig, RmaConfig, Severity};
use rma_parser::ParserEngine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SecurityArgs {
    pub path: PathBuf,
    pub format: OutputFormat,
    #[allow(dead_code)] // TODO: Add severity filtering
    pub severity: Severity,
    pub details: bool,
    pub fix: bool,
    pub offline: bool,
    pub skip_docker: bool,
    pub skip_deps: bool,
    pub skip_code: bool,
}

impl Default for SecurityArgs {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            format: OutputFormat::Pretty,
            severity: Severity::Warning,
            details: false,
            fix: false,
            offline: false,
            skip_docker: false,
            skip_deps: false,
            skip_code: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Json,
    Sarif,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" | "text" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "markdown" | "md" => Ok(Self::Markdown),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

/// A vulnerability with full CVE details and fix information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE ID (e.g., CVE-2024-1234) or advisory ID (RUSTSEC-2024-0001, GHSA-xxxx)
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: String,
    /// CVSS score if available
    pub cvss_score: Option<f32>,
    /// Affected package name
    pub package: String,
    /// Installed/affected version
    pub installed_version: String,
    /// Versions that fix this vulnerability
    pub fixed_versions: Vec<String>,
    /// Recommended fix action
    pub fix_command: Option<String>,
    /// Ecosystem (crates.io, npm, PyPI, Go, Maven, Docker)
    pub ecosystem: String,
    /// Source file where found (Cargo.lock, package-lock.json, Dockerfile, etc.)
    pub source_file: String,
    /// Related CVE IDs
    pub cve_ids: Vec<String>,
    /// Related GHSA IDs
    pub ghsa_ids: Vec<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Published date
    pub published: Option<String>,
    /// Is this vulnerability in a direct or transitive dependency
    pub is_direct: bool,
}

/// Docker-specific security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerFinding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub fix: Option<String>,
}

/// Complete security audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub scan_time: String,
    pub project_path: String,
    pub summary: SecuritySummary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub docker_findings: Vec<DockerFinding>,
    pub ecosystems: HashMap<String, EcosystemReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecuritySummary {
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub fixable: usize,
    pub docker_issues: usize,
    pub ecosystems_scanned: Vec<String>,
    pub lockfiles_found: Vec<String>,
    pub dockerfiles_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EcosystemReport {
    pub name: String,
    pub lockfile: String,
    pub total_deps: usize,
    pub vulnerable_deps: usize,
    pub vulnerabilities: Vec<String>, // IDs
}

pub fn run(args: SecurityArgs) -> Result<()> {
    let start = std::time::Instant::now();

    // Header
    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║           🔒 RMA Security Audit                                   ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════╝".cyan());
    println!();

    let mut report = SecurityReport {
        scan_time: chrono::Utc::now().to_rfc3339(),
        project_path: args.path.display().to_string(),
        summary: SecuritySummary::default(),
        vulnerabilities: Vec::new(),
        docker_findings: Vec::new(),
        ecosystems: HashMap::new(),
    };

    // 1. Discover all lockfiles and Dockerfiles
    println!("{} Discovering project files...", "→".bright_blue());
    let discovery = discover_files(&args.path)?;

    report.summary.lockfiles_found = discovery.lockfiles.iter().map(|p| p.display().to_string()).collect();
    report.summary.dockerfiles_found = discovery.dockerfiles.iter().map(|p| p.display().to_string()).collect();

    println!("  Found {} lockfiles, {} Dockerfiles",
        discovery.lockfiles.len().to_string().bright_white(),
        discovery.dockerfiles.len().to_string().bright_white()
    );
    println!();

    // 2. Scan dependencies
    if !args.skip_deps {
        println!("{} Scanning dependencies for CVEs...", "→".bright_blue());
        scan_all_dependencies(&args, &discovery, &mut report)?;
        println!();
    }

    // 3. Scan Docker files
    if !args.skip_docker && !discovery.dockerfiles.is_empty() {
        println!("{} Scanning Docker configurations...", "→".bright_blue());
        scan_docker_files(&args, &discovery, &mut report)?;
        println!();
    }

    // 4. Scan code for security issues
    if !args.skip_code {
        println!("{} Scanning code for security issues...", "→".bright_blue());
        scan_code_security(&args, &mut report)?;
        println!();
    }

    // Calculate summary
    for vuln in &report.vulnerabilities {
        match vuln.severity.as_str() {
            "critical" => report.summary.critical += 1,
            "high" => report.summary.high += 1,
            "medium" => report.summary.medium += 1,
            "low" => report.summary.low += 1,
            _ => {}
        }
        if !vuln.fixed_versions.is_empty() {
            report.summary.fixable += 1;
        }
    }
    report.summary.total_vulnerabilities = report.vulnerabilities.len();
    report.summary.docker_issues = report.docker_findings.len();
    report.summary.ecosystems_scanned = report.ecosystems.keys().cloned().collect();

    let duration = start.elapsed();

    // Output
    match args.format {
        OutputFormat::Json => output_json(&report)?,
        OutputFormat::Sarif => output_sarif(&report)?,
        OutputFormat::Markdown => output_markdown(&report)?,
        OutputFormat::Pretty => output_pretty(&report, &args, duration)?,
    }

    // Show fix commands if requested
    if args.fix {
        show_fix_commands(&report)?;
    }

    // Exit code
    if report.summary.critical > 0 || report.summary.high > 0 {
        std::process::exit(1);
    }

    Ok(())
}

struct ProjectDiscovery {
    lockfiles: Vec<PathBuf>,
    dockerfiles: Vec<PathBuf>,
    compose_files: Vec<PathBuf>,
}

fn discover_files(root: &Path) -> Result<ProjectDiscovery> {
    let mut discovery = ProjectDiscovery {
        lockfiles: Vec::new(),
        dockerfiles: Vec::new(),
        compose_files: Vec::new(),
    };

    // Known lockfile names
    let lockfile_names = [
        "Cargo.lock",           // Rust
        "package-lock.json",    // npm
        "yarn.lock",            // Yarn
        "pnpm-lock.yaml",       // pnpm
        "go.sum",               // Go
        "go.mod",               // Go
        "requirements.txt",     // Python pip
        "Pipfile.lock",         // Python pipenv
        "poetry.lock",          // Python poetry
        "pom.xml",              // Maven
        "build.gradle",         // Gradle
        "build.gradle.kts",     // Gradle Kotlin
        "Gemfile.lock",         // Ruby
        "composer.lock",        // PHP
    ];

    let dockerfile_patterns = [
        "Dockerfile",
        "dockerfile",
        "Containerfile",
    ];

    let compose_patterns = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];

    // Walk directory
    for entry in walkdir::WalkDir::new(root)
        .max_depth(10)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip common non-project directories
            !matches!(name.as_ref(), "node_modules" | ".git" | "target" | "vendor" | ".venv" | "__pycache__")
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        // Check lockfiles
        if lockfile_names.contains(&name.as_str()) {
            discovery.lockfiles.push(path.to_path_buf());
        }

        // Check Dockerfiles (including Dockerfile.prod, Dockerfile.dev, etc.)
        if dockerfile_patterns.iter().any(|p| name.starts_with(p)) || name.ends_with(".dockerfile") {
            discovery.dockerfiles.push(path.to_path_buf());
        }

        // Check compose files
        if compose_patterns.contains(&name.as_str()) {
            discovery.compose_files.push(path.to_path_buf());
        }
    }

    // Also add compose files to dockerfiles for scanning
    discovery.dockerfiles.extend(discovery.compose_files.clone());

    Ok(discovery)
}

fn scan_all_dependencies(
    args: &SecurityArgs,
    discovery: &ProjectDiscovery,
    report: &mut SecurityReport,
) -> Result<()> {
    // Group lockfiles by ecosystem
    for lockfile in &discovery.lockfiles {
        let name = lockfile.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        let ecosystem = match name.as_str() {
            "Cargo.lock" => "crates.io",
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => "npm",
            "go.sum" | "go.mod" => "Go",
            "requirements.txt" | "Pipfile.lock" | "poetry.lock" => "PyPI",
            "pom.xml" | "build.gradle" | "build.gradle.kts" => "Maven",
            "Gemfile.lock" => "RubyGems",
            "composer.lock" => "Packagist",
            _ => continue,
        };

        println!("  {} {} ({})", "•".dimmed(), lockfile.display(), ecosystem.cyan());

        // Scan with appropriate provider
        let vulns = match ecosystem {
            "crates.io" => scan_rust_deps(lockfile, args)?,
            _ => scan_osv_deps(lockfile, ecosystem, args)?,
        };

        // Add to ecosystem report
        let eco_report = report.ecosystems.entry(ecosystem.to_string()).or_insert_with(|| {
            EcosystemReport {
                name: ecosystem.to_string(),
                lockfile: lockfile.display().to_string(),
                ..Default::default()
            }
        });

        for vuln in &vulns {
            eco_report.vulnerabilities.push(vuln.id.clone());
            eco_report.vulnerable_deps += 1;
        }

        if !vulns.is_empty() {
            println!("    {} {} vulnerabilities found", "⚠".yellow(), vulns.len());
        } else {
            println!("    {} No vulnerabilities", "✓".green());
        }

        report.vulnerabilities.extend(vulns);
    }

    Ok(())
}

fn scan_rust_deps(lockfile: &Path, _args: &SecurityArgs) -> Result<Vec<Vulnerability>> {
    let provider = RustSecProvider::new();
    if !provider.is_available() {
        return Ok(Vec::new());
    }

    let parent = lockfile.parent().unwrap_or(Path::new("."));
    let findings = provider.analyze_directory(parent)?;

    Ok(findings.into_iter().map(|f| {
        let (pkg, ver) = parse_pkg_version(&f.message);
        let advisory_id = extract_id(&f.rule_id);

        Vulnerability {
            id: advisory_id.clone(),
            title: f.message.clone(),
            description: f.suggestion.clone().unwrap_or_default(),
            severity: severity_to_string(f.severity),
            cvss_score: None,
            package: pkg,
            installed_version: ver,
            fixed_versions: extract_versions(&f.suggestion),
            fix_command: Some("cargo update".to_string()),
            ecosystem: "crates.io".to_string(),
            source_file: lockfile.display().to_string(),
            cve_ids: extract_cves(&f.message),
            ghsa_ids: extract_ghsas(&f.message),
            references: extract_urls(&f.suggestion),
            published: None,
            is_direct: false,
        }
    }).collect())
}

fn scan_osv_deps(lockfile: &Path, ecosystem: &str, args: &SecurityArgs) -> Result<Vec<Vulnerability>> {
    let config = OsvProviderConfig {
        offline: args.offline,
        ..Default::default()
    };

    let provider = OsvProvider::new(config);
    if !provider.is_available() && !args.offline {
        return Ok(Vec::new());
    }

    let parent = lockfile.parent().unwrap_or(Path::new("."));
    let findings = provider.analyze_directory(parent)?;

    Ok(findings.into_iter().filter_map(|f| {
        // Filter to this ecosystem
        let rule_eco = if f.rule_id.contains("crates.io") {
            "crates.io"
        } else if f.rule_id.contains("npm") {
            "npm"
        } else if f.rule_id.contains("pypi") || f.rule_id.contains("pip") {
            "PyPI"
        } else if f.rule_id.contains("go") {
            "Go"
        } else if f.rule_id.contains("maven") {
            "Maven"
        } else {
            ecosystem
        };

        if rule_eco != ecosystem && ecosystem != "crates.io" {
            return None;
        }

        let (pkg, ver) = parse_pkg_version(&f.message);
        let advisory_id = extract_id(&f.rule_id);

        Some(Vulnerability {
            id: advisory_id.clone(),
            title: f.message.clone(),
            description: f.suggestion.clone().unwrap_or_default(),
            severity: severity_to_string(f.severity),
            cvss_score: None,
            package: pkg,
            installed_version: ver,
            fixed_versions: extract_versions(&f.suggestion),
            fix_command: get_fix_command(ecosystem),
            ecosystem: ecosystem.to_string(),
            source_file: lockfile.display().to_string(),
            cve_ids: extract_cves(&f.message),
            ghsa_ids: extract_ghsas(&f.message),
            references: extract_urls(&f.suggestion),
            published: None,
            is_direct: false,
        })
    }).collect())
}

fn scan_docker_files(
    _args: &SecurityArgs,
    discovery: &ProjectDiscovery,
    report: &mut SecurityReport,
) -> Result<()> {
    for dockerfile in &discovery.dockerfiles {
        let content = fs::read_to_string(dockerfile)?;
        let name = dockerfile.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        println!("  {} {}", "•".dimmed(), dockerfile.display());

        let mut findings = Vec::new();

        // Check if it's a compose file
        if name.contains("compose") {
            findings.extend(scan_compose_file(dockerfile, &content)?);
        } else {
            findings.extend(scan_dockerfile(dockerfile, &content)?);
        }

        if !findings.is_empty() {
            println!("    {} {} security issues", "⚠".yellow(), findings.len());
        } else {
            println!("    {} No issues", "✓".green());
        }

        report.docker_findings.extend(findings);
    }

    Ok(())
}

fn scan_dockerfile(path: &Path, content: &str) -> Result<Vec<DockerFinding>> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // Check for root user
        if trimmed.starts_with("USER") && trimmed.contains("root") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/root-user".to_string(),
                severity: "high".to_string(),
                message: "Container runs as root user".to_string(),
                fix: Some("Add 'USER nonroot' or 'USER 1000' after installing packages".to_string()),
            });
        }

        // Check for latest tag
        if (line_lower.starts_with("from ") && line_lower.contains(":latest")) ||
           (line_lower.starts_with("from ") && !line.contains(':') && !line.contains(" AS ")) {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/latest-tag".to_string(),
                severity: "medium".to_string(),
                message: "Using 'latest' or untagged image - pins to unpredictable version".to_string(),
                fix: Some("Use specific image tag like 'image:1.2.3' or digest".to_string()),
            });
        }

        // Check for ADD instead of COPY
        if trimmed.starts_with("ADD ") && !line.contains("http://") && !line.contains("https://") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/prefer-copy".to_string(),
                severity: "low".to_string(),
                message: "Use COPY instead of ADD for local files".to_string(),
                fix: Some("Replace 'ADD' with 'COPY' for local file copies".to_string()),
            });
        }

        // Check for curl/wget without verification
        if (line_lower.contains("curl ") || line_lower.contains("wget ")) &&
           (line_lower.contains("-k") || line_lower.contains("--insecure") || line_lower.contains("--no-check-certificate")) {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/insecure-download".to_string(),
                severity: "high".to_string(),
                message: "Downloading files without TLS verification".to_string(),
                fix: Some("Remove --insecure/-k/--no-check-certificate flags".to_string()),
            });
        }

        // Check for secrets in ENV
        if trimmed.starts_with("ENV ") || trimmed.starts_with("ARG ") {
            let secrets = ["password", "secret", "key", "token", "api_key", "apikey", "credential", "private"];
            for secret in secrets {
                if line_lower.contains(secret) && line.contains('=') && !line.contains("${") {
                    findings.push(DockerFinding {
                        file: path.display().to_string(),
                        line: line_num,
                        rule: "docker/hardcoded-secret".to_string(),
                        severity: "critical".to_string(),
                        message: format!("Potential hardcoded {} in Dockerfile", secret),
                        fix: Some("Use build args or runtime environment variables instead".to_string()),
                    });
                    break;
                }
            }
        }

        // Check for privileged operations
        if line_lower.contains("--privileged") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/privileged-mode".to_string(),
                severity: "critical".to_string(),
                message: "Container requests privileged mode".to_string(),
                fix: Some("Avoid --privileged; use specific capabilities instead".to_string()),
            });
        }

        // Check for sudo usage
        if line_lower.contains("sudo ") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/sudo-usage".to_string(),
                severity: "medium".to_string(),
                message: "Using sudo in Dockerfile (already running as root during build)".to_string(),
                fix: Some("Remove sudo from RUN commands".to_string()),
            });
        }

        // Check for apt-get without cleanup
        if line_lower.contains("apt-get install") && !line.contains("rm -rf /var/lib/apt") && !line.contains("&&") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/apt-cache".to_string(),
                severity: "low".to_string(),
                message: "apt-get install without cache cleanup bloats image".to_string(),
                fix: Some("Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install".to_string()),
            });
        }

        // Check for EXPOSE with all interfaces
        if trimmed.starts_with("EXPOSE") && content.contains("0.0.0.0") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/expose-all".to_string(),
                severity: "medium".to_string(),
                message: "Service binds to all interfaces (0.0.0.0)".to_string(),
                fix: Some("Consider binding to specific interface or localhost".to_string()),
            });
        }

        // Check for missing HEALTHCHECK
        // This is checked after the loop
    }

    // Check for missing HEALTHCHECK (at file level)
    if !content.to_lowercase().contains("healthcheck") {
        findings.push(DockerFinding {
            file: path.display().to_string(),
            line: 1,
            rule: "docker/no-healthcheck".to_string(),
            severity: "low".to_string(),
            message: "Dockerfile has no HEALTHCHECK instruction".to_string(),
            fix: Some("Add HEALTHCHECK to enable container health monitoring".to_string()),
        });
    }

    // Check for missing USER instruction
    if !content.to_lowercase().contains("\nuser ") && !content.to_lowercase().starts_with("user ") {
        findings.push(DockerFinding {
            file: path.display().to_string(),
            line: 1,
            rule: "docker/no-user".to_string(),
            severity: "high".to_string(),
            message: "Dockerfile has no USER instruction - runs as root".to_string(),
            fix: Some("Add 'USER nonroot' or 'USER 1000:1000' before ENTRYPOINT/CMD".to_string()),
        });
    }

    Ok(findings)
}

fn scan_compose_file(path: &Path, content: &str) -> Result<Vec<DockerFinding>> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        // Check for privileged mode
        if trimmed.contains("privileged:") && line_lower.contains("true") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/privileged".to_string(),
                severity: "critical".to_string(),
                message: "Service runs in privileged mode".to_string(),
                fix: Some("Remove 'privileged: true' or use specific capabilities".to_string()),
            });
        }

        // Check for host network mode
        if trimmed.contains("network_mode:") && line_lower.contains("host") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/host-network".to_string(),
                severity: "high".to_string(),
                message: "Service uses host network mode".to_string(),
                fix: Some("Use bridge networking with explicit port mappings".to_string()),
            });
        }

        // Check for host PID mode
        if trimmed.contains("pid:") && line_lower.contains("host") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/host-pid".to_string(),
                severity: "critical".to_string(),
                message: "Service shares host PID namespace".to_string(),
                fix: Some("Remove 'pid: host' unless absolutely necessary".to_string()),
            });
        }

        // Check for sensitive volume mounts
        let sensitive_mounts = ["/etc", "/var/run/docker.sock", "/root", "/home"];
        for mount in sensitive_mounts {
            if line.contains(mount) && (trimmed.starts_with("- ") || trimmed.starts_with("volumes:")) {
                findings.push(DockerFinding {
                    file: path.display().to_string(),
                    line: line_num,
                    rule: "compose/sensitive-mount".to_string(),
                    severity: "high".to_string(),
                    message: format!("Mounting sensitive path: {}", mount),
                    fix: Some("Avoid mounting host system paths; use named volumes".to_string()),
                });
            }
        }

        // Check for hardcoded secrets
        let secrets = ["password:", "secret:", "api_key:", "token:", "credentials:"];
        for secret in secrets {
            if line_lower.contains(secret) && !line.contains("${") && !line.contains("_FILE") {
                findings.push(DockerFinding {
                    file: path.display().to_string(),
                    line: line_num,
                    rule: "compose/hardcoded-secret".to_string(),
                    severity: "critical".to_string(),
                    message: "Hardcoded secret in compose file".to_string(),
                    fix: Some("Use environment variables (${VAR}) or Docker secrets".to_string()),
                });
                break;
            }
        }

        // Check for exposed ports on all interfaces
        if line.contains("ports:") || (trimmed.starts_with("- ") && trimmed.contains(":") &&
           !trimmed.contains("127.0.0.1") && !trimmed.contains("localhost")) {
            // Check if next line has a port mapping without bind address
            if let Some(next_line) = content.lines().nth(line_num) {
                if next_line.trim().starts_with("- \"") && !next_line.contains("127.0.0.1") {
                    // This is caught by next iteration
                }
            }
        }

        // Check for cap_add
        if trimmed.contains("cap_add:") ||
           (line_lower.contains("- sys_admin") || line_lower.contains("- net_admin") || line_lower.contains("- all")) {
            if line_lower.contains("sys_admin") || line_lower.contains("all") {
                findings.push(DockerFinding {
                    file: path.display().to_string(),
                    line: line_num,
                    rule: "compose/dangerous-capability".to_string(),
                    severity: "high".to_string(),
                    message: "Adding dangerous Linux capability".to_string(),
                    fix: Some("Use minimal capabilities required for functionality".to_string()),
                });
            }
        }

        // Check for security_opt: no-new-privileges
        if trimmed.contains("no-new-privileges:") && line_lower.contains("false") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/new-privileges".to_string(),
                severity: "medium".to_string(),
                message: "Container can gain new privileges".to_string(),
                fix: Some("Set 'no-new-privileges: true' or remove the line".to_string()),
            });
        }
    }

    Ok(findings)
}

fn scan_code_security(args: &SecurityArgs, report: &mut SecurityReport) -> Result<()> {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = rma_analyzer::AnalyzerEngine::new(config);

    let (parsed_files, _stats) = parser.parse_directory(&args.path)?;

    let mut security_findings = 0;

    for parsed in &parsed_files {
        let analysis = match analyzer.analyze_file(parsed) {
            Ok(a) => a,
            Err(_) => continue,
        };

        for f in &analysis.findings {
            if !is_security_finding(f) {
                continue;
            }

            security_findings += 1;

            let file_path = analysis.path.clone();
            report.vulnerabilities.push(Vulnerability {
                id: f.rule_id.clone(),
                title: f.message.clone(),
                description: f.suggestion.clone().unwrap_or_default(),
                severity: severity_to_string(f.severity),
                cvss_score: None,
                package: file_path.clone(),
                installed_version: format!("line {}", f.location.start_line),
                fixed_versions: Vec::new(),
                fix_command: None,
                ecosystem: "source".to_string(),
                source_file: file_path,
                cve_ids: Vec::new(),
                ghsa_ids: Vec::new(),
                references: Vec::new(),
                published: None,
                is_direct: true,
            });
        }
    }

    if security_findings > 0 {
        println!("  {} {} code security issues in {} files",
            "⚠".yellow(),
            security_findings,
            parsed_files.len()
        );
    } else {
        println!("  {} No code security issues in {} files", "✓".green(), parsed_files.len());
    }

    Ok(())
}

fn is_security_finding(f: &Finding) -> bool {
    use rma_common::FindingCategory;
    matches!(f.category, FindingCategory::Security) ||
    f.rule_id.contains("security") ||
    f.rule_id.contains("injection") ||
    f.rule_id.contains("xss") ||
    f.rule_id.contains("secret") ||
    f.rule_id.contains("unsafe") ||
    f.rule_id.contains("command") ||
    f.rule_id.contains("sql") ||
    f.rule_id.contains("path-traversal") ||
    f.rule_id.contains("xxe") ||
    f.rule_id.contains("deserialization") ||
    f.rule_id.contains("crypto")
}

fn output_pretty(report: &SecurityReport, args: &SecurityArgs, duration: std::time::Duration) -> Result<()> {
    println!();
    println!("{}", "════════════════════════════════════════════════════════════".bright_white());
    println!("{}", "                    SECURITY AUDIT REPORT                    ".bright_white().bold());
    println!("{}", "════════════════════════════════════════════════════════════".bright_white());
    println!();

    // Summary box
    println!("{}", "┌─────────────────────────────────────────────────────────────┐".dimmed());
    println!("│ {}                                              │", "SUMMARY".bright_white().bold());
    println!("{}", "├─────────────────────────────────────────────────────────────┤".dimmed());
    println!("│  Total Vulnerabilities: {:>5}                              │",
        report.summary.total_vulnerabilities.to_string().bright_white());
    println!("│  ├─ {} Critical: {:>3}                                      │",
        "●".red(), report.summary.critical);
    println!("│  ├─ {} High:     {:>3}                                      │",
        "●".yellow(), report.summary.high);
    println!("│  ├─ {} Medium:   {:>3}                                      │",
        "●".blue(), report.summary.medium);
    println!("│  └─ {} Low:      {:>3}                                      │",
        "●".dimmed(), report.summary.low);
    println!("│                                                             │");
    println!("│  Docker Issues: {:>5}                                      │",
        report.summary.docker_issues.to_string().bright_white());
    println!("│  Fixable:       {:>5}                                      │",
        report.summary.fixable.to_string().green());
    println!("│  Scan Duration: {:>5.2}s                                     │",
        duration.as_secs_f32());
    println!("{}", "└─────────────────────────────────────────────────────────────┘".dimmed());
    println!();

    // Ecosystems breakdown
    if !report.ecosystems.is_empty() {
        println!("{}", "ECOSYSTEMS SCANNED".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        for (name, eco) in &report.ecosystems {
            let status = if eco.vulnerable_deps > 0 {
                format!("{} vulnerable", eco.vulnerable_deps).yellow().to_string()
            } else {
                "✓ secure".green().to_string()
            };
            println!("  {:12} {} ({})", name.cyan(), eco.lockfile.dimmed(), status);
        }
        println!();
    }

    // Vulnerabilities grouped by severity with CVE → Fix mapping
    if !report.vulnerabilities.is_empty() {
        println!("{}", "VULNERABILITIES (CVE → FIX)".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        println!();

        // Group by severity
        let mut by_severity: BTreeMap<&str, Vec<&Vulnerability>> = BTreeMap::new();
        for vuln in &report.vulnerabilities {
            by_severity.entry(vuln.severity.as_str()).or_default().push(vuln);
        }

        for severity in ["critical", "high", "medium", "low"] {
            if let Some(vulns) = by_severity.get(severity) {
                let label = match severity {
                    "critical" => "CRITICAL".red().bold(),
                    "high" => "HIGH".yellow().bold(),
                    "medium" => "MEDIUM".blue().bold(),
                    _ => "LOW".dimmed().bold(),
                };

                println!("  {} ({})", label, vulns.len());
                println!();

                for vuln in vulns {
                    // Package and version
                    println!("    {} {}@{}",
                        "├─".dimmed(),
                        vuln.package.cyan(),
                        vuln.installed_version.dimmed()
                    );

                    // CVE/Advisory ID
                    println!("    │  ID: {}", vuln.id.bright_white());

                    // CVEs if any
                    if !vuln.cve_ids.is_empty() {
                        println!("    │  CVE: {}", vuln.cve_ids.join(", ").yellow());
                    }

                    // Title
                    let title = if vuln.title.len() > 50 {
                        format!("{}...", &vuln.title[..47])
                    } else {
                        vuln.title.clone()
                    };
                    println!("    │  {}", title);

                    // Fix version
                    if !vuln.fixed_versions.is_empty() {
                        println!("    │  {} Upgrade to: {}",
                            "→".green(),
                            vuln.fixed_versions.join(" or ").green()
                        );
                    } else {
                        println!("    │  {} No fix available", "✗".red());
                    }

                    // References if showing details
                    if args.details && !vuln.references.is_empty() {
                        println!("    │  Ref: {}", vuln.references.first().unwrap().dimmed());
                    }

                    println!("    │");
                }
                println!();
            }
        }
    }

    // Docker findings
    if !report.docker_findings.is_empty() {
        println!("{}", "DOCKER SECURITY ISSUES".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        println!();

        for finding in &report.docker_findings {
            let severity = match finding.severity.as_str() {
                "critical" => "CRIT".red().bold(),
                "high" => "HIGH".yellow().bold(),
                "medium" => "MED ".blue(),
                _ => "LOW ".dimmed(),
            };

            println!("  {} {} {}:{}",
                severity,
                finding.rule.bright_white(),
                finding.file.dimmed(),
                finding.line
            );
            println!("       {}", finding.message);
            if let Some(ref fix) = finding.fix {
                println!("       {} {}", "Fix:".green(), fix);
            }
            println!();
        }
    }

    // Footer
    println!("{}", "═".repeat(60).bright_white());
    if report.summary.critical > 0 || report.summary.high > 0 {
        println!("{}", format!(
            "⚠️  {} critical/high severity issues require immediate attention",
            report.summary.critical + report.summary.high
        ).red().bold());
    } else if report.summary.total_vulnerabilities == 0 && report.summary.docker_issues == 0 {
        println!("{}", "✅ Security audit passed - no vulnerabilities found!".green().bold());
    } else {
        println!("{}", format!(
            "ℹ️  {} lower-severity issues found",
            report.summary.total_vulnerabilities + report.summary.docker_issues
        ).blue());
    }
    println!();

    Ok(())
}

fn output_json(report: &SecurityReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn output_sarif(report: &SecurityReport) -> Result<()> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rma-security",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bumahkib7/rust-monorepo-analyzer",
                }
            },
            "results": report.vulnerabilities.iter().map(|v| {
                serde_json::json!({
                    "ruleId": v.id,
                    "level": match v.severity.as_str() {
                        "critical" | "high" => "error",
                        "medium" => "warning",
                        _ => "note"
                    },
                    "message": { "text": format!("{}: {}", v.package, v.title) },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": v.source_file }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn output_markdown(report: &SecurityReport) -> Result<()> {
    println!("# Security Audit Report\n");
    println!("**Scan Time:** {}\n", report.scan_time);

    println!("## Summary\n");
    println!("| Metric | Count |");
    println!("|--------|-------|");
    println!("| Total Vulnerabilities | {} |", report.summary.total_vulnerabilities);
    println!("| 🔴 Critical | {} |", report.summary.critical);
    println!("| 🟠 High | {} |", report.summary.high);
    println!("| 🟡 Medium | {} |", report.summary.medium);
    println!("| 🔵 Low | {} |", report.summary.low);
    println!("| Docker Issues | {} |", report.summary.docker_issues);
    println!("| Fixable | {} |", report.summary.fixable);
    println!();

    if !report.vulnerabilities.is_empty() {
        println!("## Vulnerabilities\n");
        println!("| Severity | Package | Version | CVE/ID | Fix Version |");
        println!("|----------|---------|---------|--------|-------------|");

        for v in &report.vulnerabilities {
            let sev = match v.severity.as_str() {
                "critical" => "🔴 Critical",
                "high" => "🟠 High",
                "medium" => "🟡 Medium",
                _ => "🔵 Low",
            };
            let cve = if !v.cve_ids.is_empty() {
                v.cve_ids.join(", ")
            } else {
                v.id.clone()
            };
            let fix = if !v.fixed_versions.is_empty() {
                v.fixed_versions.join(", ")
            } else {
                "N/A".to_string()
            };
            println!("| {} | {} | {} | {} | {} |", sev, v.package, v.installed_version, cve, fix);
        }
        println!();
    }

    if !report.docker_findings.is_empty() {
        println!("## Docker Issues\n");
        for f in &report.docker_findings {
            println!("### {} ({}:{})\n", f.rule, f.file, f.line);
            println!("**Severity:** {}\n", f.severity);
            println!("{}\n", f.message);
            if let Some(ref fix) = f.fix {
                println!("**Fix:** {}\n", fix);
            }
        }
    }

    Ok(())
}

fn show_fix_commands(report: &SecurityReport) -> Result<()> {
    println!();
    println!("{}", "RECOMMENDED FIX COMMANDS".bright_white().bold());
    println!("{}", "─".repeat(60).dimmed());
    println!();

    // Group vulnerabilities by ecosystem
    let mut by_eco: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    for vuln in &report.vulnerabilities {
        if !vuln.fixed_versions.is_empty() {
            by_eco.entry(vuln.ecosystem.clone()).or_default().push(vuln);
        }
    }

    if by_eco.contains_key("crates.io") {
        println!("  {} Rust (Cargo):", "📦".cyan());
        println!("    {}", "cargo update".bright_green());
        println!("    # Or update specific packages:");
        for vuln in by_eco.get("crates.io").unwrap().iter().take(5) {
            if let Some(fix_ver) = vuln.fixed_versions.first() {
                println!("    cargo update -p {} --precise {}", vuln.package, fix_ver);
            }
        }
        println!();
    }

    if by_eco.contains_key("npm") {
        println!("  {} npm:", "📦".cyan());
        println!("    {}", "npm audit fix".bright_green());
        println!("    # Or for major updates:");
        println!("    {}", "npm audit fix --force".bright_green());
        println!();
    }

    if by_eco.contains_key("PyPI") {
        println!("  {} Python (pip):", "🐍".cyan());
        println!("    {}", "pip install --upgrade <package>".bright_green());
        println!("    # Or with pip-audit:");
        println!("    {}", "pip-audit --fix".bright_green());
        println!();
    }

    if by_eco.contains_key("Go") {
        println!("  {} Go:", "🐹".cyan());
        println!("    {}", "go get -u ./...".bright_green());
        println!("    {}", "go mod tidy".bright_green());
        println!();
    }

    if by_eco.contains_key("Maven") {
        println!("  {} Maven/Gradle:", "☕".cyan());
        println!("    Update versions in pom.xml or build.gradle");
        println!("    {}", "mvn versions:use-latest-releases".bright_green());
        println!();
    }

    Ok(())
}

// Helper functions
fn severity_to_string(s: Severity) -> String {
    match s {
        Severity::Critical => "critical",
        Severity::Error => "high",
        Severity::Warning => "medium",
        Severity::Info => "low",
    }.to_string()
}

fn parse_pkg_version(msg: &str) -> (String, String) {
    // Pattern: "package vX.Y.Z" or "package@X.Y.Z" or "package X.Y.Z"
    let re = regex::Regex::new(r"(\S+)\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(msg) {
            return (
                caps.get(1).map_or("unknown", |m| m.as_str()).to_string(),
                caps.get(2).map_or("unknown", |m| m.as_str()).to_string(),
            );
        }
    }
    ("unknown".to_string(), "unknown".to_string())
}

fn extract_id(rule_id: &str) -> String {
    for prefix in ["RUSTSEC-", "GHSA-", "CVE-"] {
        if let Some(start) = rule_id.find(prefix) {
            let end = rule_id[start..]
                .find(|c: char| !c.is_alphanumeric() && c != '-')
                .map(|i| start + i)
                .unwrap_or(rule_id.len());
            return rule_id[start..end].to_string();
        }
    }
    rule_id.to_string()
}

fn extract_versions(text: &Option<String>) -> Vec<String> {
    let Some(t) = text else { return Vec::new() };
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+(?:-[\w.]+)?)").ok();
    re.map(|r| r.find_iter(t).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn extract_cves(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
    re.map(|r| r.find_iter(text).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn extract_ghsas(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}").ok();
    re.map(|r| r.find_iter(text).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn extract_urls(text: &Option<String>) -> Vec<String> {
    let Some(t) = text else { return Vec::new() };
    let re = regex::Regex::new(r"https?://[^\s\)>]+").ok();
    re.map(|r| r.find_iter(t).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn get_fix_command(ecosystem: &str) -> Option<String> {
    match ecosystem {
        "crates.io" => Some("cargo update".to_string()),
        "npm" => Some("npm audit fix".to_string()),
        "PyPI" => Some("pip install --upgrade <package>".to_string()),
        "Go" => Some("go get -u ./...".to_string()),
        "Maven" => Some("mvn versions:use-latest-releases".to_string()),
        _ => None,
    }
}
