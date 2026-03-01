use std::io::Write as _;

use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, category: &str, description: impl Into<String>) -> Self {
        Self {
            severity,
            category: category.to_string(),
            description: description.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

pub struct Printer {
    pub use_color: bool,
}

impl Printer {
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    fn writeln(line: &str) {
        let _ = writeln!(std::io::stdout(), "{line}");
    }

    fn writeln_err(line: &str) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }

    pub fn banner(&self) {
        let art = concat!(
            "\n",
            "  ██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗    ██████╗ ███████╗ ██████╗██████╗ \n",
            "  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝    ██╔══██╗██╔════╝██╔════╝██╔══██╗\n",
            "  ██████╔╝██║   ██║███████╗   ██║    ╚████╔╝     ██████╔╝███████╗██║     ██████╔╝\n",
            "  ██╔══██╗██║   ██║╚════██║   ██║     ╚██╔╝      ██╔══██╗╚════██║██║     ██╔═══╝ \n",
            "  ██║  ██║╚██████╔╝███████║   ██║      ██║       ██████╔╝███████║╚██████╗██║     \n",
            "  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝       ╚═════╝ ╚══════╝ ╚═════╝╚═╝     \n",
            "\n",
            "     Web Security Academy Auto-Recon  [Rust Edition]\n",
        );
        if self.use_color {
            Self::writeln(&art.cyan().to_string());
        } else {
            Self::writeln(art);
        }
    }

    pub fn section(&self, title: &str) {
        let sep = "─".repeat(60);
        if self.use_color {
            Self::writeln(&format!("\n{}", sep.bright_blue()));
            Self::writeln(&format!("  {}", title.bright_blue().bold()));
            Self::writeln(&sep.bright_blue().to_string());
        } else {
            Self::writeln(&format!("\n{sep}"));
            Self::writeln(&format!("  {title}"));
            Self::writeln(&sep);
        }
    }

    pub fn info(&self, msg: &str) {
        if self.use_color {
            Self::writeln(&format!("{} {msg}", "[*]".cyan()));
        } else {
            Self::writeln(&format!("[*] {msg}"));
        }
    }

    pub fn finding(&self, f: &Finding) {
        let sev = format!("[{}]", f.severity.as_str());
        let colored_sev = if self.use_color {
            match f.severity {
                Severity::High => sev.red().bold().to_string(),
                Severity::Medium => sev.yellow().bold().to_string(),
                Severity::Low => sev.cyan().bold().to_string(),
                Severity::Info => sev.green().bold().to_string(),
            }
        } else {
            sev
        };

        if self.use_color {
            Self::writeln(&format!(
                "{} {colored_sev} {} — {}",
                "[+]".green(),
                f.category.bright_white(),
                f.description
            ));
        } else {
            Self::writeln(&format!(
                "[+] {colored_sev} {} — {}",
                f.category, f.description
            ));
        }
        if let Some(details) = &f.details {
            if self.use_color {
                Self::writeln(&format!("    {}", details.dimmed()));
            } else {
                Self::writeln(&format!("    {details}"));
            }
        }
    }

    pub fn not_found(&self, msg: &str) {
        if self.use_color {
            Self::writeln(&format!("{} {}", "[-]".dimmed(), msg.dimmed()));
        } else {
            Self::writeln(&format!("[-] {msg}"));
        }
    }

    pub fn warn(&self, msg: &str) {
        if self.use_color {
            Self::writeln(&format!("{} {}", "[!]".yellow(), msg.yellow()));
        } else {
            Self::writeln(&format!("[!] {msg}"));
        }
    }

    pub fn error(&self, msg: &str) {
        if self.use_color {
            Self::writeln_err(&format!("{} {}", "[ERROR]".red().bold(), msg.red()));
        } else {
            Self::writeln_err(&format!("[ERROR] {msg}"));
        }
    }

    pub fn verbose(&self, msg: &str) {
        if self.use_color {
            Self::writeln(&format!("{} {}", "[~]".dimmed(), msg.dimmed()));
        } else {
            Self::writeln(&format!("[~] {msg}"));
        }
    }

    pub fn success(&self, msg: &str) {
        if self.use_color {
            Self::writeln(&format!("{} {}", "[✓]".green().bold(), msg.green()));
        } else {
            Self::writeln(&format!("[ok] {msg}"));
        }
    }

    pub fn summary(&self, findings: &[Finding]) {
        let sep = "─".repeat(60);
        if self.use_color {
            Self::writeln(&format!("\n{}", sep.bright_blue()));
            Self::writeln(&format!("  {}", "SCAN SUMMARY".bright_blue().bold()));
            Self::writeln(&sep.bright_blue().to_string());
        } else {
            Self::writeln(&format!("\n{sep}"));
            Self::writeln("  SCAN SUMMARY");
            Self::writeln(&sep);
        }

        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let info = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        if self.use_color {
            Self::writeln(&format!("  Total: {}", findings.len().to_string().bold()));
            Self::writeln(&format!("  {}  High", high.to_string().red().bold()));
            Self::writeln(&format!("  {}  Medium", medium.to_string().yellow().bold()));
            Self::writeln(&format!("  {}  Low", low.to_string().cyan().bold()));
            Self::writeln(&format!("  {}  Info", info.to_string().green().bold()));
        } else {
            Self::writeln(&format!("  Total: {}", findings.len()));
            Self::writeln(&format!("  {high}  High"));
            Self::writeln(&format!("  {medium}  Medium"));
            Self::writeln(&format!("  {low}  Low"));
            Self::writeln(&format!("  {info}  Info"));
        }

        if !findings.is_empty() {
            Self::writeln("\n  All findings:");
            for f in findings {
                let arrow = if self.use_color {
                    "→".green().to_string()
                } else {
                    "->".to_string()
                };
                let sev = if self.use_color {
                    match f.severity {
                        Severity::High => f.severity.as_str().red().bold().to_string(),
                        Severity::Medium => f.severity.as_str().yellow().bold().to_string(),
                        Severity::Low => f.severity.as_str().cyan().bold().to_string(),
                        Severity::Info => f.severity.as_str().green().to_string(),
                    }
                } else {
                    f.severity.as_str().to_string()
                };
                Self::writeln(&format!("  {arrow} [{sev}] {}", f.description));
            }
        }
    }
}
