use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;

mod checks;
mod config;
mod exploits;
mod output;
mod scanner;

use config::ScanConfig;
use output::Printer;

/// Web Security Academy Auto-Recon Tool (Rust)
///
/// A concurrent Rust rewrite of WSAAR with extended features:
/// custom headers/cookies, JSON output, parallel scanning.
#[derive(Parser, Debug)]
#[command(name = "rbscp", version, about)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Lab ID (32-char hex string from the lab URL)
    #[arg(short = 'i', long)]
    id: String,

    /// Username for authentication
    #[arg(short = 'u', long, default_value = "wiener")]
    username: String,

    /// Password for authentication
    #[arg(short = 'p', long, default_value = "peter")]
    password: String,

    /// Also try carlos:montoya as fallback credentials
    #[arg(long)]
    try_carlos: bool,

    /// Route traffic through Burp Suite proxy (127.0.0.1:8080)
    #[arg(short = 'b', long)]
    burp: bool,

    /// Custom proxy URL, e.g. <http://127.0.0.1:8080> (overrides --burp)
    #[arg(long)]
    proxy: Option<String>,

    /// Add a custom request header — format "Name: Value" (repeatable)
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Add a custom cookie — format "name=value" (repeatable)
    #[arg(short = 'C', long = "cookie", value_name = "COOKIE")]
    cookies: Vec<String>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Output all findings as JSON (suppresses human-readable output)
    #[arg(long)]
    json: bool,

    /// Show verbose output including failed/skipped checks
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Show debug-level output: HTTP response codes for probes, skipped endpoints, raw request details
    #[arg(short = 'd', long)]
    debug: bool,

    /// Disable ANSI colour output
    #[arg(long)]
    no_color: bool,

    /// Save output to a file (in addition to stdout)
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<String>,

    /// Run an exploit after the scan. Available: clte, wcache, xss
    #[arg(long, value_name = "TYPE")]
    exploit: Option<String>,

    /// Endpoint to access via the exploit (e.g. /admin for CL.TE smuggling).
    /// Omit to run in detection-only mode.
    #[arg(long, value_name = "PATH")]
    exploit_target: Option<String>,

    /// Save the full exploit response body to a file.
    #[arg(long, value_name = "FILE")]
    exploit_save: Option<String>,

    /// Injection vector for the exploit.
    /// Header format: "X-Forwarded-Host: evil.com"
    /// Param format:  "`utm_content`=\<script\>alert(1)\</script\>"
    #[arg(long, value_name = "INJECT")]
    exploit_inject: Option<String>,

    /// Exploit server base URL (e.g. <https://exploit-abc.exploit-server.net>).
    /// For web cache poisoning, auto-injects "X-Forwarded-Host: <hostname>"
    /// when no --exploit-inject is given; also verifies the server is reachable.
    #[arg(long, value_name = "URL")]
    exploit_server: Option<String>,

    /// Out-of-band (OOB) interaction URL for blind SSRF/XXE probing
    /// (e.g. <https://xyz.oastify.com> or a Burp Collaborator URL).
    /// When set, probes are sent to this URL instead of localhost.
    #[arg(long, value_name = "URL")]
    oob: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let printer = Arc::new(Printer::new(!args.no_color && !args.json, args.debug));

    if !args.json {
        printer.banner();
    }

    // Accept either a bare 32-char hex ID or a full lab URL; extract the ID either way.
    let bare_re = Regex::new(r"^[0-9a-f]{32}$").context("Failed to compile lab-id regex")?;
    let url_re = Regex::new(r"([0-9a-f]{32})\.web-security-academy\.net")
        .context("Failed to compile lab-url regex")?;
    let lab_id = if bare_re.is_match(&args.id) {
        args.id.clone()
    } else if let Some(cap) = url_re.captures(&args.id) {
        cap[1].to_string()
    } else {
        printer.error(
            "Lab ID must be a 32-character hex string or a full lab URL \
             (e.g. 0a1b2c3d… or https://0a1b2c3d….web-security-academy.net/)",
        );
        return Err(anyhow::anyhow!("Invalid lab ID"));
    };

    // Parse custom headers ("Name: Value")
    let mut custom_headers = Vec::new();
    for h in &args.headers {
        match h.split_once(": ") {
            Some((name, value)) => custom_headers.push((name.to_string(), value.to_string())),
            None => {
                printer.warn(&format!(
                    "Skipping malformed header (expected 'Name: Value'): {h}"
                ));
            }
        }
    }

    // Parse custom cookies ("name=value")
    let mut custom_cookies = Vec::new();
    for c in &args.cookies {
        match c.split_once('=') {
            Some((name, value)) => custom_cookies.push((name.to_string(), value.to_string())),
            None => {
                printer.warn(&format!(
                    "Skipping malformed cookie (expected 'name=value'): {c}"
                ));
            }
        }
    }

    // Resolve proxy
    let proxy_url =
        args.proxy.or_else(|| args.burp.then(|| "http://127.0.0.1:8080".to_string()));

    let config = Arc::new(ScanConfig {
        lab_id: lab_id.clone(),
        base_url: format!("https://{lab_id}.web-security-academy.net"),
        username: args.username,
        password: args.password,
        try_carlos: args.try_carlos,
        custom_headers,
        custom_cookies,
        proxy_url,
        timeout: Duration::from_secs(args.timeout),
        verbose: args.verbose,
        _json_output: args.json,
        output_file: args.output,
        oob_url: args.oob,
    });

    if !args.json {
        printer.info(&format!("Target : {}", config.base_url));
        printer.info(&format!("Timeout: {}s", args.timeout));
        if let Some(p) = &config.proxy_url {
            printer.info(&format!("Proxy  : {p}"));
        }
    }

    let mut findings =
        Box::pin(scanner::run(
            Arc::clone(&config),
            Arc::clone(&printer),
            args.exploit.as_deref(),
        ))
        .await?;

    findings.extend(
        run_exploit(
            args.exploit,
            args.exploit_target,
            args.exploit_inject,
            args.exploit_server,
            args.exploit_save,
            &config,
            &printer,
        )
        .await,
    );

    if args.json {
        let json = serde_json::to_string_pretty(&findings)?;
        std::io::Write::write_all(&mut std::io::stdout(), json.as_bytes())?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")?;
    } else {
        printer.summary(&findings);
    }

    // Optionally write findings to a file
    if let Some(path) = &config.output_file {
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(path, json)?;
        printer.info(&format!("Results saved to {path}"));
    }

    Ok(())
}

/// Run an optional exploit module and return its findings.
async fn run_exploit(
    exploit: Option<String>,
    target: Option<String>,
    inject: Option<String>,
    server: Option<String>,
    save_path: Option<String>,
    config: &Arc<ScanConfig>,
    out: &Arc<Printer>,
) -> Vec<output::Finding> {
    let Some(exploit_str) = exploit else {
        if target.is_some() {
            out.warn("--exploit-target has no effect without --exploit");
        }
        return Vec::new();
    };

    // xss recon (including OOB probes) runs entirely in the scan phase — no separate exploit step.
    if exploit_str.eq_ignore_ascii_case("xss") {
        return Vec::new();
    }

    // For wcache: derive X-Forwarded-Host from --exploit-server if no explicit inject given.
    let effective_inject = inject.or_else(|| {
        server.as_deref().and_then(|url| {
            server_hostname(url).map(|h| format!("X-Forwarded-Host: {h}"))
        })
    });

    let is_wcache = exploit_str == "wcache" || exploit_str == "cache";
    if is_wcache && effective_inject.is_none() {
        out.error(
            "--exploit wcache requires --exploit-inject or --exploit-server \
             (e.g. --exploit-server https://exploit-abc.exploit-server.net)",
        );
        return Vec::new();
    }

    out.section("Exploit");
    if let Some(exploit_type) =
        exploits::ExploitType::parse(&exploit_str, target, effective_inject, server, save_path)
    {
        Box::pin(exploits::run(Arc::clone(config), Arc::clone(out), exploit_type)).await
    } else {
        out.error(&format!(
            "Unknown exploit '{exploit_str}'. Available: {}",
            exploits::ExploitType::available(),
        ));
        Vec::new()
    }
}

/// Extract the bare hostname from a URL (`https://host/path` → `host`).
fn server_hostname(url: &str) -> Option<String> {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}
