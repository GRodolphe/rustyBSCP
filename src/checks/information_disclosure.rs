//! Information disclosure checks:
//! exposed .git, TRACE method, phpinfo, error pages, source maps.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for information disclosure…");

    let (git_f, trace_f, php_f, error_f, srcmap_f) = tokio::join!(
        check_git_exposed(ctx),
        check_trace_method(ctx),
        check_phpinfo(ctx),
        check_error_pages(ctx),
        check_source_maps(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(git_f);
    findings.extend(trace_f);
    findings.extend(php_f);
    findings.extend(error_f);
    findings.extend(srcmap_f);
    findings
}

async fn check_git_exposed(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = ["/.git/HEAD", "/.git/config", "/.env", "/.svn/entries"];

    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                // Confirm it's actually a git HEAD file, not a 200 catch-all
                let is_real = path.contains(".git/HEAD") && body.contains("ref:")
                    || path.contains(".git/config") && body.contains("[core]")
                    || path.contains(".env") && body.contains('=')
                    || path.contains(".svn");
                if is_real {
                    let f = Finding::new(
                        Severity::High,
                        "Information Disclosure",
                        format!("Sensitive file exposed: {path}"),
                    )
                    .with_details(body.trim().lines().take(3).collect::<Vec<_>>().join(" | "));
                    ctx.out.finding(&f);
                    findings.push(f);
                }
            }
            Err(e) if ctx.config.verbose => ctx.out.verbose(&format!("git check {path}: {e}")),
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

async fn check_trace_method(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = ["/", "/admin"];
    for path in paths {
        let Ok(r) = ctx
            .client
            .request(
                reqwest::Method::from_bytes(b"TRACE").unwrap_or(reqwest::Method::GET),
                ctx.url(path),
            )
            .send()
            .await
        else {
            continue;
        };
        if r.status().is_success() {
            let body = r.text().await.unwrap_or_default();
            if body.to_ascii_lowercase().contains("trace") || body.contains("TRACE") {
                let f = Finding::new(
                    Severity::Medium,
                    "Information Disclosure",
                    format!("HTTP TRACE method enabled at {path} — potential XST attack"),
                );
                ctx.out.finding(&f);
                findings.push(f);
                break;
            }
        }
    }
    findings
}

async fn check_phpinfo(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = [
        "/cgi-bin/phpinfo.php",
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
    ];
    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                if body.contains("PHP Version") || body.contains("phpinfo()") {
                    let f = Finding::new(
                        Severity::High,
                        "Information Disclosure",
                        format!("PHP info page exposed at {path}"),
                    );
                    ctx.out.finding(&f);
                    findings.push(f);
                    break;
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

async fn check_error_pages(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Trigger a type-confusion error via malformed category parameter
    let Ok(r) = ctx
        .client
        .get(ctx.url("/filter"))
        .query(&[("category", "'")])
        .send()
        .await
    else {
        return findings;
    };

    if r.status().is_server_error() {
        let body = r.text().await.unwrap_or_default();
        if body.contains("stack trace")
            || body.contains("Exception")
            || body.contains("Traceback")
            || body.contains("Internal Server Error")
        {
            let f = Finding::new(
                Severity::Medium,
                "Information Disclosure",
                "Verbose error page — stack trace / exception details leaked",
            )
            .with_details(body.trim().lines().take(5).collect::<Vec<_>>().join(" | "));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

async fn check_source_maps(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = [
        "/resources/js/tracking.js.map",
        "/js/app.js.map",
        "/static/js/main.chunk.js.map",
    ];
    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let f = Finding::new(
                    Severity::Low,
                    "Information Disclosure",
                    format!("JavaScript source map exposed at {path}"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}
