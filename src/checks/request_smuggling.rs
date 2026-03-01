//! HTTP request smuggling reconnaissance:
//! User-Agent reflection, analytics scripts, HTTP/2 downgrade hints.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for HTTP request smuggling indicators…");

    let (ua_f, analytics_f, te_f) = tokio::join!(
        check_ua_reflection(ctx),
        check_analytics_scripts(ctx),
        check_transfer_encoding(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(ua_f);
    findings.extend(analytics_f);
    findings.extend(te_f);
    findings
}

/// If the User-Agent is reflected in the response, it can be a smuggling gadget.
async fn check_ua_reflection(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let probe_ua = "rbscp-smuggling-ua-probe";

    let Ok(r) = ctx
        .client
        .get(ctx.url("/"))
        .header("User-Agent", probe_ua)
        .send()
        .await
    else {
        return findings;
    };

    let body = r.text().await.unwrap_or_default();
    if body.contains(probe_ua) {
        let f = Finding::new(
            Severity::Medium,
            "Request Smuggling",
            "User-Agent header is reflected in the response body — potential smuggling gadget for XSS/poisoning",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Presence of analytics / tracking scripts is a common indicator of HTTP/2 request smuggling labs.
async fn check_analytics_scripts(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scripts = [
        "/resources/js/analytics.js",
        "/resources/js/tracking.js",
        "/analytics",
    ];

    for path in scripts {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let f = Finding::new(
                    Severity::Low,
                    "Request Smuggling",
                    format!("Analytics/tracking script at {path} — common target for HTTP/2 request smuggling desync"),
                );
                ctx.out.finding(&f);
                findings.push(f);
                break;
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

/// Check if the server accepts chunked Transfer-Encoding (CL.TE indicator).
async fn check_transfer_encoding(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Send a request with both Content-Length and Transfer-Encoding headers.
    // If the server processes it without error, CL.TE smuggling may be possible.
    let body = "0\r\n\r\n";
    let Ok(r) = ctx
        .client
        .post(ctx.url("/"))
        .header("Transfer-Encoding", "chunked")
        .header("Content-Length", "5")
        .body(body)
        .send()
        .await
    else {
        return findings;
    };

    // 200 with conflicting headers suggests a potentially vulnerable front-end/back-end split
    if r.status().is_success() {
        let f = Finding::new(
            Severity::Low,
            "Request Smuggling",
            "Server accepted request with both Transfer-Encoding and Content-Length — investigate CL.TE smuggling",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}
