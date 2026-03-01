//! Web cache poisoning reconnaissance:
//! cache headers, known cacheable scripts, cache-key probing.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for web cache poisoning vectors…");

    let (headers_f, scripts_f, pragma_f, unkeyed_f) = tokio::join!(
        check_cache_headers(ctx),
        check_cacheable_scripts(ctx),
        check_pragma_cache_key(ctx),
        check_unkeyed_headers(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(headers_f);
    findings.extend(scripts_f);
    findings.extend(pragma_f);
    findings.extend(unkeyed_f);
    findings
}

async fn check_cache_headers(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };

    let headers = r.headers();
    let has_xcache = headers.contains_key("x-cache");
    let has_vary = headers.contains_key("vary");
    let cache_control = headers
        .get("cache-control")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if has_xcache || has_vary || !cache_control.is_empty() {
        let detail = format!(
            "X-Cache: {}, Vary: {}, Cache-Control: {}",
            headers.get("x-cache").and_then(|h| h.to_str().ok()).unwrap_or("absent"),
            headers.get("vary").and_then(|h| h.to_str().ok()).unwrap_or("absent"),
            if cache_control.is_empty() { "absent" } else { cache_control },
        );
        let f = Finding::new(
            Severity::Low,
            "Web Cache Poisoning",
            "Caching headers detected — application may be vulnerable to cache poisoning",
        )
        .with_details(&detail);
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

async fn check_cacheable_scripts(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scripts = [
        "/resources/js/tracking.js",
        "/js/geolocate.js",
        "/resources/js/analytics.js",
    ];

    for path in scripts {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let cached = r
                    .headers()
                    .get("x-cache")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown");
                let f = Finding::new(
                    Severity::Medium,
                    "Web Cache Poisoning",
                    format!("Cacheable script found at {path} (X-Cache: {cached}) — potential poisoning target"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

/// Check if the server exposes its cache key via the Pragma header trick.
async fn check_pragma_cache_key(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx
        .client
        .get(ctx.url("/"))
        .header("Pragma", "x-get-cache-key")
        .send()
        .await
    else {
        return findings;
    };

    if r.headers().contains_key("x-cache-key") {
        let key = r
            .headers()
            .get("x-cache-key")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("(present)");
        let f = Finding::new(
            Severity::High,
            "Web Cache Poisoning",
            "Server exposes cache key via X-Cache-Key header — cache key structure revealed",
        )
        .with_details(format!("X-Cache-Key: {key}"));
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Probe for unkeyed headers — injecting a custom header and checking if it appears in responses.
async fn check_unkeyed_headers(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let probe_headers = [
        ("X-Forwarded-Host", "poison.example.com"),
        ("X-Host", "poison.example.com"),
        ("X-Forwarded-Server", "poison.example.com"),
    ];

    for (header, value) in probe_headers {
        let Ok(r) = ctx.client.get(ctx.url("/")).header(header, value).send().await else {
            continue;
        };
        let body = r.text().await.unwrap_or_default();
        if body.contains(value) {
            let f = Finding::new(
                Severity::High,
                "Web Cache Poisoning",
                format!("Unkeyed header '{header}' is reflected in response body — cache poisoning likely"),
            )
            .with_details(format!("Injected value '{value}' appears in response"));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
