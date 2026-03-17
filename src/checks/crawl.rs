//! Endpoint discovery, AJAX detection, and security header analysis.
//!
//! Crawls pages in two phases (unauthenticated and authenticated) to build
//! a map of discovered endpoints and client-side fetch/XHR calls.

use std::collections::BTreeSet;
use std::sync::Arc;

use scraper::{Html, Selector};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

struct AjaxCall {
    pattern: &'static str,
    url: Option<String>,
    page: String,
}

/// Phase 1: crawl public pages for endpoints, AJAX calls, and security headers.
pub async fn run_unauthenticated(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Crawling public pages for endpoints and AJAX calls\u{2026}");
    let mut findings = Vec::new();
    let mut all_endpoints = BTreeSet::new();
    let mut all_ajax = Vec::new();

    let (home, login) = tokio::join!(fetch_page(ctx, "/"), fetch_page(ctx, "/login"),);

    if let Some((headers, body)) = home {
        findings.extend(check_security_headers(&headers, ctx));
        all_endpoints.extend(extract_endpoints(&body, &ctx.config.base_url));
        all_ajax.extend(extract_ajax_calls(&body, "/"));

        let product_paths = extract_product_paths(&body);
        let first_three: Vec<_> = product_paths.into_iter().take(3).collect();
        for path in &first_three {
            if let Some((_, pbody)) = fetch_page(ctx, path).await {
                all_endpoints.extend(extract_endpoints(&pbody, &ctx.config.base_url));
                all_ajax.extend(extract_ajax_calls(&pbody, path));
            }
        }
    }

    if let Some((_, body)) = login {
        all_endpoints.extend(extract_endpoints(&body, &ctx.config.base_url));
        all_ajax.extend(extract_ajax_calls(&body, "/login"));
    }

    print_endpoints(&all_endpoints, ctx);
    print_ajax_calls(&all_ajax, ctx);
    findings.extend(endpoints_to_findings(&all_endpoints, "unauthenticated"));
    findings.extend(ajax_to_findings(&all_ajax));
    findings
}

/// Phase 3: crawl authenticated pages for additional endpoints and AJAX calls.
pub async fn run_authenticated(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Crawling authenticated pages for endpoints and AJAX calls\u{2026}");
    let mut findings = Vec::new();
    let mut all_endpoints = BTreeSet::new();
    let mut all_ajax = Vec::new();

    let (account, admin) =
        tokio::join!(fetch_page(ctx, "/my-account"), fetch_page(ctx, "/admin"),);

    if let Some((_, body)) = account {
        all_endpoints.extend(extract_endpoints(&body, &ctx.config.base_url));
        all_ajax.extend(extract_ajax_calls(&body, "/my-account"));
    }

    if let Some((_, body)) = admin {
        all_endpoints.extend(extract_endpoints(&body, &ctx.config.base_url));
        all_ajax.extend(extract_ajax_calls(&body, "/admin"));
    }

    print_endpoints(&all_endpoints, ctx);
    print_ajax_calls(&all_ajax, ctx);
    findings.extend(endpoints_to_findings(&all_endpoints, "authenticated"));
    findings.extend(ajax_to_findings(&all_ajax));
    findings
}

async fn fetch_page(
    ctx: &Arc<ScanContext>,
    path: &str,
) -> Option<(reqwest::header::HeaderMap, String)> {
    match ctx.client.get(ctx.url(path)).send().await {
        Ok(r) if r.status().is_success() => {
            let headers = r.headers().clone();
            let body = r.text().await.unwrap_or_default();
            Some((headers, body))
        }
        Ok(r) => {
            ctx.out.debug(&format!("crawl {path}: HTTP {}", r.status()));
            None
        }
        Err(e) => {
            if ctx.config.verbose {
                ctx.out.verbose(&format!("crawl {path}: {e}"));
            }
            None
        }
    }
}

fn normalize_url(href: &str, base_url: &str) -> Option<String> {
    let trimmed = href.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("data:")
    {
        return None;
    }
    let no_fragment = trimmed.split('#').next().unwrap_or(trimmed);
    if no_fragment.starts_with("http://") || no_fragment.starts_with("https://") {
        if let Some(path) = no_fragment.strip_prefix(base_url) {
            if path.is_empty() {
                return Some("/".to_string());
            }
            return Some(path.to_string());
        }
        // External URL — keep full URL for visibility
        return Some(no_fragment.to_string());
    }
    if no_fragment.starts_with('/') {
        Some(no_fragment.to_string())
    } else {
        Some(format!("/{no_fragment}"))
    }
}

fn is_static_asset(url: &str) -> bool {
    let static_exts = [
        "png", "jpg", "jpeg", "gif", "svg", "css", "woff", "woff2", "ico",
    ];
    std::path::Path::new(url)
        .extension()
        .is_some_and(|ext| static_exts.iter().any(|e| ext.eq_ignore_ascii_case(e)))
}

fn extract_endpoints(body: &str, base_url: &str) -> BTreeSet<String> {
    let mut endpoints = BTreeSet::new();
    let doc = Html::parse_document(body);

    if let Ok(sel) = Selector::parse("a[href]") {
        for el in doc.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                if let Some(url) = normalize_url(href, base_url) {
                    endpoints.insert(url);
                }
            }
        }
    }

    if let Ok(sel) = Selector::parse("form[action]") {
        for el in doc.select(&sel) {
            if let Some(action) = el.value().attr("action") {
                if let Some(url) = normalize_url(action, base_url) {
                    endpoints.insert(url);
                }
            }
        }
    }

    if let Ok(sel) = Selector::parse("script[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                if let Some(url) = normalize_url(src, base_url) {
                    endpoints.insert(url);
                }
            }
        }
    }

    // Filter out static assets (images, css, fonts) to reduce noise
    endpoints
        .into_iter()
        .filter(|u| !is_static_asset(u))
        .collect()
}

fn extract_ajax_calls(body: &str, page: &str) -> Vec<AjaxCall> {
    let doc = Html::parse_document(body);
    let Ok(sel) = Selector::parse("script:not([src])") else {
        return Vec::new();
    };

    let script_text: String = doc
        .select(&sel)
        .flat_map(|el| el.text())
        .collect::<Vec<_>>()
        .join("\n");

    if script_text.is_empty() {
        return Vec::new();
    }

    // (regex_pattern, display_name, capture_group_for_url)
    let patterns: &[(&str, &str, usize)] = &[
        (r#"fetch\(\s*['"`]([^'"`]+)['"`]"#, "fetch", 1),
        (
            r#"\.open\(\s*['"](?:GET|POST|PUT|DELETE)['"],\s*['"]([^'"]+)['"]"#,
            "XMLHttpRequest",
            1,
        ),
        (
            r#"\$\.ajax\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]"#,
            "$.ajax",
            1,
        ),
        (r#"\$\.(get|post)\(\s*['"]([^'"]+)['"]"#, "$.get/$.post", 2),
        (r#"window\.open\(\s*['"`]([^'"`]+)['"`]"#, "window.open", 1),
    ];

    let mut calls = Vec::new();
    for &(pat, name, url_group) in patterns {
        let Ok(re) = regex::Regex::new(pat) else {
            continue;
        };
        for cap in re.captures_iter(&script_text) {
            let url = cap.get(url_group).map(|m| m.as_str().to_string());
            calls.push(AjaxCall {
                pattern: name,
                url,
                page: page.to_string(),
            });
        }
    }
    calls
}

fn extract_product_paths(body: &str) -> Vec<String> {
    let Ok(re) = regex::Regex::new(r"/product\?productId=\d+") else {
        return Vec::new();
    };
    let mut paths: Vec<String> = re
        .find_iter(body)
        .map(|m| m.as_str().to_string())
        .collect();
    paths.dedup();
    paths
}

fn check_security_headers(
    headers: &reqwest::header::HeaderMap,
    ctx: &Arc<ScanContext>,
) -> Vec<Finding> {
    let required = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
    ];

    let mut missing = Vec::new();
    for name in required {
        if let Some(val) = headers.get(name) {
            ctx.out
                .debug(&format!("{name}: {}", val.to_str().unwrap_or("(binary)")));
        } else {
            missing.push(name);
        }
    }

    if missing.is_empty() {
        return Vec::new();
    }

    let list = missing.join(", ");
    let f = Finding::new(
        Severity::Info,
        "Security Headers",
        format!("Missing security headers: {list}"),
    );
    ctx.out.finding(&f);
    vec![f]
}

fn print_endpoints(endpoints: &BTreeSet<String>, ctx: &Arc<ScanContext>) {
    if endpoints.is_empty() {
        return;
    }
    ctx.out
        .info(&format!("Discovered {} endpoint(s):", endpoints.len()));
    for ep in endpoints {
        ctx.out.info(&format!("  {ep}"));
    }
}

fn print_ajax_calls(calls: &[AjaxCall], ctx: &Arc<ScanContext>) {
    if calls.is_empty() {
        return;
    }
    ctx.out
        .info(&format!("Detected {} AJAX/fetch call(s):", calls.len()));
    for call in calls {
        let url_str = call.url.as_deref().unwrap_or("(dynamic)");
        ctx.out
            .info(&format!("  {} -> {} (on {})", call.pattern, url_str, call.page));
    }
}

fn endpoints_to_findings(endpoints: &BTreeSet<String>, phase: &str) -> Vec<Finding> {
    if endpoints.is_empty() {
        return Vec::new();
    }
    let list = endpoints
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    vec![Finding::new(
        Severity::Info,
        "Crawl",
        format!("Discovered {} endpoint(s) ({phase})", endpoints.len()),
    )
    .with_details(list)]
}

fn ajax_to_findings(calls: &[AjaxCall]) -> Vec<Finding> {
    calls
        .iter()
        .map(|call| {
            let url_str = call.url.as_deref().unwrap_or("(dynamic)");
            Finding::new(
                Severity::Info,
                "Crawl",
                format!("AJAX call: {} -> {} (on {})", call.pattern, url_str, call.page),
            )
        })
        .collect()
}
