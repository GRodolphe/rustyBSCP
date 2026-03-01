//! General-purpose unauthenticated reconnaissance:
//! admin panels, robots.txt, application features, non-session cookies.

use std::sync::Arc;

use scraper::{Html, Selector};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Enumerating application features…");

    let (admin_f, robots_f, features_f, cookies_f) = tokio::join!(
        check_admin_panels(ctx),
        check_robots(ctx),
        check_app_features(ctx),
        check_non_session_cookies(ctx),
    );

    let mut out = Vec::new();
    out.extend(admin_f);
    out.extend(robots_f);
    out.extend(features_f);
    out.extend(cookies_f);
    out
}

async fn check_admin_panels(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = ["/admin", "/admin-panel", "/administrator", "/manage", "/dashboard"];

    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let f = Finding::new(
                    Severity::High,
                    "Access Control",
                    format!("Admin panel accessible at {path} (no auth required)"),
                );
                ctx.out.finding(&f);
                findings.push(f);
                // Only report the first accessible admin path
                break;
            }
            Err(e) if ctx.config.verbose => ctx.out.verbose(&format!("admin panel {path}: {e}")),
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

async fn check_robots(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    match ctx.client.get(ctx.url("/robots.txt")).send().await {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let f = Finding::new(Severity::Info, "Enumeration", "robots.txt found — may reveal hidden paths")
                .with_details(body.trim());
            ctx.out.finding(&f);
            findings.push(f);
        }
        Ok(_) => {
            if ctx.config.verbose {
                ctx.out.not_found("No robots.txt");
            }
        }
        Err(e) if ctx.config.verbose => ctx.out.verbose(&format!("robots.txt: {e}")),
        Err(_) => {}
    }
    findings
}

async fn check_app_features(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let resp = match ctx.client.get(ctx.url("/")).send().await {
        Ok(r) => r,
        Err(e) => {
            if ctx.config.verbose {
                ctx.out.verbose(&format!("home page fetch failed: {e}"));
            }
            return findings;
        }
    };

    let Ok(body) = resp.text().await else {
        return findings;
    };

    let doc = Html::parse_document(&body);

    // Registration
    if selector_matches(&doc, "a[href*='register'], a[href*='signup']") {
        let f = Finding::new(Severity::Info, "Enumeration", "User registration enabled");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Search functionality
    if selector_matches(&doc, "input[type='search'], input[name='search'], input[name='query']") {
        let f = Finding::new(Severity::Info, "Enumeration", "Search functionality detected (potential reflected XSS / SQLi)");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Comment functionality
    if selector_matches(&doc, "form[action*='comment'], textarea[name*='comment'], textarea[name*='body']") {
        let f = Finding::new(Severity::Medium, "Enumeration", "Comment functionality detected (potential stored XSS)");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Feedback
    if body.to_ascii_lowercase().contains("feedback") {
        let f = Finding::new(Severity::Info, "Enumeration", "Feedback form detected");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Newsletter / subscribe
    let body_lower = body.to_ascii_lowercase();
    if body_lower.contains("newsletter") || body_lower.contains("subscribe") {
        let f = Finding::new(Severity::Info, "Enumeration", "Newsletter / subscription feature detected");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Exploit server link
    if body_lower.contains("exploit-") && body_lower.contains("web-security-academy.net") {
        let f = Finding::new(Severity::Info, "Enumeration", "Exploit server reference detected in page source");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // WebSocket chat
    if body_lower.contains("livechat") || body_lower.contains("live-chat") || body_lower.contains("ws://") || body_lower.contains("wss://") {
        let f = Finding::new(Severity::Info, "Enumeration", "WebSocket / live-chat feature detected");
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Social login / OAuth hint
    if body_lower.contains("login with social") || body_lower.contains("sign in with") {
        let f = Finding::new(Severity::Info, "Enumeration", "Social / OAuth login option detected");
        ctx.out.finding(&f);
        findings.push(f);
    }

    findings
}

async fn check_non_session_cookies(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(resp) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };

    for hdr in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let Ok(val) = hdr.to_str() else { continue };
        // Skip standard session cookies
        if val.to_ascii_lowercase().contains("session") {
            continue;
        }
        let name = val.split('=').next().unwrap_or(val);
        let f = Finding::new(
            Severity::Info,
            "Cookies",
            format!("Non-session cookie set: {name} — check for insecure flags or tracking"),
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

fn selector_matches(doc: &Html, css: &str) -> bool {
    Selector::parse(css)
        .ok()
        .is_some_and(|sel| doc.select(&sel).next().is_some())
}
