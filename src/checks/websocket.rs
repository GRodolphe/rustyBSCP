//! WebSocket reconnaissance:
//! detect WS endpoints, live-chat URLs, and missing origin validation.

use std::sync::Arc;

use scraper::{Html, Selector};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for WebSocket endpoints…");

    let (html_f, upgrade_f) = tokio::join!(detect_ws_in_html(ctx), check_ws_upgrade(ctx));

    let mut findings = Vec::new();
    findings.extend(html_f);
    findings.extend(upgrade_f);
    findings
}

/// Look for WebSocket URLs (ws:// / wss://) in page source.
async fn detect_ws_in_html(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pages = ["/", "/chat", "/live-chat"];

    for page in pages {
        let Ok(r) = ctx.client.get(ctx.url(page)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let body = r.text().await.unwrap_or_default();
        let doc = Html::parse_document(&body);

        // Check for ws/wss URLs in scripts and data attributes
        if body.contains("wss://") || body.contains("ws://") {
            let f = Finding::new(
                Severity::Medium,
                "WebSocket",
                format!("WebSocket URL found in source at {page} — check for XSS via WebSocket messages"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }

        // Look for chat-related endpoints
        if let Ok(sel) = Selector::parse("script[src*='chat'], script[src*='socket']") {
            if doc.select(&sel).next().is_some() {
                let f = Finding::new(
                    Severity::Medium,
                    "WebSocket",
                    format!("Chat/socket script loaded at {page} — inspect for stored/reflected XSS via WS"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
        }
    }
    findings
}

/// Check /chat for WebSocket Upgrade capability.
async fn check_ws_upgrade(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Ok(r) = ctx
        .client
        .get(ctx.url("/chat"))
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
    else {
        return findings;
    };

    let status = r.status().as_u16();
    if status == 101 || status == 200 {
        let f = Finding::new(
            Severity::Medium,
            "WebSocket",
            format!("/chat accepts WebSocket upgrade (status {status}) — test for XSS, CSRF, and cross-origin WS"),
        );
        ctx.out.finding(&f);
        findings.push(f);
    } else if r.status().is_success() {
        let f = Finding::new(
            Severity::Info,
            "WebSocket",
            "/chat endpoint exists — probe for WebSocket support manually",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}
