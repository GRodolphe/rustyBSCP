//! File upload reconnaissance:
//! detect upload endpoints, check for content-type bypass, webshell opportunities.

use std::sync::Arc;

use scraper::{Html, Selector};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for file upload vulnerabilities…");

    let (page_f, endpoint_f) = tokio::join!(detect_upload_forms(ctx), check_upload_endpoints(ctx));

    let mut findings = Vec::new();
    findings.extend(page_f);
    findings.extend(endpoint_f);
    findings
}

/// Parse account / main pages looking for file upload forms.
async fn detect_upload_forms(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pages = ["/my-account", "/profile", "/account", "/upload"];

    for page in pages {
        let Ok(r) = ctx.client.get(ctx.url(page)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let body = r.text().await.unwrap_or_default();
        let doc = Html::parse_document(&body);

        let Ok(sel) = Selector::parse("input[type='file']") else {
            continue;
        };
        if doc.select(&sel).next().is_some() {
            // Find the form action to determine upload destination
            let action = Selector::parse("form")
                .ok()
                .and_then(|fs| doc.select(&fs).next())
                .and_then(|el| el.value().attr("action"))
                .unwrap_or(page);

            let f = Finding::new(
                Severity::Medium,
                "File Upload",
                format!("File upload form at '{page}' (posts to '{action}') — test for unrestricted upload / webshell"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// Probe known upload API endpoints directly.
async fn check_upload_endpoints(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = [
        "/upload",
        "/api/upload",
        "/files/upload",
        "/my-account/avatar",
    ];

    for path in paths {
        let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
            continue;
        };
        // A 200 or 405 (method not allowed) both indicate the endpoint exists
        let status = r.status().as_u16();
        if r.status().is_success() || status == 405 || status == 415 {
            let f = Finding::new(
                Severity::Medium,
                "File Upload",
                format!("Upload endpoint exists at {path} (status {status}) — test for unrestricted file upload"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
