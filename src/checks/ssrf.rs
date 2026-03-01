//! SSRF and XXE reconnaissance:
//! product stock endpoint, stockCheck.js, XXE via XML body.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for SSRF / XXE vectors…");

    let (ssrf_f, stock_js_f) = tokio::join!(check_ssrf_stock(ctx), check_stock_js(ctx));

    let mut findings = Vec::new();
    findings.extend(ssrf_f);
    findings.extend(stock_js_f);
    findings
}

/// POST /product/stock — classic SSRF via stockApi / productId parameters.
async fn check_ssrf_stock(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // First check the endpoint exists
    let Ok(r) = ctx
        .client
        .post(ctx.url("/product/stock"))
        .form(&[("productId", "1"), ("storeId", "1")])
        .send()
        .await
    else {
        return findings;
    };

    if r.status().is_success() || r.status().as_u16() == 400 {
        let f = Finding::new(
            Severity::Medium,
            "SSRF",
            "Product stock endpoint (/product/stock) accepts server-side requests — test for SSRF via stockApi / productId",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }

    // Also try with a stockApi parameter (older lab format)
    let Ok(r2) = ctx
        .client
        .post(ctx.url("/product/stock"))
        .form(&[("stockApi", "http://127.0.0.1/admin")])
        .send()
        .await
    else {
        return findings;
    };

    if r2.status().is_success() {
        let body = r2.text().await.unwrap_or_default();
        let sev = if body.contains("admin") || body.contains("users") {
            Severity::High
        } else {
            Severity::Medium
        };
        let f = Finding::new(
            sev,
            "SSRF",
            "stockApi parameter triggers SSRF — internal request returned non-error response",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// /resources/js/stockCheck.js indicates XML-based stock check (XXE / SSRF via XML body).
async fn check_stock_js(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    match ctx.client.get(ctx.url("/resources/js/stockCheck.js")).send().await {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let is_xml = body.contains("xml") || body.contains("XML") || body.contains("XMLHttpRequest");
            let sev = if is_xml { Severity::High } else { Severity::Medium };
            let f = Finding::new(
                sev,
                "SSRF / XXE",
                "stockCheck.js found — stock check uses JavaScript XHR, likely XML body → XXE or SSRF",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
        Ok(_) | Err(_) => {}
    }
    findings
}
