//! CORS misconfiguration checks:
//! trusted subdomains, wildcard origins, credentialed CORS.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking CORS configuration…");

    let (subdomain_f, header_f) = tokio::join!(check_cors_subdomain(ctx), check_cors_headers(ctx));

    let mut findings = Vec::new();
    findings.extend(subdomain_f);
    findings.extend(header_f);
    findings
}

/// The Python WSAAR tool checks whether stock.{id}.web-security-academy.net is reachable,
/// which suggests a trusted subdomain that could be used for CORS exploitation.
async fn check_cors_subdomain(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let subdomain = format!("https://stock.{}.web-security-academy.net", ctx.config.lab_id);

    // Send with Origin set to the stock subdomain to test reflection
    let origin_url = format!("https://stock.{}.web-security-academy.net", ctx.config.lab_id);
    let resp = ctx
        .client
        .get(ctx.url("/"))
        .header("Origin", &origin_url)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let acao = r
                .headers()
                .get("access-control-allow-origin")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let acac = r
                .headers()
                .get("access-control-allow-credentials")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("false");

            if acao == origin_url || acao == "*" {
                let sev = if acac.eq_ignore_ascii_case("true") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let f = Finding::new(
                    sev,
                    "CORS",
                    format!(
                        "CORS: server reflects Origin from stock subdomain \
                         (ACAO={acao}, ACAC={acac})"
                    ),
                )
                .with_details(&subdomain);
                ctx.out.finding(&f);
                findings.push(f);
            }

            // Check if the stock subdomain itself is reachable
            if let Ok(stock_resp) = ctx.client.get(&subdomain).send().await {
                if stock_resp.status().is_success() {
                    let f = Finding::new(
                        Severity::Medium,
                        "CORS",
                        format!("Stock subdomain is reachable: {subdomain} — potential CORS pivot"),
                    );
                    ctx.out.finding(&f);
                    findings.push(f);
                }
            }
        }
        Err(e) if ctx.config.verbose => {
            ctx.out.verbose(&format!("CORS subdomain check: {e}"));
        }
        Err(_) => {}
    }
    findings
}

/// Check common CORS misconfiguration patterns on the root endpoint.
async fn check_cors_headers(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Test null origin
    let test_origins = [
        "null",
        "https://evil.com",
        &format!("https://{}.web-security-academy.net.evil.com", ctx.config.lab_id),
    ];

    for origin in test_origins {
        let Ok(r) = ctx.client.get(ctx.url("/")).header("Origin", origin).send().await else {
            continue;
        };

        let acao = r
            .headers()
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let acac = r
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("false");

        if acao == origin || acao == "*" {
            let sev = if acac.eq_ignore_ascii_case("true") {
                Severity::High
            } else {
                Severity::Medium
            };
            let f = Finding::new(
                sev,
                "CORS",
                format!("CORS: arbitrary origin '{origin}' reflected (ACAC={acac})"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
