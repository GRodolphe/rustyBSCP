//! SQL injection reconnaissance:
//! category filter parameter, XML-based stock check, login form.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

/// Unauthenticated `SQLi` checks.
pub async fn run_pre_auth(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for SQL injection vectors (pre-auth)…");

    let (filter_f, xml_f) = tokio::join!(check_filter_sqli(ctx), check_xml_sqli(ctx));

    let mut findings = Vec::new();
    findings.extend(filter_f);
    findings.extend(xml_f);
    findings
}

/// Authenticated `SQLi` checks (run after login).
pub async fn run_post_auth(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for SQL injection vectors (post-auth)…");
    check_search_sqli(ctx).await
}

/// `/filter?category=` is the canonical `BSCP` `SQLi` lab endpoint.
async fn check_filter_sqli(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // First check whether the endpoint exists
    let Ok(base_resp) = ctx
        .client
        .get(ctx.url("/filter"))
        .query(&[("category", "Gifts")])
        .send()
        .await
    else {
        return findings;
    };

    if !base_resp.status().is_success() {
        return findings;
    }

    let base_body = base_resp.text().await.unwrap_or_default();

    // Inject a quote to look for SQL errors
    let Ok(err_resp) = ctx
        .client
        .get(ctx.url("/filter"))
        .query(&[("category", "'")])
        .send()
        .await
    else {
        return findings;
    };

    let is_sqli = err_resp.status().is_server_error()
        || {
            let err_body = err_resp.text().await.unwrap_or_default();
            err_body.contains("SQL") || err_body.contains("syntax") || err_body.contains("ORA-")
        };

    if is_sqli {
        let f = Finding::new(
            Severity::High,
            "SQL Injection",
            "SQL injection in /filter?category= — server errors on quote injection",
        );
        ctx.out.finding(&f);
        findings.push(f);
    } else {
        // Check for Boolean-based: TRUE vs FALSE
        let Ok(true_resp) = ctx
            .client
            .get(ctx.url("/filter"))
            .query(&[("category", "Gifts'+OR+1=1--")])
            .send()
            .await
        else {
            return findings;
        };
        let true_body = true_resp.text().await.unwrap_or_default();
        if true_body.len() > base_body.len() + 100 {
            let f = Finding::new(
                Severity::High,
                "SQL Injection",
                "Boolean-based SQL injection in /filter?category= — OR 1=1 returns more rows",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// XML-based `SQLi` via /product/stock (`stockCheck` uses XML body in some labs).
async fn check_xml_sqli(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1 UNION SELECT NULL--</productId>
  <storeId>1</storeId>
</stockCheck>"#;

    let Ok(r) = ctx
        .client
        .post(ctx.url("/product/stock"))
        .header("Content-Type", "application/xml")
        .body(xml_body)
        .send()
        .await
    else {
        return findings;
    };

    let is_error = r.status().is_server_error();
    let body = r.text().await.unwrap_or_default();
    if body.contains("NULL") || body.contains("UNION") || is_error {
        let f = Finding::new(
            Severity::High,
            "SQL Injection",
            "XML-based SQLi candidate in /product/stock — XML body is parsed server-side",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Search endpoint `SQLi` (post-auth, common in blog/product search).
async fn check_search_sqli(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let payloads = [("search", "'"), ("q", "'"), ("query", "'")];

    for (param, payload) in payloads {
        let Ok(r) = ctx
            .client
            .get(ctx.url("/search"))
            .query(&[(param, payload)])
            .send()
            .await
        else {
            continue;
        };
        let is_error = r.status().is_server_error();
        let body = r.text().await.unwrap_or_default();
        if body.contains("SQL") || body.contains("syntax") || is_error {
            let f = Finding::new(
                Severity::High,
                "SQL Injection",
                format!("SQLi candidate in search parameter '{param}'"),
            );
            ctx.out.finding(&f);
            findings.push(f);
            break;
        }
    }
    findings
}
