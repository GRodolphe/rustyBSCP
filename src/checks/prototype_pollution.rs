//! Prototype pollution reconnaissance:
//! detect Object.prototype gadgets in client-side JS, server-side indicators.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for prototype pollution indicators…");

    let (client_f, server_f) = tokio::join!(check_client_side_pp(ctx), check_server_side_pp(ctx));

    let mut findings = Vec::new();
    findings.extend(client_f);
    findings.extend(server_f);
    findings
}

/// Scan inline JS for prototype pollution gadgets / sinks.
async fn check_client_side_pp(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let pages = ["/", "/product?productId=1"];
    for page in pages {
        let Ok(r) = ctx.client.get(ctx.url(page)).send().await else {
            continue;
        };
        let body = r.text().await.unwrap_or_default();

        let gadgets = [
            ("Object.assign(", "Object.assign — merges user-controlled keys into objects"),
            ("JSON.parse(", "JSON.parse — may merge untrusted JSON into object chain"),
            ("$.extend(true,", "jQuery deep extend — classic prototype pollution sink"),
            ("_.merge(", "lodash _.merge — known prototype pollution sink"),
            ("_.defaultsDeep(", "lodash _.defaultsDeep — known prototype pollution sink"),
        ];

        for (pattern, label) in gadgets {
            if body.contains(pattern) {
                let f = Finding::new(
                    Severity::Low,
                    "Prototype Pollution",
                    format!("{label} detected at {page} — audit for __proto__ / constructor.prototype injection"),
                );
                ctx.out.finding(&f);
                findings.push(f);
                break; // One report per page
            }
        }
    }
    findings
}

/// Server-side prototype pollution: JSON body with __proto__ key.
async fn check_server_side_pp(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Probe an API endpoint with a __proto__ key and check if it's reflected/causes error
    let payload = r#"{"__proto__": {"rbscp": "pp_probe"}, "username": "wiener"}"#;

    let endpoints = ["/login", "/my-account", "/api/user"];
    for endpoint in endpoints {
        let Ok(r) = ctx
            .client
            .post(ctx.url(endpoint))
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
        else {
            continue;
        };

        let body = r.text().await.unwrap_or_default();
        if body.contains("pp_probe") {
            let f = Finding::new(
                Severity::High,
                "Prototype Pollution",
                format!("Server-side prototype pollution: __proto__ key reflected at {endpoint}"),
            );
            ctx.out.finding(&f);
            findings.push(f);
            break;
        }
    }
    findings
}
