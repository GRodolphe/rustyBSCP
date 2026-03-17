//! Deserialization reconnaissance:
//! detect serialized cookies, `ViewState`, Java serialization magic bytes.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out
        .info("Checking for insecure deserialization indicators…");
    check_serialized_session(ctx).await
}

async fn check_serialized_session(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };

    // Inspect Set-Cookie headers for serialized data patterns
    for hdr in r.headers().get_all(reqwest::header::SET_COOKIE) {
        let Ok(val) = hdr.to_str() else { continue };

        // PHP serialized object: O:n:"ClassName"
        if val.contains("O:") && val.contains('\"') {
            let f = Finding::new(
                Severity::High,
                "Deserialization",
                "PHP serialized object detected in cookie — test for insecure deserialization RCE",
            )
            .with_details(&val[..val.len().min(120)]);
            ctx.out.finding(&f);
            findings.push(f);
        }

        // Base64-encoded value that starts with Java serialization magic (rO0A = base64 of 0xaced0000)
        let cookie_value = val
            .split('=')
            .nth(1)
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");
        if cookie_value.starts_with("rO0A") {
            let f = Finding::new(
                Severity::High,
                "Deserialization",
                "Java serialized object (magic bytes 0xACED) detected in cookie — test for gadget chains",
            )
            .with_details(&cookie_value[..cookie_value.len().min(80)]);
            ctx.out.finding(&f);
            findings.push(f);
        }

        // .NET ViewState
        if val.contains("__VIEWSTATE") || val.starts_with("AAAA") {
            let f = Finding::new(
                Severity::Medium,
                "Deserialization",
                ".NET ViewState detected — check if MAC validation is enforced",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }

    // Check the page body for hidden ViewState / serialized inputs
    if let Ok(body) = r.text().await {
        if body.contains("__VIEWSTATE") {
            let f = Finding::new(
                Severity::Medium,
                "Deserialization",
                ".NET ViewState hidden field found — test with ysoserial.net if MAC key is weak",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }

        // Ruby marshalled data (starts with BAh)
        if body.contains("BAh") {
            let f = Finding::new(
                Severity::High,
                "Deserialization",
                "Possible Ruby Marshal data (BAh prefix) detected — check for deserialization gadgets",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }

    findings
}
