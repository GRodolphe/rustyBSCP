//! Access control checks:
//! admin transcript, role/ID parameter manipulation, horizontal privilege escalation.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for access control vulnerabilities…");

    let (transcript_f, roleid_f, idor_f) = tokio::join!(
        check_transcript_ac(ctx),
        check_role_param(ctx),
        check_idor_user_id(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(transcript_f);
    findings.extend(roleid_f);
    findings.extend(idor_f);
    findings
}

/// viewTranscript.js indicates an admin transcript function (broken AC pattern).
async fn check_transcript_ac(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    match ctx.client.get(ctx.url("/resources/js/viewTranscript.js")).send().await {
        Ok(r) if r.status().is_success() => {
            let f = Finding::new(
                Severity::High,
                "Access Control",
                "viewTranscript.js is accessible — likely broken access control on transcript endpoint",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
        Ok(_) | Err(_) => {}
    }

    // Check /admin/delete (should require admin)
    match ctx.client.get(ctx.url("/admin/delete")).send().await {
        Ok(r) if r.status().is_success() => {
            let f = Finding::new(
                Severity::High,
                "Access Control",
                "Admin delete function accessible without authorization at /admin/delete",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
        Ok(_) | Err(_) => {}
    }
    findings
}

/// Check if role or admin parameter can be added to account update.
async fn check_role_param(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try adding roleid=1 or admin=true to account update
    let payloads: &[&[(&str, &str)]] = &[
        &[("username", "wiener"), ("roleid", "1")],
        &[("username", "wiener"), ("admin", "true")],
        &[("username", "wiener"), ("role", "admin")],
    ];

    for payload in payloads {
        let Ok(r) = ctx.client.post(ctx.url("/my-account/change-email")).form(payload).send().await else {
            continue;
        };
        let body = r.text().await.unwrap_or_default();
        if body.contains("admin") || body.contains("Administrator") {
            let f = Finding::new(
                Severity::High,
                "Access Control",
                "Privilege escalation via mass assignment — role parameter accepted in account update",
            )
            .with_details(format!("Payload: {payload:?}"));
            ctx.out.finding(&f);
            findings.push(f);
            break;
        }
    }
    findings
}

/// Check horizontal privilege escalation via userId / id parameter.
async fn check_idor_user_id(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let paths = [
        "/my-account?id=1",
        "/my-account?id=administrator",
        "/api/user?id=1",
        "/user?id=1",
    ];

    for path in paths {
        let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
            continue;
        };
        if r.status().is_success() {
            let body = r.text().await.unwrap_or_default();
            if body.contains("administrator") || body.contains("API key") || body.contains("apiKey") {
                let f = Finding::new(
                    Severity::High,
                    "Access Control / IDOR",
                    format!("IDOR: sensitive data accessible at {path}"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            } else if body.contains("email") || body.contains("username") {
                let f = Finding::new(
                    Severity::Medium,
                    "Access Control / IDOR",
                    format!("IDOR candidate: user profile accessible at {path} — check for data exposure"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
        }
    }
    findings
}
