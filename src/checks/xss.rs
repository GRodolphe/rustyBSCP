//! XSS reconnaissance:
//! 404 reflection, search reflection, tracking scripts, jQuery/Angular versions,
//! postMessage listeners, comment-based XSS.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for XSS vectors…");

    let (reflect_f, tracker_f, js_lib_f, postmsg_f, dom_f) = tokio::join!(
        check_404_reflection(ctx),
        check_search_reflection(ctx),
        check_js_libraries(ctx),
        check_post_message(ctx),
        check_dom_sinks(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(reflect_f);
    findings.extend(tracker_f);
    findings.extend(js_lib_f);
    findings.extend(postmsg_f);
    findings.extend(dom_f);
    findings
}

/// Check if the 404 page reflects the URL path (reflected XSS via path).
async fn check_404_reflection(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let probe = "rbscp-xss-probe-abc123";
    let Ok(r) = ctx.client.get(ctx.url(&format!("/{probe}"))).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();
    if body.contains(probe) {
        let f = Finding::new(
            Severity::Medium,
            "XSS",
            "404 page reflects URL path — potential reflected XSS",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Check if the search parameter is reflected without encoding.
async fn check_search_reflection(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let probe = "<rbscp-xss>";

    let endpoints: &[(&str, &str)] = &[
        ("/search", "search"),
        ("/search", "q"),
        ("/", "search"),
        ("/", "q"),
    ];

    for (path, param) in endpoints {
        let Ok(r) = ctx.client.get(ctx.url(path)).query(&[(*param, probe)]).send().await else {
            continue;
        };
        let body = r.text().await.unwrap_or_default();
        if body.contains(probe) {
            let f = Finding::new(
                Severity::High,
                "XSS",
                format!("Search parameter '{param}' reflects unencoded input at {path} — reflected XSS"),
            );
            ctx.out.finding(&f);
            findings.push(f);
            break;
        }
    }
    findings
}

/// Check for vulnerable/outdated jQuery and Angular versions.
async fn check_js_libraries(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    // jQuery version detection
    if let Ok(re) = regex::Regex::new(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js") {
        if let Some(cap) = re.captures(&body) {
            let version = cap.get(1).map_or("unknown", |m| m.as_str());
            // jQuery < 3.0 is vulnerable to multiple XSS issues
            let is_old = version.starts_with("1.") || version.starts_with("2.");
            if is_old {
                let f = Finding::new(
                    Severity::Medium,
                    "XSS",
                    format!("Outdated jQuery {version} — vulnerable to DOM XSS ($.parseHTML, location.hash)"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            } else {
                let f = Finding::new(
                    Severity::Info,
                    "XSS",
                    format!("jQuery {version} in use — check for DOM sink usage"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
        }
    }

    // Angular version detection
    if let Ok(re) = regex::Regex::new(r"angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js") {
        if let Some(cap) = re.captures(&body) {
            let version = cap.get(1).map_or("unknown", |m| m.as_str());
            let f = Finding::new(
                Severity::Medium,
                "XSS",
                format!("AngularJS {version} — sandbox escape XSS may apply in older versions"),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// Look for `addEventListener('message'` — potential postMessage XSS.
async fn check_post_message(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    if body.contains("addEventListener('message'") || body.contains("addEventListener(\"message\"") {
        let f = Finding::new(
            Severity::Medium,
            "XSS",
            "postMessage listener detected — potential DOM XSS via window.postMessage",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Check for dangerous DOM sinks in inline scripts.
async fn check_dom_sinks(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    let sinks = [
        ("document.write(", "document.write DOM sink"),
        ("innerHTML =", "innerHTML assignment DOM sink"),
        ("eval(", "eval() DOM sink"),
        ("location.hash", "location.hash DOM source"),
        ("document.URL", "document.URL DOM source"),
        ("document.referrer", "document.referrer DOM source"),
    ];

    let mut reported = false;
    for (pattern, label) in sinks {
        if body.contains(pattern) && !reported {
            let f = Finding::new(
                Severity::Low,
                "XSS",
                format!("{label} detected in page source — review for DOM XSS"),
            );
            ctx.out.finding(&f);
            findings.push(f);
            reported = true; // Report once per page to avoid noise
        }
    }
    findings
}
