//! `OAuth 2.0` / `OpenID` Connect reconnaissance:
//! social login detection, well-known endpoints, `redirect_uri` issues.

use std::sync::Arc;

use scraper::{Html, Selector};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for OAuth / SSO vulnerabilities…");

    let (paths_f, wellknown_f, login_f) = tokio::join!(
        check_oauth_paths(ctx),
        check_wellknown(ctx),
        check_social_login(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(paths_f);
    findings.extend(wellknown_f);
    findings.extend(login_f);
    findings
}

async fn check_oauth_paths(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = [
        "/auth",
        "/social-login",
        "/oauth-callback",
        "/oauth/callback",
        "/oauth/authorize",
        "/callback",
    ];

    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() || r.status().is_redirection() => {
                let f = Finding::new(
                    Severity::Medium,
                    "OAuth",
                    format!("OAuth-related endpoint found at {path}"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

async fn check_wellknown(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ];

    for path in paths {
        match ctx.client.get(ctx.url(path)).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                let f = Finding::new(
                    Severity::Medium,
                    "OAuth",
                    format!("OAuth/OIDC discovery endpoint exposed at {path}"),
                )
                .with_details(body.trim().chars().take(200).collect::<String>());
                ctx.out.finding(&f);
                findings.push(f);
            }
            Ok(_) | Err(_) => {}
        }
    }
    findings
}

async fn check_social_login(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/login")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    // Look for "Login with social media" or similar OAuth provider links
    if body.contains("Login with social media")
        || body.contains("Sign in with")
        || body.contains("social-login")
        || body.contains("oauth")
    {
        // Try to extract the OAuth provider domain from href attributes
        let doc = Html::parse_document(&body);
        let mut oauth_domain = None;
        let host_re = regex::Regex::new(r"https?://([^/]+)").ok();
        if let Ok(sel) = Selector::parse("a[href*='social'], a[href*='oauth'], a[href*='auth']") {
            for el in doc.select(&sel) {
                if let Some(href) = el.value().attr("href") {
                    if let Some(re) = &host_re {
                        if let Some(cap) = re.captures(href) {
                            oauth_domain = cap.get(1).map(|m| m.as_str().to_string());
                        }
                    }
                }
            }
        }

        let detail = oauth_domain
            .as_deref()
            .unwrap_or("unknown provider")
            .to_string();
        let f = Finding::new(
            Severity::Medium,
            "OAuth",
            "Social / OAuth login detected — check for flawed OAuth implementation",
        )
        .with_details(format!("OAuth server: {detail}"));
        ctx.out.finding(&f);
        findings.push(f);

        // Check for redirect_uri manipulation
        let f2 = Finding::new(
            Severity::Low,
            "OAuth",
            "Test redirect_uri parameter for open redirect / account takeover via OAuth flow",
        );
        ctx.out.finding(&f2);
        findings.push(f2);
    }
    findings
}
