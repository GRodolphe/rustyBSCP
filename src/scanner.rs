use std::sync::Arc;

use anyhow::Result;
use reqwest::cookie::Jar;

use crate::{
    checks,
    config::ScanConfig,
    output::{Finding, Printer},
};

pub struct ScanContext {
    pub client: reqwest::Client,
    pub config: Arc<ScanConfig>,
    pub out: Arc<Printer>,
}

impl ScanContext {
    /// Build the full URL for a given path on the target lab.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url)
    }
}

pub async fn run(config: Arc<ScanConfig>, out: Arc<Printer>) -> Result<Vec<Finding>> {
    // Build the shared HTTP client with a cookie jar
    let jar = Arc::new(Jar::default());
    let mut builder = reqwest::Client::builder()
        .cookie_provider(Arc::clone(&jar))
        .timeout(config.timeout)
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        )
        // Follow redirects but cap them
        .redirect(reqwest::redirect::Policy::limited(10));

    if let Some(proxy_url) = &config.proxy_url {
        builder = builder
            .proxy(reqwest::Proxy::all(proxy_url)?)
            // Accept Burp's self-signed cert
            .danger_accept_invalid_certs(true);
    }

    // Inject any user-supplied default headers
    if !config.custom_headers.is_empty() {
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in &config.custom_headers {
            let n = reqwest::header::HeaderName::from_bytes(name.as_bytes())?;
            let v = reqwest::header::HeaderValue::from_str(value)?;
            map.insert(n, v);
        }
        builder = builder.default_headers(map);
    }

    let client = builder.build()?;

    // Inject any user-supplied cookies into the jar
    if !config.custom_cookies.is_empty() {
        let url = config.base_url.parse()?;
        for (name, value) in &config.custom_cookies {
            jar.add_cookie_str(&format!("{name}={value}"), &url);
        }
    }

    let ctx = Arc::new(ScanContext {
        client,
        config: Arc::clone(&config),
        out: Arc::clone(&out),
    });

    // Verify the lab is reachable before spending time on checks
    out.info("Verifying lab accessibility…");
    match ctx.client.get(ctx.url("/")).send().await {
        Ok(r) if r.status().is_success() || r.status().is_redirection() => {
            out.success("Lab is reachable");
        }
        Ok(r) => {
            out.warn(&format!("Lab returned HTTP {}", r.status()));
        }
        Err(e) => {
            out.error(&format!("Cannot reach lab: {e}"));
            return Err(anyhow::anyhow!("Lab unreachable — aborting scan"));
        }
    }

    let mut all: Vec<Finding> = Vec::new();

    out.section("Phase 1 — Unauthenticated Reconnaissance");
    all.extend(phase1_unauthenticated(&ctx).await);

    // Git dump runs after phase 1 (which detects the exposure) but before login.
    // Box::pin keeps the future off the stack — git_dump makes many await calls.
    out.section("Phase 1b — Git Repository Dump");
    all.extend(Box::pin(checks::git_dump::run(&ctx)).await);

    out.section("Phase 2 — Authentication");
    all.extend(phase2_login(&ctx).await);

    out.section("Phase 3 — Authenticated Reconnaissance");
    all.extend(Box::pin(phase3_authenticated(&ctx)).await);

    // ── Print findings block ──────────────────────────────────────────────
    if all.is_empty() {
        out.info("No findings recorded");
    } else {
        out.section("Findings");
        for f in &all {
            out.finding(f);
        }
    }

    Ok(all)
}

/// Phase 1: unauthenticated, fully parallel checks.
async fn phase1_unauthenticated(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let (enum_f, info_f, cors_f, cache_f, ssrf_f, sqli_pre_f) = tokio::join!(
        checks::enumeration::run(ctx),
        checks::information_disclosure::run(ctx),
        checks::cors::run(ctx),
        checks::web_cache::run(ctx),
        checks::ssrf::run(ctx),
        checks::sqli::run_pre_auth(ctx),
    );
    let mut findings = Vec::new();
    findings.extend(enum_f);
    findings.extend(info_f);
    findings.extend(cors_f);
    findings.extend(cache_f);
    findings.extend(ssrf_f);
    findings.extend(sqli_pre_f);
    findings
}

/// Phase 2: authentication — must run sequentially before authenticated checks.
async fn phase2_login(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    checks::login::run(ctx).await
}

/// Phase 3: authenticated checks, fully parallel.
async fn phase3_authenticated(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let (
        access_f,
        oauth_f,
        lfi_f,
        upload_f,
        sqli_post_f,
        xss_f,
        smuggling_f,
        ws_f,
        pp_f,
        deser_f,
        bl_f,
    ) = tokio::join!(
        checks::access_control::run(ctx),
        checks::oauth::run(ctx),
        checks::lfi::run(ctx),
        checks::upload::run(ctx),
        checks::sqli::run_post_auth(ctx),
        checks::xss::run(ctx),
        checks::request_smuggling::run(ctx),
        checks::websocket::run(ctx),
        checks::prototype_pollution::run(ctx),
        checks::deserialization::run(ctx),
        checks::business_logic::run(ctx),
    );
    let mut findings = Vec::new();
    findings.extend(access_f);
    findings.extend(oauth_f);
    findings.extend(lfi_f);
    findings.extend(upload_f);
    findings.extend(sqli_post_f);
    findings.extend(xss_f);
    findings.extend(smuggling_f);
    findings.extend(ws_f);
    findings.extend(pp_f);
    findings.extend(deser_f);
    findings.extend(bl_f);
    findings
}
