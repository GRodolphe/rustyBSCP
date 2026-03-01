//! Web cache poisoning reconnaissance:
//! cache infrastructure detection, MISS→HIT confirmation, unkeyed header/
//! parameter probing, parameter cloaking, geolocate.js cloaking,
//! fat GET body-param override, cacheable script enumeration.

use std::{fmt::Write as _, sync::Arc};

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

/// Unique canary value used in all probe requests to avoid false positives.
const PROBE: &str = "rbscptest9x";

/// JS paths that are commonly cached and used as poisoning targets in BSCP labs.
const CACHED_SCRIPTS: &[&str] = &[
    "/resources/js/tracking.js",
    "/resources/js/analytics.js",
    "/resources/js/geolocate.js",
    "/js/geolocate.js",
    "/resources/labheader/js/labHeader.js",
    "/resources/js/productFilter.js",
];

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for web cache poisoning vectors…");

    let (headers_f, confirm_f, scripts_f, pragma_f, unkeyed_hdr_f, unkeyed_param_f) =
        tokio::join!(
            check_cache_headers(ctx),
            check_cache_confirmation(ctx),
            check_cacheable_scripts(ctx),
            check_pragma_cache_key(ctx),
            check_unkeyed_headers(ctx),
            check_unkeyed_params(ctx),
        );

    let (param_key_f, geolocate_cloak_f, fat_get_f) = tokio::join!(
        check_unkeyed_param_cache_key(ctx),
        check_param_cloaking_geolocate(ctx),
        check_fat_get(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(headers_f);
    findings.extend(confirm_f);
    findings.extend(scripts_f);
    findings.extend(pragma_f);
    findings.extend(unkeyed_hdr_f);
    findings.extend(unkeyed_param_f);
    findings.extend(param_key_f);
    findings.extend(geolocate_cloak_f);
    findings.extend(fat_get_f);
    findings
}

/// Detect caching infrastructure via response headers.
async fn check_cache_headers(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };

    let headers = r.headers();
    let x_cache = headers.get("x-cache").and_then(|h| h.to_str().ok()).unwrap_or("absent");
    let vary = headers.get("vary").and_then(|h| h.to_str().ok()).unwrap_or("absent");
    let cache_control =
        headers.get("cache-control").and_then(|h| h.to_str().ok()).unwrap_or("absent");
    let age = headers.get("age").and_then(|h| h.to_str().ok());
    let cf_cache = headers.get("cf-cache-status").and_then(|h| h.to_str().ok());

    let caching_present = headers.contains_key("x-cache")
        || headers.contains_key("cf-cache-status")
        || headers.contains_key("age")
        || headers.contains_key("vary");

    if caching_present {
        let mut detail = format!(
            "X-Cache: {x_cache}, Vary: {vary}, Cache-Control: {cache_control}"
        );
        if let Some(a) = age {
            let _ = write!(detail, ", Age: {a}");
        }
        if let Some(cf) = cf_cache {
            let _ = write!(detail, ", CF-Cache-Status: {cf}");
        }
        let f = Finding::new(
            Severity::Low,
            "Web Cache Poisoning",
            "Caching infrastructure detected — application may be vulnerable to cache poisoning",
        )
        .with_details(detail);
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Confirm active caching by making the same request twice and checking for MISS→HIT.
async fn check_cache_confirmation(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Ok(r1) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let first_cache = r1
        .headers()
        .get("x-cache")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let Ok(r2) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let second_cache = r2
        .headers()
        .get("x-cache")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if first_cache.contains("miss") && second_cache.contains("hit") {
        let f = Finding::new(
            Severity::Medium,
            "Web Cache Poisoning",
            "Cache confirmed active: first request MISS, second HIT — cache poisoning viable",
        )
        .with_details(format!("Request 1 X-Cache: {first_cache}, Request 2: {second_cache}"));
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Enumerate cacheable script paths; a hit means these are prime poisoning targets.
async fn check_cacheable_scripts(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in CACHED_SCRIPTS {
        let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let cached =
            r.headers().get("x-cache").and_then(|h| h.to_str().ok()).unwrap_or("unknown");
        let f = Finding::new(
            Severity::Medium,
            "Web Cache Poisoning",
            format!("Cached script at {path} (X-Cache: {cached}) — prime poisoning target"),
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Check if the server reveals its cache key via Pragma: x-get-cache-key.
async fn check_pragma_cache_key(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx
        .client
        .get(ctx.url("/"))
        .header("Pragma", "x-get-cache-key")
        .send()
        .await
    else {
        return findings;
    };

    if let Some(key) = r.headers().get("x-cache-key").and_then(|h| h.to_str().ok()) {
        let f = Finding::new(
            Severity::High,
            "Web Cache Poisoning",
            "Server exposes cache key via X-Cache-Key — cache key structure is visible",
        )
        .with_details(format!("X-Cache-Key: {key}"));
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Probe unkeyed request headers on both the homepage and cached script paths.
///
/// Injects a canary hostname via each header and checks whether it appears in
/// the response body (indicating the header is unkeyed and reflected).
async fn check_unkeyed_headers(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let headers = [
        ("X-Forwarded-Host", PROBE),
        ("X-Host", PROBE),
        ("X-Forwarded-Server", PROBE),
        // X-Forwarded-Scheme: http forces a redirect on some CDN configs
        ("X-Forwarded-Scheme", "http"),
    ];

    // Probe both the homepage and the most common cacheable script
    let paths = ["/", "/resources/js/tracking.js", "/resources/js/geolocate.js"];

    for path in paths {
        for (header, value) in headers {
            let Ok(r) =
                ctx.client.get(ctx.url(path)).header(header, value).send().await
            else {
                continue;
            };

            // X-Forwarded-Scheme: redirect to http is a poisoning signal
            if header == "X-Forwarded-Scheme" {
                if let Some(loc) = r.headers().get("location").and_then(|h| h.to_str().ok()) {
                    if loc.starts_with("http://") {
                        let f = Finding::new(
                            Severity::High,
                            "Web Cache Poisoning",
                            format!("X-Forwarded-Scheme causes http redirect on {path} — cache-poisonable redirect"),
                        )
                        .with_details(format!("Location: {loc}"));
                        ctx.out.finding(&f);
                        findings.push(f);
                    }
                }
                continue;
            }

            let body = r.text().await.unwrap_or_default();
            if body.contains(value) {
                let f = Finding::new(
                    Severity::High,
                    "Web Cache Poisoning",
                    format!("Unkeyed header '{header}' reflected in {path} — cache poisoning confirmed"),
                )
                .with_details(format!("Injected '{value}' appears in response body"));
                ctx.out.finding(&f);
                findings.push(f);
            }
        }
    }
    findings
}

/// Probe unkeyed query parameters and parameter cloaking patterns.
///
/// Checks `utm_content` (commonly unkeyed) and the semicolon cloaking trick
/// (`?utm_content=safe;callback=EVIL`) that hides the second parameter from
/// the cache key.
async fn check_unkeyed_params(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Plain unkeyed parameter probe
    let params = [
        ("utm_content", PROBE),
        ("callback", PROBE),
    ];

    for (param, value) in params {
        let url = format!("{}/?{param}={value}", ctx.config.base_url);
        let Ok(r) = ctx.client.get(&url).send().await else {
            continue;
        };
        let body = r.text().await.unwrap_or_default();
        if body.contains(value) {
            let f = Finding::new(
                Severity::High,
                "Web Cache Poisoning",
                format!("Unkeyed parameter '{param}' reflected in response — inject XSS/JS payload here"),
            )
            .with_details(format!("?{param}={value} reflected in body"));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }

    // Parameter cloaking: semicolon trick hides second param from cache key
    let cloak_url = format!(
        "{}/?utm_content=safe;callback={}",
        ctx.config.base_url, PROBE
    );
    let Ok(r) = ctx.client.get(&cloak_url).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();
    if body.contains(PROBE) {
        let f = Finding::new(
            Severity::High,
            "Web Cache Poisoning",
            "Parameter cloaking via semicolons: 'callback' hidden from cache key but reflected",
        )
        .with_details(format!("utm_content=safe;callback={PROBE} — second param reflected"));
        ctx.out.finding(&f);
        findings.push(f);
    }

    findings
}

/// Confirm `utm_content` is excluded from the cache key by sending two requests
/// with different values and checking that the second still returns `X-Cache: hit`.
///
/// Lab: Web cache poisoning with an unkeyed parameter.
async fn check_unkeyed_param_cache_key(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let probe_a = format!("{PROBE}A");
    let probe_b = format!("{PROBE}B");

    let url_a = format!("{}/?utm_content={probe_a}", ctx.config.base_url);
    let Ok(r1) = ctx.client.get(&url_a).send().await else {
        return findings;
    };
    let x_cache_1 =
        r1.headers().get("x-cache").and_then(|h| h.to_str().ok()).unwrap_or("").to_lowercase();

    // Only meaningful if the first response was a MISS (we caused the cache write).
    if !x_cache_1.contains("miss") {
        return findings;
    }

    let url_b = format!("{}/?utm_content={probe_b}", ctx.config.base_url);
    let Ok(r2) = ctx.client.get(&url_b).send().await else {
        return findings;
    };
    let x_cache_2 =
        r2.headers().get("x-cache").and_then(|h| h.to_str().ok()).unwrap_or("").to_lowercase();

    if x_cache_2.contains("hit") {
        let f = Finding::new(
            Severity::High,
            "Web Cache Poisoning",
            "utm_content confirmed excluded from cache key — different value still served from cache",
        )
        .with_details(format!(
            "utm_content={probe_a} → {x_cache_1}, utm_content={probe_b} → {x_cache_2}"
        ));
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Probe parameter cloaking on the geolocate.js endpoint.
///
/// Sends `?callback=setCountryCookie&utm_content=foo;callback=PROBE` — the cache
/// excludes `utm_content` from its key, so the cloaked `callback` override is
/// invisible to the cache but processed by the server.
///
/// Lab: Web cache poisoning via parameter cloaking.
async fn check_param_cloaking_geolocate(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let paths = ["/js/geolocate.js", "/resources/js/geolocate.js"];

    for path in paths {
        let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }

        let probe_url = format!(
            "{}{}?callback=setCountryCookie&utm_content=foo;callback={PROBE}",
            ctx.config.base_url, path
        );
        let Ok(r2) = ctx.client.get(&probe_url).send().await else {
            continue;
        };
        let body = r2.text().await.unwrap_or_default();
        if body.contains(PROBE) {
            let f = Finding::new(
                Severity::High,
                "Web Cache Poisoning",
                format!(
                    "Parameter cloaking on {path}: cloaked 'callback' reflected \
                     — semicolon hides override from cache key"
                ),
            )
            .with_details(format!(
                "?callback=setCountryCookie&utm_content=foo;callback={PROBE} \
                 → '{PROBE}' in response"
            ));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// Probe fat GET: send a GET request with a body parameter that overrides the
/// URL parameter. The cache keys on the URL; the server uses the body value.
///
/// Lab: Web cache poisoning via a fat GET request.
async fn check_fat_get(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let paths = ["/js/geolocate.js", "/resources/js/geolocate.js"];

    for path in paths {
        let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }

        let fat_url = format!("{}{}?callback=setCountryCookie", ctx.config.base_url, path);
        let Ok(r2) = ctx
            .client
            .get(&fat_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("callback={PROBE}"))
            .send()
            .await
        else {
            continue;
        };
        let body = r2.text().await.unwrap_or_default();
        if body.contains(PROBE) {
            let f = Finding::new(
                Severity::High,
                "Web Cache Poisoning",
                format!(
                    "Fat GET on {path}: server uses body param over URL param \
                     — cache key uses URL only"
                ),
            )
            .with_details(format!(
                "GET ?callback=setCountryCookie + body callback={PROBE} → '{PROBE}' in response"
            ));
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
