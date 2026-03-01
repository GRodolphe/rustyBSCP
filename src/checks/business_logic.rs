//! Business logic vulnerability reconnaissance:
//! negative quantity, price manipulation, workflow bypass.

use std::sync::Arc;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    ctx.out.info("Checking for business logic vulnerabilities…");

    let (cart_f, coupon_f, qty_f) = tokio::join!(
        check_cart_manipulation(ctx),
        check_coupon_reuse(ctx),
        check_negative_quantity(ctx),
    );

    let mut findings = Vec::new();
    findings.extend(cart_f);
    findings.extend(coupon_f);
    findings.extend(qty_f);
    findings
}

async fn check_cart_manipulation(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if the cart endpoint exists
    let Ok(r) = ctx.client.get(ctx.url("/cart")).send().await else {
        return findings;
    };

    if r.status().is_success() {
        let f = Finding::new(
            Severity::Info,
            "Business Logic",
            "Shopping cart found at /cart — test for price manipulation (negative qty, overflow)",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

async fn check_coupon_reuse(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try to apply coupon endpoint
    let Ok(r) = ctx
        .client
        .post(ctx.url("/cart/coupon"))
        .form(&[("csrf", "dummy"), ("coupon", "NEWCUST5")])
        .send()
        .await
    else {
        return findings;
    };

    if r.status().is_success() || r.status().as_u16() == 302 {
        let f = Finding::new(
            Severity::Medium,
            "Business Logic",
            "Coupon endpoint /cart/coupon is accessible — test for coupon reuse / stacking",
        );
        ctx.out.finding(&f);
        findings.push(f);
    }
    findings
}

async fn check_negative_quantity(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Attempt to add a product with negative quantity
    let Ok(r) = ctx
        .client
        .post(ctx.url("/cart"))
        .form(&[("productId", "1"), ("quantity", "-1"), ("redir", "PRODUCT")])
        .send()
        .await
    else {
        return findings;
    };

    let status = r.status();
    if status.is_success() || status.is_redirection() {
        let body = r.text().await.unwrap_or_default();
        // A negative total price or no validation error indicates the issue
        if body.contains('-') && (body.contains("£") || body.contains('$') || body.contains("price")) {
            let f = Finding::new(
                Severity::High,
                "Business Logic",
                "Negative quantity accepted by /cart — price may underflow to negative total",
            );
            ctx.out.finding(&f);
            findings.push(f);
        } else {
            let f = Finding::new(
                Severity::Low,
                "Business Logic",
                "Cart endpoint accepts POST with quantity=-1 — validate server-side bounds checking",
            );
            ctx.out.finding(&f);
            findings.push(f);
        }
    }
    findings
}
