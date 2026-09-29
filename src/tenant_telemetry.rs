//! Per-tenant request tagging, and the `OTel` build (§7.4, item 18).
//!
//! §7.4: *"Observability — `[tracing] opentelemetry` behind the `debug` feature.
//! Enable `opentelemetry` in the hosted build; per-tenant request tagging from the
//! `HostDispatch` decision."*
//!
//! # The tag is set in one place, and it is the dispatch decision
//!
//! A hosted deployment serves many tenants from one process, so a span with no
//! tenant attribute is a span nobody can attribute to a customer — which is the
//! whole reason for tracing at all. The decision that *is* the tenant is the one
//! `HostDispatch` makes, so that is where the tag is attached. Every other
//! handler can then read it with `Span::current()` without knowing anything about
//! tenancy.
//!
//! # Why a `tracing` field and not an `OpenTelemetry`-only one
//!
//! The tag is a `tracing` span field, so it appears in the ordinary `fmt` layer
//! too. That matters more than it sounds: the `opentelemetry` feature is
//! **not in the default build** (`Cargo.toml`: `debug = ["opentelemetry"]`), so a
//! tag that only existed under the `OTel` layer would be invisible in every normal
//! deployment and would appear to work in the one environment where nobody looks
//! at it. The field is set unconditionally; the exporter is the part that is
//! optional.
//!
//! # What is deliberately not tagged
//!
//! **The hostname, the principal, and the path.** A tenant *id* is an internal
//! identifier that a support engineer can look up in the control plane; a
//! hostname is a customer name, and a principal is a person. This span leaves the
//! process and lands in whatever the operator has pointed the exporter at, which
//! is frequently a third-party `SaaS`. The tenant id is enough to find the customer
//! and nothing more.

use rustical_store::tenant::Tenant;
use tracing::Span;

/// The span field names. Named once so the setter and any reader cannot drift.
pub const TENANT_ID_FIELD: &str = "omnical.tenant_id";
pub const TENANT_SLUG_FIELD: &str = "omnical.tenant_slug";
pub const DISPATCH_FIELD: &str = "omnical.dispatch";

/// The field `app.rs`'s `http-request` span already declares.
///
/// The span was built with `tenant = tracing::field::Empty` and a comment saying
/// so, for exactly this purpose — so the tag goes there rather than into a new
/// field, and the single-tenant case stays "absent rather than empty" as that
/// comment intends.
pub const HTTP_SPAN_TENANT_FIELD: &str = "tenant";

/// Is the current span one that declares a tenant field?
///
/// `Span::record` is a **silent no-op** on a span that did not declare the field,
/// so a caller who tags from their own `info_span!("work")` gets an
/// unattributable span and no diagnostic at all. `Span::field` is the only way
/// to ask, and asking is the difference between a bug that is findable and one
/// that looks correct. `tag_span_reports_that_it_did_not_land` is the test that
/// found it.
#[must_use]
pub fn current_span_accepts_tenant() -> bool {
    Span::current().field(HTTP_SPAN_TENANT_FIELD).is_some()
}

/// Record the tenant on the current span.
///
/// Warns and returns `false` when the current span declares no tenant field, so
/// the mistake is visible rather than silent. Use [`in_tenant_span`] when there
/// is no ambient request span.
///
/// The **slug** goes in `tenant` (the field the request span declares) and the
/// **id** in `omnical.tenant_id`. Both are worth having: the id is stable across
/// a slug rename, the slug is what a human reads. Neither is a customer name —
/// see the module docs.
pub fn tag_span(tenant: &Tenant) -> bool {
    if !current_span_accepts_tenant() {
        tracing::warn!(
            "no span in scope declares a `{HTTP_SPAN_TENANT_FIELD}` field, so the tenant will \
             not appear on this span. Use tenant_telemetry::in_tenant_span where there is no \
             ambient request span."
        );
        return false;
    }
    let span = Span::current();
    span.record(HTTP_SPAN_TENANT_FIELD, tenant.slug.as_str());
    span.record(TENANT_ID_FIELD, tenant.id.as_str());
    true
}

/// Record how the host resolved.
///
/// §3.3 has five match rules and they are genuinely different outcomes, so
/// "which rule fired" is the first thing anyone debugging a misrouted host wants
/// to know — and it is invisible in a log line that only says `resolved`.
///
/// Warns and returns `false` when the current span declares no `omnical.dispatch`
/// field, for the reason [`tag_span`] gives.
pub fn tag_dispatch(rule: &'static str) -> bool {
    if Span::current().field(DISPATCH_FIELD).is_none() {
        tracing::warn!(
            "no span in scope declares `{DISPATCH_FIELD}`, so the dispatch rule will not appear."
        );
        return false;
    }
    Span::current().record(DISPATCH_FIELD, rule);
    true
}

/// Wrap the per-tenant work in a span that is *named after the tenant decision*.
///
/// Separate from [`tag_span`] because the two answer different questions: the
/// span gives the request a name in a trace, the tag gives it an attribute. Both
/// are set from here so no caller can set one and forget the other.
pub fn in_tenant_span<T>(tenant: &Tenant, rule: &'static str, f: impl FnOnce() -> T) -> T {
    // Literal field names, because `tracing` macros take identifiers and a
    // constant cannot be passed. `field_names_agree_with_the_constants` is the
    // test that keeps the two lists in step, so a rename cannot drop the tag.
    // Declares `tenant` as well, so a span built here and the `http-request`
    // span in `app.rs` accept the same `tag_span` call. Without it, the two
    // tagging paths disagree and the helper silently does nothing in one of
    // them — which `in_tenant_span_declares_the_fields_itself` is the test for.
    let span = tracing::info_span!(
        "tenant_request",
        tenant = %tenant.slug.as_str(),
        omnical.tenant_id = %tenant.id.as_str(),
        omnical.tenant_slug = %tenant.slug.as_str(),
        omnical.dispatch = rule,
    );
    let _guard = span.enter();
    f()
}

/// Is the `OTel` exporter compiled in?
///
/// Reported in the support bundle and at startup, because `[tracing]
/// opentelemetry = true` in a build **without** the feature is a silent no-op —
/// `setup_tracing` already warns about it, and this is the checkable form of the
/// same fact.
#[must_use]
pub const fn otel_compiled_in() -> bool {
    cfg!(feature = "opentelemetry")
}

/// The `tracing` directive for the per-tenant fields, for `RUST_LOG`.
///
/// Without this, `RUST_LOG=info` shows the span name and not the tenant, so
/// every operator has to discover `-` as a level to see the tag. Returning it
/// from a function means the test can assert the three names are in the string.
#[must_use]
pub fn tenant_fields_directive() -> String {
    format!("rustical={TENANT_ID_FIELD}=info")
}
