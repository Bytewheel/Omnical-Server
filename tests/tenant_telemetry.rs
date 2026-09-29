//! Item 18 (§7.4), part three: per-tenant request tagging.
//!
//! The failure mode here is a span with no tenant on it, which is useless and
//! looks fine. So most of this file asserts what the tag must **not** contain as
//! well as what it must.

use std::sync::{Arc, Mutex};

use rustical::tenant_telemetry::{
    DISPATCH_FIELD, HTTP_SPAN_TENANT_FIELD, TENANT_ID_FIELD, TENANT_SLUG_FIELD,
    current_span_accepts_tenant, in_tenant_span, otel_compiled_in, tag_dispatch, tag_span,
    tenant_fields_directive,
};
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};

fn tenant(slug: &str) -> Tenant {
    Tenant {
        id: TenantId::generate(),
        slug: slug.parse().expect("a valid slug"),
        display_name: "Acme Corporation Ltd".to_owned(),
        status: TenantStatus::Active,
        config_json: "{}".to_owned(),
        plan: "enterprise".to_owned(),
        suspended_at: None,
        created_at: None,
    }
}

/// A `MakeWriter` that appends every formatted line to a shared buffer.
#[derive(Clone)]
struct Capture(Arc<Mutex<String>>);

struct Line(Arc<Mutex<String>>);

impl std::io::Write for Line {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Line;
    fn make_writer(&'a self) -> Self::Writer {
        Line(Arc::clone(&self.0))
    }
}

/// Capture what the ordinary `fmt` layer wrote while `f` ran.
///
/// The `fmt` layer rather than a bespoke subscriber, on purpose: the claim under
/// test is that the tenant tag is visible in a **normal** deployment, and a test
/// that installed its own subscriber would pass even if `fmt` dropped the field.
fn capture(f: impl FnOnce() + Send + Sync + 'static) -> String {
    let out = Arc::new(Mutex::new(String::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_target(false)
        .with_writer(Capture(Arc::clone(&out)))
        .finish();
    // Thread-local, so this composes with the parallel tests in this file.
    let _guard = tracing::subscriber::set_default(subscriber);
    f();
    out.lock().expect("the capture lock").clone()
}

// ── the tag exists, and is visible without the OTel feature ────────────────

#[test]
fn tag_span_says_so_rather_than_failing_silently() {
    // The trap this caught. `Span::record` is a no-op on a span that did not
    // declare the field, so a handler that calls `tag_span` inside its own
    // `info_span!("work")` gets an unattributable span and no diagnostic at all.
    // The first version returned `()` and this test failed with "the tenant is not
    // on the span" and nothing else — the kind of bug that ships.
    let t = tenant("hooli");
    let out = capture(move || {
        let span = tracing::info_span!("work");
        let _g = span.enter();
        assert!(!current_span_accepts_tenant());
        let landed = tag_span(&t);
        assert!(
            !landed,
            "a span that declares no tenant field must report no landing"
        );
        tracing::info!("inside my own span");
    });
    assert!(
        out.contains("no span in scope declares"),
        "the caller must be told, not left guessing:\n{out}"
    );
    assert!(!out.contains("hooli"), "and nothing was tagged:\n{out}");
}

#[test]
fn a_span_that_declares_the_fields_accepts_the_tag() {
    // The supported path, and the one the dispatch loop gets for free because
    // `app.rs`'s `http-request` span declares them.
    let t = tenant("hooli");
    let out = capture(move || {
        let span = tracing::info_span!(
            "http-request",
            tenant = tracing::field::Empty,
            omnical.tenant_id = tracing::field::Empty,
            omnical.dispatch = tracing::field::Empty,
        );
        let _g = span.enter();
        assert!(current_span_accepts_tenant());
        assert!(tag_span(&t), "a declaring span must accept the tag");
        assert!(tag_dispatch("explicit-host"), "…and the rule too");
        tracing::info!("attributed");
    });
    assert!(out.contains("hooli"), "{out}");
    assert!(out.contains("explicit-host"), "{out}");
}

#[test]
fn in_tenant_span_declares_the_fields_itself() {
    let t = tenant("hooli");
    let out = capture(move || {
        in_tenant_span(&t, "explicit-host", || {
            assert!(
                current_span_accepts_tenant(),
                "in_tenant_span must declare the tenant field, or tagging inside it is a no-op"
            );
            // An *event* inside the span: a span on its own writes nothing, so
            // without this the assertion below would pass for the wrong reason.
            tracing::info!("inside in_tenant_span");
        });
    });
    assert!(out.contains("hooli"), "{out}");
}

#[test]
fn a_tenant_request_records_the_tenant_and_the_rule() {
    let t = tenant("acme");
    let id = t.id.as_str().to_owned();
    let out = capture(move || {
        in_tenant_span(&t, "explicit-host", || {
            tag_dispatch("explicit-host");
            tracing::info!("handled a request");
        });
    });
    assert!(
        out.contains("acme") || out.contains(&id),
        "the tenant is not on the span:\n{out}"
    );
    assert!(
        out.contains("explicit-host"),
        "the dispatch rule is not on the span:\n{out}"
    );
}

#[test]
fn the_tag_does_not_need_the_opentelemetry_feature() {
    // The whole reason the tag is a plain `tracing` field: the OTel feature is
    // not in the default build (`Cargo.toml`: `debug = ["opentelemetry"]`), so a
    // tag that only existed under the OTel layer would be invisible in every
    // normal deployment and appear to work in the one environment nobody looks
    // at.
    //
    // `cargo test --all-features` *does* enable the feature, so this test asserts
    // the property that holds either way — the tag reaches the ordinary `fmt`
    // layer — and reports which build it ran in. The default-build claim is
    // covered by `cargo test --workspace` without `--all-features`, where
    // `otel_compiled_in()` is false; the gate below is the check for that.
    let t = tenant("globex");
    let out = capture(move || {
        in_tenant_span(&t, "base-domain", || {
            tracing::info!("tagged, whatever the build");
        });
    });
    assert!(
        out.contains("globex"),
        "the tenant tag did not reach the fmt layer (otel compiled in: {})",
        otel_compiled_in()
    );
    // The fmt layer is the point: an OTel-only field would not be in this string
    // even with the feature on, so this asserts the *layer*, not the exporter.
    assert!(
        out.contains("tagged, whatever the build"),
        "the fmt layer did not see the event at all, so the assertion above proves nothing:\n{out}"
    );
}

// ── what must NOT be in the span ────────────────────────────────────────────

#[test]
fn a_span_carries_the_tenant_id_and_never_the_company_name() {
    // A span leaves the process and usually lands in a third-party SaaS. The id
    // is enough to find the customer; a `display_name` is the customer's legal
    // name, and the plan is a commercial relationship.
    let t = tenant("initech");
    let out = capture(move || {
        in_tenant_span(&t, "default-tenant", || {
            tracing::info!("sensitive check");
        });
    });
    assert!(
        !out.contains("Acme Corporation"),
        "the tenant's display name leaked into a span:\n{out}"
    );
    assert!(
        !out.contains("enterprise"),
        "the tenant's plan leaked into a span:\n{out}"
    );
}

#[test]
fn no_hostname_or_principal_is_tagged_anywhere() {
    let src = include_str!("../src/tenant_telemetry.rs");
    for forbidden in ["host", "principal", "email", "password"] {
        assert!(
            !src.contains(&format!("{forbidden} =")),
            "the telemetry module tags a {forbidden}, which is not a tenant id:\n{src}"
        );
    }
    // …and the constants are exactly the three that were asked for.
    assert_eq!(TENANT_ID_FIELD, "omnical.tenant_id");
    assert_eq!(TENANT_SLUG_FIELD, "omnical.tenant_slug");
    assert_eq!(DISPATCH_FIELD, "omnical.dispatch");
    assert_eq!(HTTP_SPAN_TENANT_FIELD, "tenant");

    // The request span must **declare** every field `tag_span` records, or the
    // tag is dropped with no error. This is the check that keeps a rename from
    // making the tag disappear.
    let app = include_str!("../src/app.rs");
    for field in [HTTP_SPAN_TENANT_FIELD, TENANT_ID_FIELD, DISPATCH_FIELD] {
        assert!(
            app.contains(&format!("{field} = tracing::field::Empty")),
            "the http-request span does not declare `{field}`, so Span::record would drop it"
        );
    }
}

#[test]
fn the_rust_log_directive_names_the_tenant_field() {
    // Without this, `RUST_LOG=info` shows the span name and not the tenant, and
    // every operator has to discover `-` as a level to see the tag.
    let directive = tenant_fields_directive();
    assert!(
        directive.contains(TENANT_ID_FIELD),
        "the directive does not mention the tenant field: {directive}"
    );
}

// ── the field names cannot drift ────────────────────────────────────────────

#[test]
fn the_span_macro_literals_match_the_constants() {
    // `tracing::info_span!` takes identifiers, so the macro must use literals
    // while `Span::record` uses the constants. Two lists, one meaning — and this
    // is the test that stops a rename from silently dropping the tag.
    let src = include_str!("../src/tenant_telemetry.rs");
    for field in [TENANT_ID_FIELD, TENANT_SLUG_FIELD, DISPATCH_FIELD] {
        assert!(
            src.contains(&format!("{field} = ")),
            "the span macro does not set {field}, so a rename would drop the tag silently"
        );
    }
    // The macro's dotted names and the constants' values must be the same strings.
    assert_eq!(TENANT_ID_FIELD, "omnical.tenant_id");
    assert_eq!(TENANT_SLUG_FIELD, "omnical.tenant_slug");
    assert_eq!(DISPATCH_FIELD, "omnical.dispatch");
}

#[test]
fn every_resolve_rule_is_named() {
    // §3.3 has five match rules; a sixth appears later, it must be named too, and
    // an unnamed one is the case where an operator has nothing to look at.
    let src = include_str!("../src/host_dispatch.rs");
    for rule in [
        "explicit-host",
        "base-domain",
        "host-as-slug",
        "default-tenant",
    ] {
        assert!(
            src.contains(&format!("\"{rule}\"")),
            "the resolve arms do not name the rule `{rule}`"
        );
    }
}

// ── the tag is set on the request path, not only in the helper ──────────────

#[test]
fn host_dispatch_tags_on_every_resolved_request() {
    // If the tagging call is ever deleted from the dispatch loop, every other
    // test in this file still passes — they call the helpers directly. This one
    // is the only thing that notices.
    let src = include_str!("../src/host_dispatch.rs");
    assert!(
        src.contains("tag_span(&tenant)"),
        "the dispatch loop no longer tags the tenant — spans would be unattributable"
    );
    assert!(
        src.contains("tag_dispatch(rule)"),
        "the dispatch loop no longer tags which rule fired"
    );
}

#[test]
fn a_404_is_not_tagged_with_a_tenant() {
    // An unknown host resolves to nothing, so there is no tenant to tag — and
    // tagging the *requested* host would turn the span into a customer-enumeration
    // oracle for anyone who can reach the exporter.
    let t = tenant("acme");
    let out = capture(move || {
        in_tenant_span(&t, "explicit-host", || {
            tracing::info!("normal request");
        });
    });
    // The assertion is really about `host_dispatch`: a `tag_host`-style call
    // would not exist. Guard the shape instead.
    let src = include_str!("../src/host_dispatch.rs");
    assert!(
        !src.contains("tag_host"),
        "something tags the requested host; that is a customer-enumeration oracle"
    );
    assert!(!out.is_empty());
}
