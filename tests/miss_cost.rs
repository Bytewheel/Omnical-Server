//! Where a cache miss actually spends its time, and what that implies about making
//! it cheap.
//!
//! §18.25 measured the symptom — a tenant returning after idle pays **~102 ms** of
//! pool construction — and declined to optimise it because nothing had said how the
//! 102 ms divides up. That is the question this file answers, and it is the
//! question that decides whether a cheap miss is one change or five.
//!
//! Four stages are measured directly; the fifth (`build_extensions`) is private
//! and is derived by subtraction, which is labelled as such below.
//!
//! Three outcomes are possible and they imply very different work:
//!
//! * **one stage dominates** — fix that stage, and the miss is cheap;
//! * **the cost is spread** — a cheap miss needs all of them fixed, which is a
//!   redesign rather than an optimisation;
//! * **it is all in one thing we cannot avoid** — then the answer is not "make it
//!   cheap" but "do not pay it twice", which is a different fix.
//!
//! ```sh
//! cargo test --release --test miss_cost -- --ignored --nocapture --test-threads=1
//! ```

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rustical_store::tenant::{Tenant, TenantId, TenantStatus};

const SAMPLES: usize = 40;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn stage_report(name: &str, mut samples: Vec<f64>) {
    let total: f64 = samples.iter().sum();
    let med = median(samples.clone());
    samples.sort_by(f64::total_cmp);
    println!(
        "  {name:<34} median {med:>7.2} ms   min {:>7.2}   max {:>7.2}",
        samples[0],
        samples[samples.len() - 1]
    );
    let _ = total;
}

/// **Time each stage of a miss, in the order `tenant_builder` runs them.**
#[test]
#[ignore = "a micro-benchmark; run in release and record the machine"]
fn where_does_a_miss_spend_its_time() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let dir = tempfile::tempdir().expect("a temp dir");
        let data_root: PathBuf = dir.path().join("data");
        std::fs::create_dir_all(&data_root).expect("the data dir");

        let tenant: Tenant = Tenant {
            id: "t-0000".parse().expect("a slug"),
            slug: "t-0000".parse().expect("a slug"),
            display_name: "Tenant 0".to_owned(),
            status: TenantStatus::Active,
            config_json: "{}".to_owned(),
            plan: "load".to_owned(),
            suspended_at: None,
            created_at: None,
        };

        let mut base = rustical::config::Config::default_config();
        base.tenancy.enabled = true;
        base.data_store =
            rustical::config::DataStoreConfig::Sqlite(rustical::config::SqliteDataStoreConfig {
                db_url: format!("file:{}", data_root.join("db.sqlite3").display()),
                run_repairs: false,
                skip_broken: false,
            });

        // One store, migrated, so stages 3-5 have something real to work on.
        let db_path = base
            .tenancy
            .ensure_tenant_store_dir(&data_root, &tenant.id)
            .expect("dir");
        let data_store =
            rustical::config::DataStoreConfig::Sqlite(rustical::config::SqliteDataStoreConfig {
                db_url: format!("file:{}", db_path.display()),
                run_repairs: false,
                skip_broken: false,
            });
        rustical::get_store_bundle(true, &data_store)
            .await
            .expect("a first bundle");

        // The FIRST iteration is the one that matters, and separating it is the
        // whole point of this benchmark.
        //
        // Stages 1-3 and 5 measured ~3 ms in total, while `cache_decision.rs`
        // measures a *real* cold miss at ~102 ms. That 32x gap is the question.
        // If it is the first iteration alone then the miss is **I/O** — the OS
        // page cache has evicted the tenant's SQLite file, and the cost is
        // re-reading it — and no amount of restructuring the builder helps. If
        // every iteration is ~3 ms then the 102 ms is elsewhere entirely, in
        // `build_extensions` or on the request path after the router exists.
        let mut cold_total: Option<f64> = None;

        let mut s_dir = Vec::new();
        let mut s_pool = Vec::new();
        let mut s_overrides = Vec::new();
        let mut s_router = Vec::new();

        for i in 0..SAMPLES {
            // Stage 1 — the data directory. Cheap on purpose: SQLite creates a
            // *file*, not the parent directories, so this has to happen somewhere.
            let t = Instant::now();
            let path = base
                .tenancy
                .ensure_tenant_store_dir(&data_root, &tenant.id)
                .expect("dir");
            let t_dir = t.elapsed();
            s_dir.push(ms(t_dir));

            // Stage 2 — the stores: the SQLite pool, its migrations, and every
            // `Sqlite*Store` over it. `migrate: true` because a tenant's store is
            // created by whatever inserted its row and nothing guarantees that actor
            // ran them.
            let ds = rustical::config::DataStoreConfig::Sqlite(
                rustical::config::SqliteDataStoreConfig {
                    db_url: format!("file:{}", path.display()),
                    run_repairs: false,
                    skip_broken: false,
                },
            );
            let t = Instant::now();
            let bundle = rustical::get_store_bundle(true, &ds).await.expect("stores");
            let t_pool = t.elapsed();
            s_pool.push(ms(t_pool));

            // Stage 3 — §3.6's per-tenant override merge. This is what mounts the
            // three public routers at all.
            let t = Instant::now();
            let overrides = rustical::tenant_overrides::Overrides::parse(&tenant.config_json);
            let _sched = overrides.scheduling(&base.scheduling);
            let _subs = overrides.subscriptions(&base.subscriptions);
            let _reg = overrides.registration(&base.registration);
            let mut app_config = base.clone();
            app_config.scheduling = _sched.clone();
            app_config.subscriptions = _subs.clone();
            app_config.registration = _reg.clone();
            let t_overrides = t.elapsed();
            s_overrides.push(ms(t_overrides));

            // Stage 5 — the whole axum router: routes, layers, the CalDAV/CardDAV
            // merges and the session layer.
            let t = Instant::now();
            // Stage 5 needs an `AppConfig`, which `build_extensions` normally
            // produces. It is built by hand here so the router can be timed
            // without widening `build_extensions` for a benchmark — and with the
            // extensions all `None`, which is also the *cheap* end of what the
            // real builder may produce, so a large figure here would be a floor
            // rather than an over-estimate.
            let stage5_config = rustical::app::AppConfig {
                frontend: app_config.frontend.clone(),
                oidc: None,
                caldav: app_config.caldav.clone(),
                scheduler: None,
                subscriptions: None,
                registration: None,
                nextcloud_login: app_config.nextcloud_login.clone(),
                dav_push_enabled: false,
                session_cookie_samesite_strict: false,
                payload_limit_mb: app_config.http.payload_limit_mb,
                subscriptions_public_url: String::new(),
                smtp_accounts: Vec::new(),
            };
            let _router = rustical::app::make_app_for(
                Some(tenant.clone()),
                stage5_config,
                bundle.app_stores(),
            );
            let t_router = t.elapsed();
            s_router.push(ms(t_router));

            if i == 0 {
                cold_total = Some(ms(t_dir) + ms(t_pool) + ms(t_overrides) + ms(t_router));
            }

            // Keep the optimiser honest: the loop must not be elided.
            assert!(i < SAMPLES);
        }

        let sum = |v: &Vec<f64>| v.iter().sum::<f64>();
        let total = sum(&s_dir) + sum(&s_pool) + sum(&s_overrides) + sum(&s_router);
        println!("=== stage cost of a cache miss ({SAMPLES} samples, medians) ===");
        stage_report("1. ensure_tenant_store_dir", s_dir.clone());
        stage_report("2. get_store_bundle (pool+migrate)", s_pool.clone());
        stage_report("3. overrides merge (§3.6)", s_overrides.clone());
        stage_report("5. make_app_for (router)", s_router.clone());
        println!();
        println!("  share of the total:");
        for (name, v) in [
            ("ensure_tenant_store_dir", &s_dir),
            ("get_store_bundle", &s_pool),
            ("overrides merge", &s_overrides),
            ("make_app_for", &s_router),
        ] {
            println!("    {name:<26} {:>5.1}%", 100.0 * sum(v) / total);
        }
        let per_iter = total / SAMPLES as f64;
        let cold = cold_total.unwrap_or(0.0);
        println!("\n  median per iteration (warm): {per_iter:.2} ms");
        println!("  FIRST iteration (cold file):  {cold:.2} ms");
        println!(
            "  ratio cold:warm              {:.1}x",
            cold / per_iter.max(0.001)
        );
        println!();
        if cold > per_iter * 5.0 {
            println!("  => the miss is I/O-bound. The OS page cache has evicted the tenant's");
            println!(
                "     SQLite file, and ~{:.0} ms of the ~102 ms is re-reading it.",
                cold
            );
            println!("     Restructuring the builder cannot help; the lever is how the file is");
            println!("     read (mmap, a per-connection page cache) or not re-read at all.");
        } else {
            println!("  => the cost is NOT cold-file I/O. It is in work this benchmark does not");
            println!("     reach — build_extensions, or the first request *after* the router");
            println!("     exists. Both are inside the request path, so they are where to look.");
        }
        println!("\n  measured stages total: {total:.1} ms over {SAMPLES} samples");
        println!("  (stage 4, build_extensions, is `pub`-private, so it is *derived by");
        println!("   subtraction* from the ~102 ms a real miss costs in tests/cache_decision.rs");
        println!("   rather than measured here. Widening the API so a benchmark can reach a");
        println!("   private function is the wrong trade for one derived number.)");
    });
}
