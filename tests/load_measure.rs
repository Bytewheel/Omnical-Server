//! §7.2's load number (item 20c), as a harness that produces a real measurement.
//!
//! §7.2 says *"measure, do not guess"* and *"§6 A1 measures per-tenant pool cost
//! in wave 3 and records the number here"*. The gate is *"200 tenants × 50
//! concurrent clients, p99 DAV latency within 2× the single-tenant baseline, RSS
//! within the pod limit."*
//!
//! # Why this is `#[ignore]`d and how to run it
//!
//! A load test in the normal suite is a test that is slow, that fails on a busy
//! CI runner for reasons unrelated to the code, and that everybody eventually
//! marks `#[ignore]`d anyway — at which point it is decoration. So it is marked
//! ignored **from the start**, and the number is recorded in the plan with the
//! machine it was measured on, because a p99 measured on a laptop and quoted as
//! a production figure is worse than no number at all.
//!
//! ```sh
//! cargo test --test load_measure -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # What it measures, and what it cannot
//!
//! Real: N tenant stores on disk, real HTTP, real `HostDispatch` resolution, real
//! SQLite. The clients are real TCP connections and the timing is wall-clock.
//!
//! Not real: TLS, the edge, the network, and the disk's own behaviour under
//! contention. So the numbers are a **lower bound** on production latency and are
//! only comparable to each other — which is exactly what the gate asks for
//! ("within 2× the single-tenant baseline"), and why the baseline is measured on
//! the same machine in the same run rather than quoted from elsewhere.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantStore as _};

/// How many tenants to serve. The gate says 200.
const TENANTS: usize = 200;
/// How many requests in flight at once. The gate says 50.
const CONCURRENCY: usize = 50;
/// Requests per client. Enough to be a distribution, few enough to finish.
const PER_CLIENT: usize = 20;
/// §7.2's documented default. **This is the configuration that fails the gate**
/// at {TENANTS} tenants, and the harness asserts it on every run so the finding
/// cannot be quietly deleted.
const DOCUMENTED_CACHE: usize = 64;
/// Every tenant resident. Used for the baseline (which must not thrash) and to
/// isolate dispatch's cost from the cache's.
const CACHE_UNDER_TEST: usize = 256;

fn percentile(mut samples: Vec<u64>, p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let idx = ((samples.len() as f64 - 1.0) * p).round() as usize;
    samples[idx.min(samples.len() - 1)]
}

#[derive(Debug, Clone)]
struct Stats {
    latencies_ms: Vec<u64>,
    errors: u64,
}

impl Stats {
    fn summary(&self) -> String {
        let mut l = self.latencies_ms.clone();
        l.sort_unstable();
        format!(
            "n={} p50={}ms p95={}ms p99={}ms max={}ms errors={}",
            l.len(),
            percentile(l.clone(), 0.50),
            percentile(l.clone(), 0.95),
            percentile(l.clone(), 0.99),
            l.last().copied().unwrap_or(0),
            self.errors
        )
    }
}

/// RSS of a process, in MiB, read from `/proc/<pid>/status`.
///
/// `VmRSS` and not `VmHWM`: the gate is about a *resident* set, and quoting the
/// peak would make a run that spiked during tenant construction look like one
/// that needs a bigger pod forever after.
fn rss_mib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Seed N tenants with a real store each, and return their hostnames.
async fn seed(dir: &std::path::Path, tenancy: bool) -> Vec<String> {
    let control_url = format!("sqlite://{}", dir.join("control.sqlite3").display());
    let control = rustical_store_sqlite::SqliteTenantStore::new(
        rustical_store_sqlite::create_control_plane_pool(&control_url, true)
            .await
            .expect("a control plane"),
    );
    let actor = rustical_store::Actor::new("load-test").expect("an actor");
    let mut hosts = Vec::with_capacity(TENANTS);
    for n in 0..TENANTS {
        let slug: TenantId = format!("t{n:04}").parse().expect("a valid slug");
        let path = dir.join("data").join(format!("{}.sqlite3", slug.as_str()));
        let pool =
            rustical_store_sqlite::create_db_pool(&format!("sqlite://{}", path.display()), true)
                .await
                .expect("a tenant store");
        pool.close().await;
        let host = format!("{slug}.load.test");
        if tenancy {
            control
                .create_tenant(
                    &NewTenant {
                        tenant: Tenant {
                            id: slug.clone(),
                            slug,
                            display_name: format!("Tenant {n}"),
                            status: TenantStatus::Active,
                            config_json: "{}".to_owned(),
                            plan: "load".to_owned(),
                            suspended_at: None,
                            created_at: None,
                        },
                        hosts: vec![host.clone()],
                    },
                    &actor,
                )
                .await
                .expect("the tenant is created");
        }
        hosts.push(host);
    }
    hosts
}

/// Fire `PER_CLIENT` requests at one tenant's `.well-known/caldav`, timed.
async fn drive(addr: SocketAddr, host: &str, path: &str, per_client: usize) -> Stats {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("a client");
    let url = format!("http://{addr}{path}");
    let mut latencies_ms = Vec::with_capacity(per_client);
    let mut errors = 0;
    for _ in 0..per_client {
        let started = Instant::now();
        match client.get(&url).header("Host", host).send().await {
            Ok(r) => {
                let _ = r.bytes().await;
                // A 404 still proves resolution + routing + a served response;
                // the gate is about dispatch and pool cost, not about content.
                latencies_ms.push(started.elapsed().as_millis() as u64);
            }
            Err(_) => {
                errors += 1;
            }
        }
    }
    Stats {
        latencies_ms,
        errors,
    }
}

/// Run one configuration and return the aggregate.
async fn run(
    label: &str,
    tenancy: bool,
    tenants: usize,
    max_cached: usize,
    warm_all: bool,
) -> (Stats, Option<u64>) {
    let dir = tempfile::tempdir().expect("a temp dir");
    std::fs::create_dir_all(dir.path().join("data")).expect("the data directory");
    let hosts = seed(dir.path(), tenancy).await;
    assert!(
        hosts.len() >= tenants,
        "the harness must be able to serve {tenants} tenants"
    );

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        l.local_addr().expect("an address").port()
    };
    let mut config = format!(
        "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
         [data_store.sqlite]\ndb_url = \"{}\"\nrun_repairs = false\nskip_broken = false\n\n\
         [frontend]\nenabled = true\nallow_password_login = true\n",
        dir.path().join("data").join("db.sqlite3").display(),
    );
    if tenancy {
        config.push_str(&format!(
            "\n[tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://{}\"\n\
             base_domain = \"load.test\"\ndefault_tenant = \"\"\n\
             max_cached_tenants = {max_cached}\ndata_root = \"{}\"\n",
            dir.path().join("control.sqlite3").display(),
            dir.path().join("data").display(),
        ));
    }
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, config).expect("the config is written");

    let log = std::fs::File::create(dir.path().join("server.log")).expect("a log");
    let err = log.try_clone().expect("a second handle");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rustical"))
        .arg("--config-file")
        .arg(&config_path)
        .arg("serve")
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .expect("the server starts");
    let pid = child.id();

    // Wait for readiness rather than sleeping a fixed amount: a fixed sleep is
    // either too short on a loaded machine (every request fails) or wasteful.
    let addr = format!("127.0.0.1:{port}");
    let probe = reqwest::Client::new();
    let health = if tenancy { "/healthz" } else { "/ping" };
    let mut up = false;
    for _ in 0..200 {
        if probe
            .get(format!("http://{addr}{health}"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(up, "the server never became ready; see {label}");

    // Warm the cache: the gate is about steady state, and the first request to
    // each tenant pays pool construction, which is exactly what item 20c is
    // *not* measuring.
    let socket: SocketAddr = addr.parse().expect("an address");
    // The SAME work in both modes. `/ping` is a static string with no
    // resolution, no pool and no router, so a baseline of it measures nothing.
    // The gate says "p99 **DAV** latency within 2x the single-tenant baseline",
    // which is a baseline that serves DAV.
    const DAV_PATH: &str = "/.well-known/caldav";
    // **Warm the working set, not the whole fleet** — unless `warm_all`, which
    // is the churn case and a different question entirely.
    //
    // Warming all `tenants` and then spreading `CONCURRENCY` clients over
    // `hosts[c % tenants]` (tenants 0..49) means that at `max_cached_tenants = 64`
    // the warmup left tenants 136..199 in the LRU, so **every tenant the
    // measurement then touched had just been evicted**. That is 50 cold requests
    // out of 1000 — 5%, precisely where p95 and p99 live — and it is what produced
    // the "6.7x, the documented default fails the gate" figure that §7.2 and
    // §18.24 recorded. It was this harness, not the cache.
    let warm: Vec<&String> = if warm_all {
        hosts.iter().take(tenants).collect()
    } else {
        hosts.iter().take(CONCURRENCY.min(tenants)).collect()
    };
    for host in warm {
        let _ = drive(socket, host, DAV_PATH, 1).await;
    }

    let stats = Arc::new(Mutex::new(Stats {
        latencies_ms: Vec::new(),
        errors: 0,
    }));
    let done = Arc::new(AtomicU64::new(0));

    let mut tasks = Vec::with_capacity(CONCURRENCY);
    for c in 0..CONCURRENCY {
        // Spread clients across tenants so the pool cache is exercised rather
        // than one tenant's pool absorbing all 50.
        let host = hosts[c % tenants].clone();
        let stats = Arc::clone(&stats);
        let done = Arc::clone(&done);
        tasks.push(tokio::spawn(async move {
            let path = DAV_PATH;
            let s = drive(socket, &host, path, PER_CLIENT).await;
            {
                let mut g = stats.lock().expect("the stats lock");
                g.latencies_ms.extend(s.latencies_ms);
                g.errors += s.errors;
            }
            done.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for t in tasks {
        t.await.expect("a client task");
    }

    let rss = rss_mib(pid);
    let _ = child.kill();
    let _ = child.wait();

    let stats = Arc::try_unwrap(stats)
        .map(|m| m.into_inner().expect("the stats lock"))
        .unwrap_or_else(|a| a.lock().expect("the stats lock").clone());
    assert_eq!(
        done.load(Ordering::SeqCst) as usize,
        CONCURRENCY,
        "not every client finished"
    );
    (stats, rss)
}

/// **§7.2's gate.** Run with `--ignored`; see the module docs.
///
/// # Correction, 2026-09-29: the original "finding" was this harness's own bug
///
/// The first version of this file reported that §7.2's documented
/// `max_cached_tenants = 64` **failed** §7.2's gate at 200 tenants — p99 6.7× the
/// single-tenant DAV baseline — and §7.2 and §18.24 recorded that. It was wrong.
///
/// The warmup loop touched all 200 tenants and then spread 50 clients over
/// tenants 0..49. At 64 slots the warmup left tenants 136..199 in the LRU, so
/// **every tenant the measurement then touched had just been evicted**: 50 cold
/// requests out of 1000, which is 5%, which is exactly where p95 and p99 live.
/// The number was real and it was not the property it was reported as.
///
/// Measured properly — `tests/cache_decision.rs`, which reports steady state and
/// churn separately and sweeps the bound:
///
/// | `max_cached_tenants` | steady-state p99 | RSS | churn p99 |
/// |---|---|---|---|
/// | 16 | 119 ms | 73 MiB | 139 ms |
/// | 32 | 109 ms | 77 MiB | 189 ms |
/// | **64** (§7.2's default) | **4 ms** | 74 MiB | 170 ms |
/// | 128 | 5 ms | 74 MiB | 243 ms |
/// | 256 | 9 ms | 74 MiB | 4 ms |
///
/// **The gate passes at §7.2's documented default.** The real constraint is not
/// the tenant count at all: it is that the bound must be **at least the
/// concurrent working set**, because the bound is a ceiling and RSS is set by
/// what is actually resident. 32 slots thrash with 50 concurrent clients; 64 do
/// not.
///
/// Two things survive from the original finding, and both are worth more than
/// the false one:
///
/// * **A cold tenant returning after idle pays ~170 ms** for pool construction.
///   That is real, and it is the case that would justify making the miss cheap.
/// * **RSS is flat at ~74 MiB across 16 and 256 slots.** The bound is a ceiling,
///   not an allocation, so raising it costs nothing until the pools are genuinely
///   resident — and then it costs ~0.93 MiB a pool.
#[test]
#[ignore = "a load test; run explicitly and record the number with the machine"]
fn p99_within_two_times_the_single_tenant_baseline_across_tenants() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    runtime.block_on(async {
        eprintln!("=== §7.2 load measurement (steady state) ===");
        eprintln!(
            "machine: {} / {} cpus",
            std::env::consts::OS,
            std::num::NonZeroUsize::new(
                std::thread::available_parallelism().map_or(1, |n| n.get())
            )
            .expect("a count")
        );
        eprintln!(
            "shape:   {TENANTS} tenants, {CONCURRENCY} concurrent clients on {PER_CLIENT} \
             requests each, working set = the {CONCURRENCY} tenants the clients touch"
        );

        // 1 tenant, serving the same DAV path. `/ping` is a static string with no
        // resolution, no pool and no router, so a baseline of it measures nothing
        // — the very first version of this harness used one and reported an 8.23×
        // ratio that was almost entirely the baseline being free.
        let (baseline, baseline_rss) =
            run("single-tenant", false, 1, CACHE_UNDER_TEST, false).await;
        eprintln!("baseline (1 tenant, DAV): {}", baseline.summary());
        eprintln!("baseline RSS:            {} MiB", rss_str(baseline_rss));
        let base_p99 = percentile(baseline.latencies_ms.clone(), 0.99) as f64;
        assert!(
            base_p99 > 0.0,
            "the baseline produced no timings; the ratio is meaningless"
        );

        for (cache, expect_pass) in [(DOCUMENTED_CACHE, true), (CACHE_UNDER_TEST, true)] {
            let (multi, multi_rss) =
                run(&format!("cache-{cache}"), true, TENANTS, cache, false).await;
            let multi_p99 = percentile(multi.latencies_ms.clone(), 0.99) as f64;
            let ratio = multi_p99 / base_p99;
            eprintln!("--- {TENANTS} tenants, max_cached_tenants = {cache} ---");
            eprintln!("  {}", multi.summary());
            eprintln!("  RSS: {} MiB", rss_str(multi_rss));
            eprintln!("  p99 ratio: {ratio:.2}x (the gate is 2.00x)");

            assert_eq!(
                multi.errors, 0,
                "{} requests failed; a load number with errors in it is not a latency number",
                multi.errors
            );
            if expect_pass {
                assert!(
                    ratio <= 2.0,
                    "§7.2's gate: in steady state, p99 across {TENANTS} tenants is {ratio:.2}x \
                     the single-tenant DAV baseline ({multi_p99:.0}ms vs {base_p99:.0}ms) with \
                     max_cached_tenants = {cache}.\n\nThe bound must be at least the concurrent \
                     working set ({CONCURRENCY} tenants here), not the tenant count: RSS is set \
                     by what is resident, not by the ceiling."
                );
            }
            if let (Some(b), Some(m)) = (baseline_rss, multi_rss) {
                eprintln!(
                    "  RSS across {} resident pools: {} MiB",
                    TENANTS,
                    m.saturating_sub(b)
                );
            }
        }

        // The finding that survived: a tenant returning after idle.
        let (cold, _rss) = run("churn", true, TENANTS, DOCUMENTED_CACHE, true).await;
        let cold_p99 = percentile(cold.latencies_ms.clone(), 0.99);
        eprintln!("--- churn: the whole fleet touched, then the working set ---");
        eprintln!("  {}", cold.summary());
        eprintln!("  cold-tenant p99: {cold_p99}ms at max_cached_tenants = {DOCUMENTED_CACHE}");
        // Not asserted as a pass or a failure: it is a cost with no agreed budget,
        // and inventing one here would be the same mistake as the original.
        // §7.2 has no target for it; adding one is the owner's call.
        assert!(cold_p99 > 0, "the churn run produced no timings");
    });
}

fn rss_str(v: Option<u64>) -> String {
    v.map_or_else(|| "unknown (not /proc)".to_owned(), |m| m.to_string())
}

/// The per-tenant pool cost §6 A1 asked §7.2 to record.
#[test]
#[ignore = "a load test; run explicitly and record the number with the machine"]
fn the_per_tenant_pool_cost_is_recordable() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let (_, one) = run("pool-cost-1", true, 1, 256, true).await;
        let (_, many) = run("pool-cost-200", true, TENANTS, 256, true).await;
        let (Some(one), Some(many)) = (one, many) else {
            eprintln!("RSS is unavailable on this platform; nothing to record");
            return;
        };
        let per_tenant = many.saturating_sub(one) as f64 / TENANTS as f64;
        eprintln!("=== §6 A1 / §7.2 per-tenant pool cost ===");
        eprintln!("1 tenant:   {one} MiB RSS");
        eprintln!("{TENANTS} tenants: {many} MiB RSS");
        eprintln!("marginal:   {per_tenant:.2} MiB per tenant pool");
        eprintln!("(64 of these are resident at once — max_cached_tenants)");
    });
}
