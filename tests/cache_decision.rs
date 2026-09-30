//! The §7.2 decision, measured on both sides: what raising the cache costs, and
//! what a miss is actually made of.
//!
//! §7.2's gate fails at `max_cached_tenants = 64` with 200 tenants (§18.24), and
//! §7.2 deliberately does not pick between "raise the bound" and "make the miss
//! cheap" — they have different profiles. Deciding needs two numbers, and neither
//! was in the plan:
//!
//! 1. **The memory curve.** What does the bound cost per slot, and where is the
//!    knee? RSS is not linear in slots, because a SQLite pool costs more than its
//!    file and the allocator's behaviour is part of the answer.
//!
//! 2. **The miss breakdown.** A miss does five things. If one of them is 90% of
//!    the cost, then only that one is worth optimising, and "make the miss cheap"
//!    is a much smaller job than it sounds. If the cost is spread evenly, it is
//!    not worth optimising at all and the bound should just be raised.
//!
//! ```sh
//! cargo test --release --test cache_decision -- --ignored --nocapture --test-threads=1
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantStore as _};

const TENANTS: usize = 200;
const CONCURRENCY: usize = 50;
const PER_CLIENT: usize = 20;
const DAV_PATH: &str = "/.well-known/caldav";

fn percentile(mut s: Vec<u64>, p: f64) -> u64 {
    if s.is_empty() {
        return 0;
    }
    s.sort_unstable();
    let i = ((s.len() as f64 - 1.0) * p).round() as usize;
    s[i.min(s.len() - 1)]
}

fn rss_mib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix("VmRSS:")
            .and_then(|r| r.trim().trim_end_matches(" kB").trim().parse::<u64>().ok())
            .map(|kb| kb / 1024)
    })
}

struct Env {
    _dir: tempfile::TempDir,
    data_root: std::path::PathBuf,
    hosts: Vec<String>,
    control_url: String,
}

async fn seed() -> Env {
    let dir = tempfile::tempdir().expect("a temp dir");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(&data_root).expect("the data directory");
    let control_url = format!("sqlite://{}", dir.path().join("control.sqlite3").display());
    let control = rustical_store_sqlite::SqliteTenantStore::new(
        rustical_store_sqlite::create_control_plane_pool(&control_url, true)
            .await
            .expect("a control plane"),
    );
    let actor = rustical_store::Actor::new("cache-decision").expect("an actor");
    let mut hosts = Vec::with_capacity(TENANTS);
    for n in 0..TENANTS {
        let slug: TenantId = format!("t{n:04}").parse().expect("a valid slug");
        let pool = rustical_store_sqlite::create_db_pool(
            &format!(
                "sqlite://{}",
                data_root
                    .join(format!("{}.sqlite3", slug.as_str()))
                    .display()
            ),
            true,
        )
        .await
        .expect("a tenant store");
        pool.close().await;
        let host = format!("{slug}.load.test");
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
        hosts.push(host);
    }
    Env {
        _dir: dir,
        data_root,
        hosts,
        control_url,
    }
}

/// Boot a server at `max_cached`, returning its address, pid, a handle to kill it
/// with, and the path to its log.
///
/// The log is returned **on purpose**. The first version of this harness booted a
/// server that never became ready and panicked with `the server never became
/// ready at max_cached=16`, which says nothing about why. It was a **config**
/// bug, not a cache bug: the harness wrote `[tracing] level = "warn"`, `Config` is
/// `deny_unknown_fields`, and `TracingConfig` has exactly one field
/// (`opentelemetry`). So the server exited on a parse error — correctly, and
/// exactly as §18.14 requires ("a config key that is accepted and does nothing is
/// worse than a missing one").
///
/// The fix is one line of config. The lesson is that a harness which panics
/// without showing the log will cost the next person an hour, so it dumps it.
async fn boot(
    env: &Env,
    max_cached: usize,
) -> (String, u32, std::process::Child, std::path::PathBuf) {
    let dir = env._dir.path();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        l.local_addr().expect("an address").port()
    };
    let mut config = format!(
        "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
         [data_store.sqlite]\ndb_url = \"{}\"\nrun_repairs = false\nskip_broken = false\n\n\
         [frontend]\nenabled = true\nallow_password_login = true\n\n\
         [tenancy]\nenabled = true\ncontrol_db_url = \"{}\"\nbase_domain = \"load.test\"\n\
         default_tenant = \"\"\nmax_cached_tenants = {max_cached}\ndata_root = \"{}\"\n",
        dir.join("data").join("db.sqlite3").display(),
        env.control_url,
        env.data_root.display(),
    );
    // No `[tracing] level` — see the doc comment above. `TracingConfig` has one
    // field and this is not it.
    let _ = &mut config;

    let config_path = dir.join(format!("config-{max_cached}.toml"));
    std::fs::write(&config_path, config).expect("the config");
    let log_path = dir.join(format!("server-{max_cached}.log"));
    let log = std::fs::File::create(&log_path).expect("log");
    let err = log.try_clone().expect("a second handle");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_rustical"))
        .arg("--config-file")
        .arg(&config_path)
        .arg("serve")
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .expect("the server starts");
    let pid = child.id();

    let addr = format!("127.0.0.1:{port}");
    let probe = reqwest::Client::new();
    for _ in 0..300 {
        if probe
            .get(format!("http://{addr}/healthz"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return (addr, pid, child, log_path);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    panic!(
        "the server never became ready at max_cached={max_cached}\n\
         --- {} ---\n{log}\n--- end ---",
        log_path.display()
    );
}

/// Steady-state p99 plus RSS at one cache size.
async fn measure(cache: usize, tenants: usize, warm_all: bool) -> (u64, Option<u64>, u64) {
    let env = seed().await;
    let (addr, pid, mut child, _log) = boot(&env, cache).await;
    let socket: std::net::SocketAddr = addr.parse().expect("an address");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("a client");

    // **Warm the working set, not the whole fleet.**
    //
    // The first version of this harness warmed all `tenants` (0..200) and then
    // measured clients spread over `tenants[..CONCURRENCY]` — i.e. tenants 0..49.
    // At `max_cached = 64` the warmup left tenants 136..199 in the LRU, so **every
    // tenant the measurement then touched had just been evicted**: 50 cold
    // requests out of 1000, which is 5%, which is exactly where p95 and p99 live.
    //
    // That produced the 6.7x figure recorded in §7.2 and §18.24, and it was an
    // artefact of the harness, not a property of the cache. "Steady state" means
    // the working set is resident, so the warmup has to be the working set.
    //
    // Both cases are real and both are measured below, separately:
    //   * `WARM_WORKING_SET` — steady state. This is what the gate means.
    //   * `WARM_ALL`         — after churn: the whole fleet was touched, so the
    //                          cache holds the *last* `max_cached` of them. This
    //                          is what a real deployment looks like when a tenant
    //                          nobody has used for hours comes back, and it is a
    //                          genuinely different question.
    let warm: Vec<&String> = if warm_all {
        env.hosts.iter().take(tenants).collect()
    } else {
        let working = CONCURRENCY.min(tenants);
        env.hosts.iter().take(working).collect()
    };
    for host in warm {
        let _ = client
            .get(format!("http://{addr}{DAV_PATH}"))
            .header("Host", host)
            .send()
            .await;
    }

    let stats = Arc::new(Mutex::new(Vec::<u64>::new()));
    let errors = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for c in 0..CONCURRENCY {
        let host = env.hosts[c % tenants].clone();
        let stats = Arc::clone(&stats);
        let errors = Arc::clone(&errors);
        let url = format!("http://{addr}{DAV_PATH}");
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..PER_CLIENT {
                let t = Instant::now();
                match client.get(&url).header("Host", &host).send().await {
                    Ok(r) => {
                        let _ = r.bytes().await;
                        stats
                            .lock()
                            .expect("lock")
                            .push(t.elapsed().as_millis() as u64);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let _ = socket;
    let rss = rss_mib(pid);
    // Kill *and reap*. `mem::forget(child)` in the first version leaked the handle,
    // so a panic in the readiness loop would leave a 200-tenant server running for
    // the rest of the sweep — five of them, each with its own pools.
    let _ = child.kill();
    let _ = child.wait();
    let lat = Arc::try_unwrap(stats)
        .map(|m| m.into_inner().expect("lock"))
        .unwrap_or_else(|a| a.lock().expect("lock").clone());
    (percentile(lat, 0.99), rss, errors.load(Ordering::SeqCst))
}

/// **The memory curve**, in steady state, plus the churn case separately.
#[test]
#[ignore = "a load measurement; run explicitly and record the machine"]
fn the_memory_cost_of_the_cache_bound() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        eprintln!("=== §7.2: what raising the bound costs ===");
        eprintln!("{TENANTS} tenants, {CONCURRENCY} clients, {PER_CLIENT} requests each");
        eprintln!("working set = the {CONCURRENCY} tenants the clients touch\n");
        eprintln!(
            "{:>7}  {:>8}  {:>9}  {:>13}  {:>12}",
            "slots", "p99 ms", "RSS MiB", "MiB / slot", "p99 churn"
        );

        let mut previous: Option<(usize, u64)> = None;
        for cache in [16usize, 32, 64, 128, 256] {
            let (p99, rss, errors) = measure(cache, TENANTS, false).await;
            assert_eq!(errors, 0, "{errors} errors at {cache} slots");
            let rss_v = rss.unwrap_or(0);
            let per_slot = match (previous, rss) {
                (Some((prev_slots, prev_rss)), Some(_)) if cache > prev_slots => {
                    format!(
                        "{:>8.2}",
                        (rss_v.saturating_sub(prev_rss)) as f64 / (cache - prev_slots) as f64
                    )
                }
                _ => "-".to_owned(),
            };
            // The churn case, once per size: the whole fleet touched, then the
            // working set measured — so every measured tenant was evicted first.
            let (churn_p99, _, _) = measure(cache, TENANTS, true).await;
            eprintln!("{cache:>7}  {p99:>8}  {rss_v:>9}  {per_slot:>13}  {churn_p99:>8} ms");
            previous = Some((cache, rss_v));
        }

        eprintln!("\nThe two p99 columns answer different questions:");
        eprintln!("  steady  — the working set is resident, which is what \"p99 within 2x the");
        eprintln!("            single-tenant baseline\" means, and what §7.2's gate is about.");
        eprintln!("  churn   — the whole fleet was touched first, so the cache holds only the");
        eprintln!("            last `slots` of it. This is a cold tenant coming back after");
        eprintln!("            hours idle, and it is the case the original 6.7x figure measured");
        eprintln!("            while comparing it against a steady-state baseline.");
        eprintln!("\nMiB/slot is the *marginal* cost between consecutive rows, and it is the");
        eprintln!("number that decides whether a bound can be raised.");
    });
}
