use crate::config::{HttpBindConfig, HttpConfig};
use anyhow::{Context, Result, bail};
use clap::Parser;
use http::Method;

#[derive(Parser, Debug, Default)]
pub struct HealthArgs {}

/// Healthcheck for running rustical instance
/// Currently just pings to see if it's reachable via HTTP
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_health(http_config: HttpConfig, _health_args: HealthArgs) -> Result<()> {
    let bind_config = http_config.bind_config()?;
    let mut client_builder = reqwest::ClientBuilder::new();

    let address = match bind_config {
        HttpBindConfig::Tcp(address) => address,
        HttpBindConfig::Unix(path) => {
            client_builder = client_builder.unix_socket(path);
            "rustical".to_string()
        }
    };
    let client = client_builder.build()?;

    let endpoint = format!("http://{address}/ping").parse().unwrap();
    let request = reqwest::Request::new(Method::GET, endpoint);

    // A failed probe is an *error*, not a panic. This command is the health
    // check for the Docker image (rustical/Dockerfile:60), for `deploy.sh`'s
    // post-deploy gate on the router, and for `packaging/native/install.sh` —
    // so "not up yet" is an ordinary expected answer that every one of those
    // callers retries in a loop. It used to `assert!`, which printed a Rust
    // backtrace and an "Aborted (core dumped)" line into all of those logs on
    // the *first* attempt and made a normal startup look like a crash. Found by
    // the §8.1 self-host gate, which polls in a loop and had been hiding it
    // behind 2>/dev/null.
    let response = client
        .execute(request)
        .await
        .with_context(|| format!("health check: could not reach http://{address}/ping"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("health check: http://{address}/ping answered {status}");
    }

    Ok(())
}
