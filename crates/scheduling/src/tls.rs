//! Shared rustls client connector for the outbound SMTP and inbound IMAP
//! clients (explicit aws-lc-rs provider, webpki roots).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsConnector;

use crate::error::SchedulingError;

fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

fn connector_with_roots(roots: rustls::RootCertStore) -> TlsConnector {
    // Select aws-lc-rs explicitly: the binary's dependency graph enables BOTH
    // rustls crypto providers (ring via other workspace members), which makes
    // the process-level default ambiguous — `ClientConfig::builder()` panics
    // at runtime in that case (found in the item-4 smoke test).
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the safe default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub(crate) fn tls_connector() -> TlsConnector {
    connector_with_roots(webpki_root_store())
}

/// Like [`tls_connector`], but additionally trusting the certificates in
/// the PEM file `extra_ca`.
///
/// For IMAP providers that serve an incomplete chain — e.g.
/// `imap.novo-ordo.com:993` omits its Sectigo intermediate, which rustls
/// rejects as `invalid peer certificate: UnknownIssuer`. The recommended
/// content is the missing intermediate (survives the provider's annual
/// leaf renewals); the webpki roots stay trusted, so a provider-side fix
/// is picked up transparently and unrelated hosts are unaffected. Lines
/// outside `-----BEGIN/END CERTIFICATE-----` sections (e.g. `#`
/// provenance comments) are ignored by the PEM parser.
pub(crate) fn tls_connector_with_extra_ca(
    extra_ca: &Path,
) -> Result<TlsConnector, SchedulingError> {
    let imap_err =
        |msg: String| SchedulingError::Imap(format!("ca file {}: {msg}", extra_ca.display()));
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(extra_ca)
        .map_err(|e| imap_err(format!("cannot read: {e}")))?
        .collect::<Result<_, _>>()
        .map_err(|e| imap_err(format!("cannot parse: {e}")))?;
    if certs.is_empty() {
        return Err(imap_err("no certificates found".to_owned()));
    }
    let mut roots = webpki_root_store();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(imap_err("no usable certificates".to_owned()));
    }
    Ok(connector_with_roots(roots))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn tls_connector_builds_with_explicit_provider() {
        // Regression: with both rustls providers enabled in the binary graph,
        // the implicit-default `ClientConfig::builder()` panics at runtime.
        let _connector = tls_connector();
    }

    /// Throwaway self-signed certificate (CN=localhost, exp. 2054) for
    /// exercising the extra-CA path without network access or live
    /// provider data. Content is irrelevant — only parseability matters.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB6jCCAY+gAwIBAgIUX09rOfepYd2blZGzU6OiyUYHswMwCgYIKoZIzj0EAwIw
STELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRkwFwYDVQQKDBBydXN0aWNhbC10
ZXN0LWNhMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMjYwOTA5MTcxMjAzWhgPMjA1
NDAxMjQxNzEyMDNaMEkxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEZMBcGA1UE
CgwQcnVzdGljYWwtdGVzdC1jYTESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAElIKrMm1bEJld5Gyu+qyWjS0GCBChabGlPdyNbcLq
7NfBBYhP2d5me9nUMpidrSAoEd5Ij/jZoy0tSc4lGKQWYqNTMFEwHQYDVR0OBBYE
FM8vKF3ocEgOFnRWz+gWFDUUMEoaMB8GA1UdIwQYMBaAFM8vKF3ocEgOFnRWz+gW
FDUUMEoaMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKzvlpNP
hESRZHHi4V3wKk9Opa91GcR2DoN0+gvIziLcAiEAhE5tVAIIIPlNV05U71fIBS1u
kqAB/zcdZIfdEKi4o0Q=
-----END CERTIFICATE-----
";

    fn temp_pem(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustical-scheduling-tls-{name}-{}.pem",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn extra_ca_connector_builds_with_valid_pem() {
        let path = temp_pem("valid", TEST_CA_PEM);
        tls_connector_with_extra_ca(&path).unwrap_or_else(|e| panic!("{e}"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn extra_ca_connector_rejects_missing_file() {
        let err =
            tls_connector_with_extra_ca(Path::new("/nonexistent/rustical-scheduling-tls.pem"))
                .err()
                .unwrap();
        assert!(err.to_string().contains("cannot read"), "{err}");
    }

    #[test]
    fn extra_ca_connector_rejects_non_pem_file() {
        let path = temp_pem("garbage", "this file has no certificates\n");
        let err = tls_connector_with_extra_ca(&path).err().unwrap();
        assert!(err.to_string().contains("no certificates found"), "{err}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn extra_ca_connector_tolerates_comment_lines() {
        // The deployed ca file carries `#` provenance comments around the
        // PEM; the parser must skip everything outside BEGIN/END sections.
        let path = temp_pem(
            "commented",
            &format!("# provenance note\n{TEST_CA_PEM}\n# trailing\n"),
        );
        tls_connector_with_extra_ca(&path).unwrap_or_else(|e| panic!("{e}"));
        let _ = fs::remove_file(&path);
    }
}
