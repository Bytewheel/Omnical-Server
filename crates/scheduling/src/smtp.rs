//! Minimal async SMTP client with STARTTLS for delivering iMIP messages.
//!
//! Hand-rolled deliberately: the workspace already vendors tokio, rustls
//! (aws-lc provider) and webpki-roots, so this adds no new dependencies or
//! build-time C code compared to pulling in a mail framework.

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};

use crate::config::SmtpAccount;
use crate::error::SchedulingError;
use crate::tls::tls_connector;

/// EHLO hostname, set once at startup from the public base URL. Strict
/// receivers (Postfix `reject_unknown_helo_hostname`, e.g.
/// smtp.novo-ordo.com) reject HELO names that do not resolve in DNS, so a
/// placeholder like `omnical.local` bounces every mail (found live
/// 2026-09-22). "localhost" is the RFC 5321 fallback and always resolves.
static EHLO_NAME: OnceLock<String> = OnceLock::new();

/// Set the EHLO hostname from an absolute base URL (scheme and optional
/// port are stripped). No-op for empty/unparseable input.
pub fn set_ehlo_name_from_url(url: &str) {
    if let Some(host) = url_host(url) {
        let _ = EHLO_NAME.set(host.to_owned());
    }
}

/// Host part of an absolute URL (no scheme, userinfo, port or path).
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(inner) = host.strip_prefix('[') {
        // IPv6 literal: the bracketed address, without brackets/port
        return inner.split(']').next();
    }
    let host = host.split(':').next()?;
    (!host.is_empty()).then_some(host)
}

fn ehlo_name() -> &'static str {
    EHLO_NAME.get().map_or("localhost", String::as_str)
}
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// One SMTP reply (code + all response lines).
#[derive(Debug, Clone)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    fn text(&self) -> String {
        self.lines.join(" / ")
    }
}

async fn read_reply<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Reply, SchedulingError> {
    let mut lines = vec![];
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(SchedulingError::SmtpUnexpectedEof);
        }
        let line = line.trim_end().to_owned();
        // "250-..." continues, "250 ..." terminates
        if line.len() < 4 {
            return Err(SchedulingError::Smtp(format!("malformed reply: {line}")));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| SchedulingError::Smtp(format!("malformed reply code in: {line}")))?;
        let terminator = line.as_bytes()[3];
        lines.push(line[4..].to_owned());
        if terminator == b' ' {
            return Ok(Reply { code, lines });
        }
        // '-' or anything else: more lines follow
    }
}

async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), SchedulingError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    writer
        .write_all(b"\r\n")
        .await
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    // Never log the AUTH PLAIN payload: base64 is not a secret
    // protection. Everything else is protocol noise.
    if line.starts_with("AUTH ") {
        debug!("C: AUTH <redacted>");
    } else {
        debug!("C: {line}");
    }
    Ok(())
}

async fn command<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    line: &str,
) -> Result<Reply, SchedulingError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_line(writer, line).await?;
    let reply = read_reply(reader).await?;
    debug!("S: {} {}", reply.code, reply.text());
    if !reply.is_positive() {
        return Err(SchedulingError::Smtp(format!(
            "SMTP error {} after {line}: {}",
            reply.code,
            reply.text()
        )));
    }
    Ok(reply)
}

/// Dot-stuff a DATA payload and terminate it. Input must already be CRLF-normalized.
fn dot_stuff(message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 8);
    for line in message.split("\r\n") {
        if line.starts_with('.') {
            out.push(b'.');
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Send one email through the given account. `message` is a complete RFC 5322
/// message with CRLF line endings.
#[instrument(fields(from = from, to = to, host = account.host), skip(account, message))]
pub async fn send_mail(
    account: &SmtpAccount,
    from: &str,
    to: &str,
    message: &str,
) -> Result<(), SchedulingError> {
    let future = async move {
        let stream = TcpStream::connect((account.host.as_str(), account.port)).await?;
        send_mail_inner(stream, account, from, to, message).await
    };
    timeout(IO_TIMEOUT * 2, future)
        .await
        .map_err(|_| SchedulingError::Smtp("timed out".to_owned()))?
}

async fn send_mail_inner(
    stream: TcpStream,
    account: &SmtpAccount,
    from: &str,
    to: &str,
    message: &str,
) -> Result<(), SchedulingError> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = writer;

    // Server greeting
    let greeting = read_reply(&mut reader).await?;
    if !greeting.is_positive() {
        return Err(SchedulingError::Smtp(format!(
            "SMTP greeting refused: {}",
            greeting.text()
        )));
    }

    let ehlo = command(&mut reader, &mut writer, &format!("EHLO {}", ehlo_name())).await?;
    let capabilities: Vec<String> = ehlo
        .lines
        .iter()
        .map(|l| l.split(' ').next().unwrap_or_default().to_ascii_uppercase())
        .collect();
    if !capabilities.iter().any(|c| c == "STARTTLS") {
        return Err(SchedulingError::Smtp(format!(
            "server does not advertise STARTTLS (capabilites: {capabilities:?})"
        )));
    }

    // STARTTLS
    command(&mut reader, &mut writer, "STARTTLS").await?;

    let connector = tls_connector();
    let server_name = rustls::pki_types::ServerName::try_from(account.host.clone())
        .map_err(|e| SchedulingError::Smtp(format!("invalid server name: {e}")))?;
    let plain_stream = reader
        .into_inner()
        .reunite(writer)
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    let tls_stream = connector.connect(server_name, plain_stream).await?;
    // Split again through TLS
    let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(tls_reader);
    let mut writer = tls_writer;

    // EHLO again (capabilities inside TLS)
    command(&mut reader, &mut writer, &format!("EHLO {}", ehlo_name())).await?;

    // AUTH PLAIN
    let plain = format!("\x00{}\x00{}", account.username, account.password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());
    command(&mut reader, &mut writer, &format!("AUTH PLAIN {encoded}")).await?;

    // Envelope
    command(&mut reader, &mut writer, &format!("MAIL FROM:<{from}>")).await?;
    command(&mut reader, &mut writer, &format!("RCPT TO:<{to}>")).await?;
    command(&mut reader, &mut writer, "DATA").await?;

    // Payload (dot-stuffed)
    writer
        .write_all(&dot_stuff(message))
        .await
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| SchedulingError::Smtp(e.to_string()))?;
    let reply = read_reply(&mut reader).await?;
    if reply.code != 250 {
        return Err(SchedulingError::Smtp(format!(
            "DATA rejected: {} {}",
            reply.code,
            reply.text()
        )));
    }

    // QUIT (best-effort)
    if let Err(err) = write_line(&mut writer, "QUIT").await {
        warn!("QUIT failed (ignoring): {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuffing() {
        let stuffed = dot_stuff("Subject: x\r\n\r\nLine one\r\n.dot line\r\n..two dots\r\n");
        let as_string = String::from_utf8(stuffed).unwrap();
        assert!(as_string.contains("\r\n..dot line\r\n"));
        assert!(as_string.contains("\r\n...two dots\r\n"));
        assert!(as_string.ends_with(".\r\n"));
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(
            url_host("https://0115d8cf.duckdns.org:8443"),
            Some("0115d8cf.duckdns.org")
        );
        assert_eq!(url_host("https://example.com/"), Some("example.com"));
        assert_eq!(
            url_host("https://user:pass@example.com:8443/x?y#z"),
            Some("example.com")
        );
        assert_eq!(url_host("https://[2001:db8::1]:8443/"), Some("2001:db8::1"));
        assert_eq!(url_host("example.com"), None, "no scheme");
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn ehlo_name_defaults_to_localhost() {
        // A fresh process default; the OnceLock may already be set by an
        // earlier test in the same process, so only assert the fallback
        // when it is unset.
        if EHLO_NAME.get().is_none() {
            assert_eq!(ehlo_name(), "localhost");
        }
    }

    #[test]
    fn set_ehlo_name_from_url_ignores_garbage() {
        // Must not panic and must not overwrite a previously set name.
        let before = EHLO_NAME.get().cloned();
        set_ehlo_name_from_url("not a url");
        assert_eq!(EHLO_NAME.get().cloned(), before);
    }
}
