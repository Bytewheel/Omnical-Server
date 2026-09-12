//! Minimal async IMAP4rev1 client (implicit TLS) for polling iMIP replies.
//!
//! Hand-rolled like [`crate::smtp`]: the workspace already vendors tokio,
//! rustls (aws-lc provider) and webpki-roots, so this adds no new
//! dependencies. Only the subset the ingestion loop needs is implemented:
//!
//! * greeting + `AUTHENTICATE PLAIN` (SASL-IR with `+`-continuation fallback,
//!   then `LOGIN` as last resort),
//! * `SELECT` (UIDVALIDITY/EXISTS),
//! * `UID SEARCH OR UNSEEN SINCE <date>` — unseen mail plus a ~3-day
//!   recheck window, so replies read (flagged `\Seen`) by the user's
//!   normal mail client before a poll saw them are still candidates,
//! * `UID FETCH … (BODY.PEEK[])` — literal framing included, oversized
//!   messages are streamed to /dev/null to keep the session in sync,
//! * `UID STORE … +FLAGS.SILENT (\Seen)`,
//! * `LOGOUT`.

use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{debug, instrument};

use crate::config::ImapAccount;
use crate::error::SchedulingError;
use crate::tls::{tls_connector, tls_connector_with_extra_ca};

/// Whole-poll deadline (connect through LOGOUT); a stuck session is
/// dropped and retried on the next cycle.
pub(crate) const SESSION_TIMEOUT: Duration = Duration::from_secs(90);
/// Recheck window for the ingest search: mail read (flagged `\Seen`) by
/// the user's normal mail client before a poll saw it stays a candidate
/// for this many days after arrival, closing the UNSEEN-only race
/// between the mail client and the poll loop.
const RECHECK_WINDOW_DAYS: i64 = 3;
/// Largest message body buffered; larger ones are downloaded and discarded.
const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const DISCARD_CHUNK: usize = 64 * 1024;

/// The mailbox view of one `UID FETCH` result.
#[derive(Debug)]
pub struct FetchedMessage {
    pub uid: u32,
    pub data: Vec<u8>,
    /// Message larger than [`MAX_MESSAGE_BYTES`]; `data` is empty.
    pub oversize: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MailboxStatus {
    pub uidvalidity: u32,
    pub exists: u32,
}

/// One "response unit": a line plus, when the server announced a
/// `{N}` literal, the literal bytes (or an oversize marker). The line
/// closing the literal is consumed but not kept (nothing needs it).
#[derive(Debug)]
struct Unit {
    text: String,
    literal: Option<Vec<u8>>,
    oversize: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Status {
    Ok,
    No,
    Bad,
}

pub type Session = ImapSession<
    tokio::io::ReadHalf<TlsStream<TcpStream>>,
    tokio::io::WriteHalf<TlsStream<TcpStream>>,
>;

pub struct ImapSession<R, W> {
    reader: BufReader<R>,
    writer: W,
    tag_counter: u32,
}

/// Connect to `account` over implicit TLS and read the greeting.
#[instrument(fields(host = account.host), skip(account))]
pub async fn connect(account: &ImapAccount) -> Result<Session, SchedulingError> {
    let stream = TcpStream::connect((account.host.as_str(), account.port)).await?;
    let server_name = rustls::pki_types::ServerName::try_from(account.host.clone())
        .map_err(|e| SchedulingError::Imap(format!("invalid server name: {e}")))?;
    // Webpki roots, plus the account's pinned extra anchors (for providers
    // serving an incomplete chain) when `ca_file` is configured.
    let connector = match &account.ca_file {
        Some(ca_file) => tls_connector_with_extra_ca(ca_file)?,
        None => tls_connector(),
    };
    let tls_stream = connector.connect(server_name, stream).await?;

    let (reader, writer) = tokio::io::split(tls_stream);
    let mut session = Session {
        reader: BufReader::new(reader),
        writer,
        tag_counter: 1,
    };

    let greeting = read_line(&mut session.reader).await?;
    if !greeting.starts_with("* OK") {
        return Err(SchedulingError::Imap(format!(
            "unexpected greeting: {}",
            truncate(&greeting)
        )));
    }
    Ok(session)
}

impl<R, W> ImapSession<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Log a command without ever leaking credentials: AUTHENTICATE/LOGIN
    /// payloads are replaced with `<redacted>`.
    fn redacted(cmd: &str) -> String {
        let first = cmd.split(' ').next().unwrap_or("");
        if matches!(first, "AUTHENTICATE" | "LOGIN") {
            format!("{first} <redacted>")
        } else {
            truncate(cmd)
        }
    }

    async fn write_line(&mut self, line: &str) -> Result<(), SchedulingError> {
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| SchedulingError::Imap(e.to_string()))?;
        self.writer
            .write_all(b"\r\n")
            .await
            .map_err(|e| SchedulingError::Imap(e.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|e| SchedulingError::Imap(e.to_string()))?;
        Ok(())
    }

    fn next_tag(&mut self) -> String {
        let tag = format!("a{}", self.tag_counter);
        self.tag_counter += 1;
        tag
    }

    /// Run `cmd` to completion, returning the untagged units and the final
    /// status line.
    async fn command(&mut self, cmd: &str) -> Result<(Vec<Unit>, Status, String), SchedulingError> {
        let tag = self.next_tag();
        debug!("IMAP C: {} {}", tag, Self::redacted(cmd));
        self.write_line(&format!("{tag} {cmd}")).await?;
        let (units, status, text) = self.read_response(&tag, None).await?;
        debug!("IMAP S: {tag} {status:?} {}", truncate(&text));
        Ok((units, status, text))
    }

    /// Run `cmd` and require an `OK`.
    async fn command_ok(&mut self, cmd: &str) -> Result<Vec<Unit>, SchedulingError> {
        let (units, status, text) = self.command(cmd).await?;
        match status {
            Status::Ok => Ok(units),
            Status::No | Status::Bad => Err(SchedulingError::Imap(format!(
                "{} failed: {}",
                Self::redacted(cmd),
                text
            ))),
        }
    }

    /// Read units until the tagged completion line for `tag` arrives.
    /// `first` allows an already-read line to seed the first unit (the
    /// `+` continuation of AUTHENTICATE).
    async fn read_response(
        &mut self,
        tag: &str,
        first: Option<String>,
    ) -> Result<(Vec<Unit>, Status, String), SchedulingError> {
        let mut units: Vec<Unit> = vec![];
        let mut first = first;
        loop {
            let line = match first.take() {
                Some(line) => line,
                None => read_line(&mut self.reader).await?,
            };
            if let Some(rest) = line.strip_prefix(tag).and_then(|r| r.strip_prefix(' ')) {
                let (status_word, text) = rest.split_once(' ').map_or((rest, ""), |(w, t)| (w, t));
                let status = match status_word.to_ascii_uppercase().as_str() {
                    "OK" => Status::Ok,
                    "NO" => Status::No,
                    _ => Status::Bad,
                };
                return Ok((units, status, text.to_owned()));
            }
            if line.starts_with('+') {
                // AUTHENTICATE continuation — the caller handles this case
                // before calling read_response; treat as protocol error here.
                return Err(SchedulingError::Imap(format!(
                    "unexpected continuation: {}",
                    truncate(&line)
                )));
            }
            let unit = self.read_unit(line).await?;
            debug!(
                "IMAP S: {}{}",
                truncate(&unit.text),
                unit.literal
                    .as_ref()
                    .map_or_else(String::new, |l| format!(" (+{} bytes)", l.len()))
            );
            units.push(unit);
        }
    }

    /// Read one unit whose first line was already consumed (`line`): if the
    /// line ends with a `{N}` literal marker, consume exactly N bytes (or
    /// discard them when oversize) and the closing line.
    async fn read_unit(&mut self, line: String) -> Result<Unit, SchedulingError> {
        let Some(size) = literal_size(&line) else {
            return Ok(Unit {
                text: line,
                literal: None,
                oversize: false,
            });
        };

        let oversize = size > MAX_MESSAGE_BYTES;
        let mut data: Vec<u8> = Vec::with_capacity(if oversize { 0 } else { size });
        let mut remaining = size;
        let mut chunk = [0_u8; DISCARD_CHUNK];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            self.reader
                .read_exact(&mut chunk[..want])
                .await
                .map_err(SchedulingError::Io)?;
            if !oversize {
                data.extend_from_slice(&chunk[..want]);
            }
            remaining -= want;
        }

        // The line closing the FETCH list (usually `)`)
        if read_line(&mut self.reader).await.is_err() {
            // EOF right after the literal: the tags completion line is gone;
            // the caller's next read will surface the error. Not fatal here.
        }

        Ok(Unit {
            text: line,
            literal: if oversize { None } else { Some(data) },
            oversize,
        })
    }

    /// Authenticate. Tries `AUTHENTICATE PLAIN` (SASL-IR, with a
    /// `+`-continuation fallback for servers without SASL-IR) and falls
    /// back to quoted `LOGIN`.
    pub async fn login(&mut self, account: &ImapAccount) -> Result<(), SchedulingError> {
        let plain = format!("\0{}\0{}", account.username, account.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());

        let tag = self.next_tag();
        debug!("IMAP C: {tag} AUTHENTICATE <redacted>");
        self.write_line(&format!("{tag} AUTHENTICATE PLAIN {encoded}"))
            .await?;

        // First reply: either the tagged status (SASL-IR accepted/rejected)
        // or `+` asking for the initial response.
        let first = read_line(&mut self.reader).await?;
        let (_units, status, text) = if first.starts_with('+') {
            self.write_line(&encoded).await?;
            self.read_response(&tag, None).await?
        } else {
            self.read_response(&tag, Some(first)).await?
        };
        match status {
            Status::Ok => return Ok(()),
            Status::No | Status::Bad => {
                debug!("IMAP AUTHENTICATE PLAIN rejected: {}", truncate(&text));
            }
        }

        // LOGIN fallback (safe over TLS)
        let user = quote_imap_string(&account.username);
        let pass = quote_imap_string(&account.password);
        self.command_ok(&format!("LOGIN {user} {pass}"))
            .await
            .map(|_| ())
    }

    /// `SELECT` a mailbox, returning its UIDVALIDITY and EXISTS count.
    pub async fn select(&mut self, mailbox: &str) -> Result<MailboxStatus, SchedulingError> {
        let units = self
            .command_ok(&format!("SELECT {}", quote_imap_string(mailbox)))
            .await?;
        let mut status = MailboxStatus::default();
        for unit in &units {
            if let Some(v) = parse_uidvalidity(&unit.text) {
                status.uidvalidity = v;
            }
            if let Some(v) = parse_exists(&unit.text) {
                status.exists = v;
            }
        }
        Ok(status)
    }

    /// UIDs of the messages to examine this poll: everything currently
    /// flagged `\Unseen`, plus everything that arrived within
    /// [`RECHECK_WINDOW_DAYS`] regardless of `\Seen` — a mail client may
    /// read (and flag) a reply before a poll sees it, and an UNSEEN-only
    /// search would then miss it permanently.
    pub async fn uid_search_unseen(&mut self) -> Result<Vec<u32>, SchedulingError> {
        let since = recheck_since_date(chrono::Utc::now().date_naive());
        let units = self
            .command_ok(&format!("UID SEARCH OR UNSEEN SINCE {since}"))
            .await?;
        for unit in &units {
            if let Some(uids) = parse_search_uids(&unit.text) {
                return Ok(uids);
            }
        }
        Ok(vec![])
    }

    /// Fetch full bodies without setting `\Seen` (BODY.PEEK).
    pub async fn uid_fetch_peek(
        &mut self,
        uids: &[u32],
    ) -> Result<Vec<FetchedMessage>, SchedulingError> {
        if uids.is_empty() {
            return Ok(vec![]);
        }
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let units = self
            .command_ok(&format!("UID FETCH {set} (BODY.PEEK[])"))
            .await?;
        Ok(units
            .into_iter()
            .filter_map(|unit| {
                parse_fetch_uid(&unit.text).map(|uid| FetchedMessage {
                    uid,
                    data: unit.literal.unwrap_or_default(),
                    oversize: unit.oversize,
                })
            })
            .collect())
    }

    /// Flag one message as `\Seen`.
    pub async fn uid_mark_seen(&mut self, uid: u32) -> Result<(), SchedulingError> {
        self.command_ok(&format!("UID STORE {uid} +FLAGS.SILENT (\\Seen)"))
            .await
            .map(|_| ())
    }

    /// Politely end the session. Errors are ignored — servers may close the
    /// connection immediately after `* BYE`.
    pub async fn logout(&mut self) {
        let _ = self.command("LOGOUT").await;
    }
}

/// Read one line, stripping the trailing CRLF/LF. Errors on EOF.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<String, SchedulingError> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(SchedulingError::Imap(
            "connection closed unexpectedly".to_owned(),
        ));
    }
    let stripped = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(&line);
    Ok(stripped.to_owned())
}

fn truncate(text: &str) -> String {
    const MAX: usize = 120;
    if text.len() > MAX {
        let mut cut = MAX;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &text[..cut])
    } else {
        text.to_owned()
    }
}

/// If a response line ends with a literal marker `{N}` / `{N+}` (RFC 3501
/// 7.4.2 / RFC 7888), the literal's byte count.
fn literal_size(line: &str) -> Option<usize> {
    if !line.ends_with('}') {
        return None;
    }
    let open = line.rfind('{')?;
    let digits = &line[open + 1..line.len() - 1];
    let digits = digits.strip_suffix('+').unwrap_or(digits);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The RFC 3501 `date` (`dd-Mon-yyyy`, zero-padded day — valid
/// `date-day-fixed`) for the start of the ingest recheck window:
/// `today - RECHECK_WINDOW_DAYS`. Pure so unit tests can pin it to
/// fixed dates; `SINCE` compares against INTERNALDATE.
fn recheck_since_date(today: chrono::NaiveDate) -> String {
    (today - chrono::Duration::days(RECHECK_WINDOW_DAYS))
        .format("%d-%b-%Y")
        .to_string()
}

/// UIDs from `* SEARCH 1 2 3` (also `* SEARCH` with no hits → empty).
fn parse_search_uids(text: &str) -> Option<Vec<u32>> {
    let rest = text.strip_prefix("* SEARCH")?;
    Some(
        rest.split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect(),
    )
}

/// The UID item from a `* <seq> FETCH (… UID 42 …)` line. `UID` must be a
/// standalone word (paren or space boundary) so that `UIDNEXT` or
/// `RFC822.SIZE` values never shadow it.
fn parse_fetch_uid(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    let mut idx = 0;
    while let Some(pos) = text[idx..].find("UID").map(|p| idx + p) {
        let after = pos + "UID".len();
        let boundary_before = pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric();
        let space_after = after < bytes.len() && bytes[after].is_ascii_whitespace();
        if boundary_before && space_after {
            let digits: String = text[after..]
                .trim_start()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(uid) = digits.parse() {
                return Some(uid);
            }
        }
        idx = after;
    }
    None
}

/// UIDVALIDITY from `* OK [UIDVALIDITY 123] …`.
fn parse_uidvalidity(text: &str) -> Option<u32> {
    let pos = text.find("UIDVALIDITY ")?;
    let digits: String = text[pos + "UIDVALIDITY ".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Message count from `* 17 EXISTS`.
fn parse_exists(text: &str) -> Option<u32> {
    let rest = text.strip_prefix('*')?.trim_end();
    let rest = rest.strip_suffix("EXISTS")?.trim_end();
    rest.trim().parse().ok()
}

/// Quote an IMAP string (formal syntax `astring`/`quoted`), escaping
/// backslashes and double quotes.
fn quote_imap_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // ---- pure parsing helpers --------------------------------------------

    #[test]
    fn literal_sizes() {
        assert_eq!(literal_size("* 4 FETCH (UID 4 BODY[] {123}"), Some(123));
        assert_eq!(literal_size("* 4 FETCH (UID 4 BODY[] {123+}"), Some(123));
        assert_eq!(literal_size("* 4 FETCH (UID 4 BODY[]"), None);
        assert_eq!(literal_size("{x}"), None);
        assert_eq!(literal_size("{}"), None);
    }

    #[test]
    fn search_uids() {
        assert_eq!(parse_search_uids("* SEARCH 4 9 17"), Some(vec![4, 9, 17]));
        assert_eq!(parse_search_uids("* SEARCH"), Some(vec![]));
        assert_eq!(parse_search_uids("* FLAGS (\\Seen)"), None);
    }

    #[test]
    fn recheck_window_dates() {
        fn date(y: i32, m: u32, d: u32) -> chrono::NaiveDate {
            chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap()
        }
        // Window start is today - 3 days, as RFC 3501 dd-Mon-yyyy.
        assert_eq!(recheck_since_date(date(2026, 9, 9)), "06-Sep-2026");
        // Single-digit day must be zero-padded.
        assert_eq!(recheck_since_date(date(2026, 9, 12)), "09-Sep-2026");
        // Month rollover: 2026-09-03 - 3 = 2026-08-31.
        assert_eq!(recheck_since_date(date(2026, 9, 3)), "31-Aug-2026");
        // Year rollover: 2027-01-02 - 3 = 2026-12-30.
        assert_eq!(recheck_since_date(date(2027, 1, 2)), "30-Dec-2026");
        // Leap year: 2028-03-01 - 3 = 2028-02-27 (Feb has 29 days).
        assert_eq!(recheck_since_date(date(2028, 3, 1)), "27-Feb-2028");
        // All twelve RFC 3501 month abbreviations (chrono %b is English,
        // always 3 letters).
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        for (month_num, month) in (1_u32..=12).zip(MONTHS) {
            // Mid-month day so the window never rolls over.
            assert_eq!(
                recheck_since_date(date(2026, month_num, 15)),
                format!("12-{month}-2026"),
                "month {month_num}"
            );
        }
    }

    #[test]
    fn fetch_uid_parsing() {
        assert_eq!(parse_fetch_uid("* 4 FETCH (UID 4 BODY[] {12})"), Some(4));
        assert_eq!(
            parse_fetch_uid("* 9 FETCH (FLAGS () UID 9 BODY[] {3})"),
            Some(9)
        );
        assert_eq!(parse_fetch_uid("* 4 FETCH (BODY[] {12})"), None);
        // UID inside RFC822.SIZE must not shadow the UID item
        assert_eq!(
            parse_fetch_uid("* 1 FETCH (UID 42 RFC822.SIZE 4242 BODY[] {9})"),
            Some(42)
        );
        // UIDNEXT-like words are not the UID item
        assert_eq!(parse_fetch_uid("* OK [UIDNEXT 18]"), None);
    }

    #[test]
    fn uidvalidity_and_exists() {
        assert_eq!(
            parse_uidvalidity("* OK [UIDVALIDITY 3857529045] UIDs valid"),
            Some(3_857_529_045)
        );
        assert_eq!(parse_exists("* 17 EXISTS"), Some(17));
        assert_eq!(parse_exists("* OK [UIDNEXT 18]"), None);
    }

    #[test]
    fn imap_string_quoting() {
        assert_eq!(quote_imap_string("in\"box"), "\"in\\\"box\"");
        assert_eq!(quote_imap_string("back\\slash"), "\"back\\\\slash\"");
    }

    // ---- fake-server session tests ----------------------------------------

    type TestSession = ImapSession<
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    >;

    /// Drive a session against a scripted server over an in-memory pipe,
    /// proving the protocol framing (tags, literals, tagged completion).
    /// `{tag}` in each script entry is replaced with the client's tag; the
    /// server sends one scripted reply per command line. The first script
    /// entry is the greeting and is consumed here — the tests skip
    /// [`connect`], which would otherwise read it.
    async fn with_session(script: &[String]) -> TestSession {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let script: Vec<String> = script.to_vec();
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut reader = BufReader::new(read);
            let mut lines = script.into_iter();
            // Greeting first
            let greeting = lines.next().unwrap_or_default();
            write.write_all(greeting.as_bytes()).await.unwrap();
            write.write_all(b"\r\n").await.unwrap();
            // Then one scripted reply per command
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if line.contains("LOGOUT") {
                    break;
                }
                let tag = line.split(' ').next().unwrap_or("").to_owned();
                let reply = lines.next().unwrap_or_else(|| format!("{tag} OK"));
                let reply = reply.replace("{tag}", &tag);
                write.write_all(reply.as_bytes()).await.unwrap();
                write.write_all(b"\r\n").await.unwrap();
                if reply.starts_with('+') {
                    // AUTHENTICATE continuation: consume the client's SASL
                    // response line, then send the completion status
                    let mut sasl_response = String::new();
                    reader.read_line(&mut sasl_response).await.unwrap();
                    let completion = lines.next().unwrap_or_else(|| format!("{tag} OK"));
                    let completion = completion.replace("{tag}", &tag);
                    write.write_all(completion.as_bytes()).await.unwrap();
                    write.write_all(b"\r\n").await.unwrap();
                }
            }
        });

        let (r, w) = tokio::io::split(client);
        let mut session = ImapSession {
            reader: BufReader::new(r),
            writer: w,
            tag_counter: 1,
        };
        let mut greeting = String::new();
        session.reader.read_line(&mut greeting).await.unwrap();
        assert!(
            greeting.starts_with("* OK"),
            "script must start with a greeting, got: {greeting:?}"
        );
        session
    }

    fn account() -> ImapAccount {
        ImapAccount {
            identity: "a@example.com".to_owned(),
            host: "imap.example.com".to_owned(),
            port: 993,
            username: "user".to_owned(),
            password: "pass".to_owned(),
            mailbox: "INBOX".to_owned(),
            mark_seen: true,
            ca_file: None,
        }
    }

    #[tokio::test]
    async fn full_session_flow() {
        // The {tag} placeholders are filled with the client's tag.
        let mut session = with_session(&[
            "* OK ready".to_owned(),
            "{tag} OK Logged in".to_owned(),
            "* 2 EXISTS\r\n* OK [UIDVALIDITY 42] UIDs valid\r\n{tag} OK [READ-WRITE] SELECT"
                .to_owned(),
            "* SEARCH 4 9\r\n{tag} OK Search done".to_owned(),
            // One reply per command: both FETCH responses plus the tagged
            // completion belong to the single `UID FETCH 4,9` round trip.
            // The `{N}` literal marker ends the response line; the `)`
            // closing the FETCH list only arrives after the literal.
            "* 4 FETCH (UID 4 BODY[] {15}\r\nHello, world!\r\n)\r\n\
             * 9 FETCH (UID 9 BODY[] {5}\r\nBYTES\r\n)\r\n{tag} OK Fetch done"
                .to_owned(),
            "{tag} OK Store done".to_owned(),
        ])
        .await;

        session.login(&account()).await.unwrap();
        let status = session.select("INBOX").await.unwrap();
        assert_eq!((status.uidvalidity, status.exists), (42, 2));

        let uids = session.uid_search_unseen().await.unwrap();
        assert_eq!(uids, vec![4, 9]);

        let messages = session.uid_fetch_peek(&uids).await.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].uid, 4);
        assert_eq!(messages[0].data, b"Hello, world!\r\n");
        assert_eq!(messages[1].uid, 9);
        assert_eq!(messages[1].data, b"BYTES");

        session.uid_mark_seen(4).await.unwrap();
        session.logout().await;
    }

    /// Capture what the client actually sends: the search must be
    /// `UID SEARCH OR UNSEEN SINCE <dd-Mon-yyyy>` so read-but-recent
    /// replies (flagged `\Seen` by a mail client between polls) stay
    /// candidates — regression for the UNSEEN-only race.
    #[tokio::test]
    async fn search_command_covers_recheck_window() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(client);
        let mut session = ImapSession {
            reader: BufReader::new(r),
            writer: w,
            tag_counter: 1,
        };
        let (server_read, mut server_write) = tokio::io::split(server);
        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(server_read);
            let mut cmd = String::new();
            reader.read_line(&mut cmd).await.unwrap();
            let tag = cmd.split(' ').next().unwrap_or("").to_owned();
            server_write.write_all(b"* SEARCH\r\n").await.unwrap();
            server_write
                .write_all(format!("{tag} OK Search done\r\n").as_bytes())
                .await
                .unwrap();
            cmd
        });

        // Empty result is fine here — only the command matters.
        assert!(session.uid_search_unseen().await.unwrap().is_empty());
        let cmd = server.await.unwrap();
        let cmd = cmd.trim_end();
        assert!(
            cmd.starts_with("a1 UID SEARCH OR UNSEEN SINCE "),
            "got: {cmd}"
        );
        let date = cmd.rsplit(' ').next().unwrap();
        // A real dd-Mon-yyyy date that round-trips through chrono…
        let parsed = chrono::NaiveDate::parse_from_str(date, "%d-%b-%Y")
            .unwrap_or_else(|e| panic!("bad date {date:?}: {e}"));
        assert_eq!(parsed.format("%d-%b-%Y").to_string(), date);
        // …and within the window (2–4 days back tolerates a UTC-midnight
        // flip between the command and this assertion).
        let age = (chrono::Utc::now().date_naive() - parsed).num_days();
        assert!((2..=4).contains(&age), "age {age} days from {date}");
    }

    #[tokio::test]
    async fn login_falls_back_to_login_command() {
        // Server rejects AUTHENTICATE PLAIN, accepts LOGIN
        let mut session = with_session(&[
            "* OK ready".to_owned(),
            "{tag} NO Unsupported authentication mechanism".to_owned(),
            "{tag} OK Logged in".to_owned(),
        ])
        .await;
        session.login(&account()).await.unwrap();
    }

    #[tokio::test]
    async fn login_handles_continuation() {
        // Old-school server without SASL-IR: challenges with `+ `
        let mut session = with_session(&[
            "* OK ready".to_owned(),
            "+ ".to_owned(),
            "{tag} OK Logged in".to_owned(),
        ])
        .await;
        session.login(&account()).await.unwrap();
    }

    #[tokio::test]
    async fn oversize_literal_is_discarded_and_session_stays_in_sync() {
        // A message larger than MAX_MESSAGE_BYTES: the client must stream
        // the literal to the void and still parse everything after it.
        let oversize = MAX_MESSAGE_BYTES + 1;
        let mut payload = String::with_capacity(oversize);
        for _ in 0..=oversize / 4096 {
            payload.push_str(&"x".repeat(4096));
        }
        let payload = &payload[..oversize];
        assert_eq!(payload.len(), oversize);

        let mut session = with_session(&[
            "* OK ready".to_owned(),
            "{tag} OK Logged in".to_owned(),
            "* 1 EXISTS\r\n* OK [UIDVALIDITY 7]\r\n{tag} OK SELECT".to_owned(),
            "* SEARCH 4\r\n{tag} OK".to_owned(),
            format!(
                "* 4 FETCH (UID 4 BODY[] {{{}}}\r\n{payload})\r\n{{tag}} OK",
                oversize
            ),
            "{tag} OK".to_owned(),
        ])
        .await;

        session.login(&account()).await.unwrap();
        session.select("INBOX").await.unwrap();
        let uids = session.uid_search_unseen().await.unwrap();
        assert_eq!(uids, vec![4]);

        let messages = session.uid_fetch_peek(&uids).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].oversize);
        assert!(messages[0].data.is_empty());

        // The session is still usable afterwards (sync proven)
        session.uid_mark_seen(4).await.unwrap();
    }

    // ---- live connect() regression ------------------------------------------

    /// `Sectigo RSA Domain Validation Secure Server CA`, the intermediate
    /// that `imap.novo-ordo.com:993` omits from its served chain (extracted
    /// 2026-09-09 from smtp.novo-ordo.com:587, which serves the same leaf;
    /// valid to 2030-12-31, fingerprint
    /// 7F:A4:FF:68:EC:04:A9:9D:75:28:D5:08:5F:94:90:7F:4D:1D:D1:C5:38:1B:
    /// AC:DC:83:2E:D5:C9:60:21:46:76). Shipped as
    /// `router/etc/rustical/certs/imap-novo-ordo.pem` in the router-dav
    /// repo, deployed to `/etc/rustical/certs/` on the router.
    const NOVO_ORDO_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIGEzCCA/ugAwIBAgIQfVtRJrR2uhHbdBYLvFMNpzANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgx
MTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjCBjzELMAkGA1UEBhMCR0IxGzAZBgNV
BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
ChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFJTQSBEb21haW4g
VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA1nMz1tc8INAA0hdFuNY+B6I/x0HuMjDJsGz99J/LEpgPLT+N
TQEMgg8Xf2Iu6bhIefsWg06t1zIlk7cHv7lQP6lMw0Aq6Tn/2YHKHxYyQdqAJrkj
eocgHuP/IJo8lURvh3UGkEC0MpMWCRAIIz7S3YcPb11RFGoKacVPAXJpz9OTTG0E
oKMbgn6xmrntxZ7FN3ifmgg0+1YuWMQJDgZkW7w33PGfKGioVrCSo1yfu4iYCBsk
Haswha6vsC6eep3BwEIc4gLw6uBK0u+QDrTBQBbwb4VCSmT3pDCg/r8uoydajotY
uK3DGReEY+1vVv2Dy2A0xHS+5p3b4eTlygxfFQIDAQABo4IBbjCCAWowHwYDVR0j
BBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFI2MXsRUrYrhd+mb
+ZsF4bgBjWHhMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAbBgNVHSAEFDASMAYGBFUdIAAw
CAYGZ4EMAQIBMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0
LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2Bggr
BgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNv
bS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDov
L29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMr9hvQ5Iw0/H
ukdN+Jx4GQHcEx2Ab/zDcLRSmjEzmldS+zGea6TvVKqJjUAXaPgREHzSyrHxVYbH
7rM2kYb2OVG/Rr8PoLq0935JxCo2F57kaDl6r5ROVm+yezu/Coa9zcV3HAO4OLGi
H19+24rcRki2aArPsrW04jTkZ6k4Zgle0rj8nSg6F0AnwnJOKf0hPHzPE/uWLMUx
RP0T7dWbqWlod3zu4f+k+TY4CFM5ooQ0nBnzvg6s1SQ36yOoeNDT5++SR2RiOSLv
xvcRviKFxmZEJCaOEDKNyJOuB56DPi/Z+fVGjmO+wea03KbNIaiGCpXZLoUmGv38
sbZXQm2V0TP2ORQGgkE49Y9Y3IBbpNV9lXj9p5v//cWoaasm56ekBYdbqbe4oyAL
l6lFhd2zi+WJN44pDfwGF/Y4QA5C5BIG+3vzxhFoYt/jmPQT2BVPi7Fp2RBgvGQq
6jG35LWjOhSbJuMLe/0CjraZwTiXWTb2qHSihrZe68Zk6s+go/lunrotEbaGmAhY
LcmsJWTyXnW0OMGuf1pGg+pRyrbxmRE1a6Vqe8YAsOf4vmSyrcjC8azjUeqkk+B5
yOGBQMkKW+ESPMFgKuOXwIlCypTPRpgSabuY0MLTDXJLR27lk8QyKGOHQ+SwMj4K
00u/I5sUKUErmgQfky3xxzlIPK1aEn8=
-----END CERTIFICATE-----
";

    /// Regression for the novo-ordo known issue: `imap.novo-ordo.com:993`
    /// serves only its leaf, so plain webpki verification fails with
    /// `UnknownIssuer`; pinning the missing Sectigo intermediate via
    /// `ca_file` must let the TLS handshake and greeting succeed.
    /// Network + real provider — run explicitly with:
    /// `cargo test -p rustical_scheduling -- --ignored novo_ordo`
    #[tokio::test]
    #[ignore = "live network: dials imap.novo-ordo.com:993"]
    async fn connect_novo_ordo_with_pinned_intermediate() {
        let ca_file = std::env::temp_dir().join(format!(
            "rustical-scheduling-novo-ordo-{}.pem",
            std::process::id()
        ));
        std::fs::write(&ca_file, NOVO_ORDO_CA_PEM).unwrap();

        // Without the pin the handshake must fail (documents the bug).
        let mut plain = account();
        plain.host = "imap.novo-ordo.com".to_owned();
        let err = connect(&plain).await.err().unwrap();
        assert!(
            err.to_string().contains("UnknownIssuer"),
            "expected UnknownIssuer without the pinned intermediate, got: {err}"
        );

        // With the pin the full connect (TLS + greeting) must succeed. No
        // login: credentials are not needed to prove the chain verifies.
        let mut pinned = plain;
        pinned.identity = "nfcalaway@novo-ordo.com".to_owned();
        pinned.username = "nfcalaway@novo-ordo.com".to_owned();
        pinned.ca_file = Some(ca_file.clone());
        connect(&pinned).await.unwrap_or_else(|e| panic!("{e}"));

        let _ = std::fs::remove_file(&ca_file);
    }
}
