//! Inbound iMIP ingestion (RFC 6047): poll the configured IMAP mailboxes
//! for `METHOD:REPLY` iTIP emails and feed them to the scheduler.
//!
//! This is the missing inbound leg of email scheduling: when an invitation
//! goes to an external attendee (or to a local user before their principal
//! exists), their acceptance lands as an email in the organizer's mailbox
//! on the external mail provider. Without this loop the server-side
//! PARTSTAT never updates; with it, replies update the organizer's stored
//! copies and appear in their scheduling inbox like internal replies.
//!
//! Mailbox hygiene: only messages carrying a `text/calendar` part are ever
//! touched (flagged `\Seen` after successful ingestion when `mark_seen`).
//! Everything else — personal mail, invitations addressed *to* the user —
//! is fetched, found irrelevant, and left exactly as it was; per-process
//! UID bookkeeping (invalidated on UIDVALIDITY change) keeps the steady
//! state cheap.
//!
//! Candidate scope: all `\Unseen` messages plus mail from the last few
//! days regardless of `\Seen` — a normal mail client may read (and flag)
//! a reply before a poll sees it, and an UNSEEN-only search would then
//! miss it permanently.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::config::ImapAccount;
use crate::imap::{self, SESSION_TIMEOUT};
use crate::mime_parse;
use crate::scheduler::Scheduler;

/// Cap on messages examined per mailbox per poll (bounds the first-poll
/// burst on a busy personal mailbox).
const MAX_PER_POLL: usize = 25;
/// Soft cap on the process-local "already examined, not ours" set.
const MAX_CHECKED: usize = 100_000;

/// Spawn one polling task per configured IMAP account. No-op when
/// scheduling is disabled or no mailboxes are configured. `shutdown` is a
/// constructor for shutdown futures so every task gets its own listener.
pub fn spawn_ingestion<S, F>(scheduler: Arc<Scheduler>, shutdown: S)
where
    S: Fn() -> F + Send + Sync + Clone + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let accounts = scheduler.imap_accounts().to_vec();
    if accounts.is_empty() {
        return;
    }
    let poll_interval = scheduler.imap_poll_interval();
    info!(
        identities = accounts.len(),
        every_secs = poll_interval.as_secs(),
        "IMAP iMIP ingestion enabled ({} mailboxes)",
        accounts.len()
    );
    for account in accounts {
        let scheduler = scheduler.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            poll_loop(scheduler, account, poll_interval, shutdown).await;
        });
    }
}

async fn poll_loop<S, F>(
    scheduler: Arc<Scheduler>,
    account: ImapAccount,
    poll_interval: std::time::Duration,
    shutdown: S,
) where
    S: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let mut state = AccountState::default();
    loop {
        if let Err(err) = poll_mailbox(&scheduler, &account, &mut state).await {
            warn!("IMAP ingest {}: {}", account.identity, err);
        }
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            () = shutdown() => {
                debug!("IMAP ingest {}: stopping", account.identity);
                return;
            }
        }
    }
}

/// Process-local bookkeeping for one mailbox.
#[derive(Default)]
struct AccountState {
    uidvalidity: Option<u32>,
    /// UIDs already examined (and found irrelevant or already ingested);
    /// saves refetching mail that matched the candidate search on every
    /// poll.
    checked: HashSet<u32>,
}

impl AccountState {
    fn observe_uidvalidity(&mut self, uidvalidity: u32) {
        if self.uidvalidity.is_some_and(|old| old != uidvalidity) {
            // Mailbox was recreated; UIDs no longer mean the same messages
            self.checked.clear();
        }
        self.uidvalidity = Some(uidvalidity);
    }

    fn remember(&mut self, uid: u32) {
        if self.checked.len() >= MAX_CHECKED {
            self.checked.clear();
        }
        self.checked.insert(uid);
    }
}

/// One poll cycle: connect, login, SELECT, find candidate mail (unseen
/// or recently arrived), ingest every REPLY addressed to this identity.
/// Wrapped in [`SESSION_TIMEOUT`]; a stuck session is dropped and
/// retried next cycle.
async fn poll_mailbox(
    scheduler: &Arc<Scheduler>,
    account: &ImapAccount,
    state: &mut AccountState,
) -> Result<(), String> {
    let future = poll_mailbox_inner(scheduler, account, state);
    tokio::time::timeout(SESSION_TIMEOUT, future)
        .await
        .map_err(|_| "session timed out".to_owned())?
}

async fn poll_mailbox_inner(
    scheduler: &Arc<Scheduler>,
    account: &ImapAccount,
    state: &mut AccountState,
) -> Result<(), String> {
    let mut session = imap::connect(account).await.map_err(|e| e.to_string())?;
    session.login(account).await.map_err(|e| e.to_string())?;
    let status = session
        .select(&account.mailbox)
        .await
        .map_err(|e| e.to_string())?;
    state.observe_uidvalidity(status.uidvalidity);

    let candidates = session
        .uid_search_unseen()
        .await
        .map_err(|e| e.to_string())?;
    let todo: Vec<u32> = candidates
        .iter()
        .copied()
        .filter(|uid| !state.checked.contains(uid))
        .take(MAX_PER_POLL)
        .collect();

    let mut ingested = 0;
    let mut examined = 0;
    if !todo.is_empty() {
        let messages = session
            .uid_fetch_peek(&todo)
            .await
            .map_err(|e| e.to_string())?;
        for message in messages {
            examined += 1;
            if message.oversize {
                state.remember(message.uid);
                debug!(
                    "IMAP ingest {}: skipping oversized message (uid {})",
                    account.identity, message.uid
                );
                continue;
            }
            match process_message(scheduler, account, &message.data).await {
                Disposition::Ingested => {
                    ingested += 1;
                    state.remember(message.uid);
                    if account.mark_seen {
                        if let Err(err) = session.uid_mark_seen(message.uid).await {
                            warn!(
                                "IMAP ingest {}: could not mark uid {} seen: {}",
                                account.identity, message.uid, err
                            );
                        }
                    }
                }
                Disposition::NotOurs => state.remember(message.uid),
                Disposition::RetryLater => {
                    // Leave unseen and unchecked: retried next poll
                }
            }
        }
    }
    session.logout().await;

    debug!(
        "{} candidates, {} examined, {} replies ingested (uidvalidity {})",
        candidates.len(),
        examined,
        ingested,
        status.uidvalidity
    );
    Ok(())
}

enum Disposition {
    /// A REPLY was applied to the organizer's copies + inbox.
    Ingested,
    /// No (relevant) scheduling content: plain email, oversized, an
    /// invitation addressed to the user, a reply for another organizer,
    /// … — logged by the callee, remembered, never flagged.
    NotOurs,
    /// Operational failure — retried on the next poll.
    RetryLater,
}

async fn process_message(
    scheduler: &Arc<Scheduler>,
    account: &ImapAccount,
    data: &[u8],
) -> Disposition {
    let text = String::from_utf8_lossy(data);
    // Never log message content: this is the user's personal mailbox.
    let Some((calendar, _method)) = mime_parse::extract_calendar_part(&text) else {
        return Disposition::NotOurs;
    };
    let from = mime_parse::from_address(&text);
    match scheduler
        .ingest_imip_reply(&account.identity, &calendar, from.as_deref())
        .await
    {
        Ok(Some(_)) => Disposition::Ingested,
        Ok(None) => Disposition::NotOurs,
        Err(err) => {
            warn!("IMAP ingest {}: {}", account.identity, err);
            Disposition::RetryLater
        }
    }
}
