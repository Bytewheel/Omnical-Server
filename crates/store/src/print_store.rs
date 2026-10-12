//! Print-state tracking for the portal's print pages (``PLAN_NEXT_AGENT_PRINTING.md``).
//!
//! "Print only new" means *previously unprinted*, so printing is recorded:
//! [`PrintStore::mark_printed`] upserts marks (an explicit POST on the print
//! page, never a side effect of rendering — plan D5), and
//! [`PrintStore::printed_keys`] is what a `scope=new` render subtracts.
//!
//! Marks are keyed per owning collection **and** per event *instance* (plan
//! D4): a weekly series printed for October must come back as new in November,
//! because next month's instances are next month's stickers. Tasks and contacts
//! carry no recurrence expansion, so their instance key is empty.
//!
//! The state is per-collection and shared across members (plan D7): once the
//! stickers exist on paper, nobody in the household needs to print them twice.
//! `printed_by` records who did.

use crate::error::Error;
use async_trait::async_trait;
use std::collections::HashSet;

/// Which kind of collection a [`PrintMark`] belongs to.
///
/// Mandatory as a stored discriminator: this deployment's principal has a
/// calendar and an addressbook that can share the id `personal`, so
/// `(principal, collection_id)` is not unique across kinds (plan D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrintCollectionKind {
    Calendar,
    Addressbook,
}

impl PrintCollectionKind {
    /// The stored discriminator (`print_state.kind`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::Addressbook => "addressbook",
        }
    }
}

impl TryFrom<&str> for PrintCollectionKind {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "calendar" => Ok(Self::Calendar),
            "addressbook" => Ok(Self::Addressbook),
            other => Err(Error::Other(anyhow::anyhow!(
                "unknown print-state collection kind: {other}"
            ))),
        }
    }
}

/// One printed-object record. `(principal, collection_id, kind, object_id,
/// instance_key)` is the upsert key.
#[derive(Debug, Clone)]
pub struct PrintMark {
    /// Owning principal of the collection (the collection's, not the actor's).
    pub principal: String,
    pub collection_id: String,
    pub kind: PrintCollectionKind,
    pub object_id: String,
    /// Empty for whole-object marks (tasks, contacts); for events the
    /// concrete instance's start (`%Y%m%d` for DATE, `%Y%m%dT%H%M%SZ` UTC).
    pub instance_key: String,
    /// Who clicked "Mark printed".
    pub printed_by: String,
}

#[async_trait]
pub trait PrintStore: Send + Sync + 'static {
    /// Upsert the given marks. Idempotent: re-printing refreshes
    /// `printed_at`/`printed_by` instead of failing.
    async fn mark_printed(&self, marks: &[PrintMark]) -> Result<(), Error>;

    /// The `(object_id, instance_key)` pairs already printed for one
    /// collection. A `scope=new` render subtracts exactly these.
    async fn printed_keys(
        &self,
        principal: &str,
        kind: PrintCollectionKind,
        collection_id: &str,
    ) -> Result<HashSet<(String, String)>, Error>;
}
