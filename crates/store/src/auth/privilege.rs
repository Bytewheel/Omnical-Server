use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Per-member privilege level inside a shared group (Omnical §17.9.2 /
/// PLAN_SHARING §10). Grants:
/// - [`Privilege::View`] — read-only access to the group's collections
/// - [`Privilege::Edit`] — full CRUD on the group's collections (the old
///   "membership = full r/w" level)
/// - [`Privilege::Admin`] — `Edit` plus member management (change privileges,
///   invite/remove members)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Privilege {
    View,
    Edit,
    Admin,
}

impl Privilege {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Edit => "edit",
            Self::Admin => "admin",
        }
    }

    /// Whether this privilege allows writing to the group's collections.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Edit | Self::Admin)
    }

    /// Whether this privilege allows member management (invites, membership
    /// and privilege changes, group deletion).
    #[must_use]
    pub const fn can_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl FromStr for Privilege {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "view" => Ok(Self::View),
            "edit" => Ok(Self::Edit),
            "admin" => Ok(Self::Admin),
            _ => Err(format!(
                "Invalid privilege '{s}' — must be one of 'view', 'edit', 'admin'."
            )),
        }
    }
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
