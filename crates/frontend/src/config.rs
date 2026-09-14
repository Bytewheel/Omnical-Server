use serde::{Deserialize, Serialize};

const fn default_true() -> bool {
    true
}

const fn default_min_password_length() -> usize {
    12
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FrontendConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_password_login: bool,
    /// Minimum accepted password length for the portal password-change form
    /// (mirrors `[registration] min_password_length`).
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_password_login: true,
            min_password_length: default_min_password_length(),
        }
    }
}
