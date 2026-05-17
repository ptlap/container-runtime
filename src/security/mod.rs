use anyhow::{Context, Result};
use nix::sys::prctl;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    Default,
    Unconfined,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Unconfined => "unconfined",
        }
    }
}

pub fn apply(profile: SecurityProfile) -> Result<()> {
    match profile {
        SecurityProfile::Default => prctl::set_no_new_privs()
            .context("failed to enable no_new_privs for default security profile"),
        SecurityProfile::Unconfined => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_security_profiles_for_state() {
        assert_eq!(SecurityProfile::Default.as_str(), "default");
        assert_eq!(SecurityProfile::Unconfined.as_str(), "unconfined");
    }
}
