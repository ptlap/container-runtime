use crate::cgroup::CgroupConfig;
use crate::error::PolicyError;
use crate::modes::LogMode;
use crate::security::SecurityProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyProfile {
    None,
    Restricted,
    Debug,
}

impl PolicyProfile {
    pub fn from_config(value: Option<&str>) -> Result<Self, PolicyError> {
        match value {
            None => Ok(Self::None),
            Some("restricted") => Ok(Self::Restricted),
            Some("debug") => Ok(Self::Debug),
            Some(value) => Err(PolicyError::UnsupportedProfile {
                value: value.to_string(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Restricted => "restricted",
            Self::Debug => "debug",
        }
    }
}

pub fn apply_security(
    security_profile: SecurityProfile,
    policy_profile: PolicyProfile,
) -> SecurityProfile {
    match policy_profile {
        PolicyProfile::Restricted => SecurityProfile::Default,
        PolicyProfile::Debug if security_profile == SecurityProfile::Default => {
            SecurityProfile::Unconfined
        }
        _ => security_profile,
    }
}

pub fn apply_log_mode(log_mode: LogMode, policy_profile: PolicyProfile) -> LogMode {
    match policy_profile {
        PolicyProfile::Debug if matches!(log_mode, LogMode::Auto) => LogMode::On,
        _ => log_mode,
    }
}

pub fn apply_cgroup(
    explicit: Option<CgroupConfig>,
    policy_profile: PolicyProfile,
) -> Option<CgroupConfig> {
    let defaults = match policy_profile {
        PolicyProfile::Restricted => CgroupConfig {
            memory_limit: Some(256 * 1024 * 1024),
            cpu_quota: None,
            cpu_period: None,
            pids_limit: Some(64),
        },
        _ => CgroupConfig {
            memory_limit: None,
            cpu_quota: None,
            cpu_period: None,
            pids_limit: None,
        },
    };

    let merged = if let Some(explicit) = explicit {
        CgroupConfig {
            memory_limit: explicit.memory_limit.or(defaults.memory_limit),
            cpu_quota: explicit.cpu_quota.or(defaults.cpu_quota),
            cpu_period: explicit.cpu_period.or(defaults.cpu_period),
            pids_limit: explicit.pids_limit.or(defaults.pids_limit),
        }
    } else {
        defaults
    };

    (merged.memory_limit.is_some()
        || merged.cpu_quota.is_some()
        || merged.cpu_period.is_some()
        || merged.pids_limit.is_some())
    .then_some(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_profiles_from_config() {
        assert_eq!(
            PolicyProfile::from_config(None).unwrap(),
            PolicyProfile::None
        );
        assert_eq!(
            PolicyProfile::from_config(Some("restricted")).unwrap(),
            PolicyProfile::Restricted
        );
        assert_eq!(
            PolicyProfile::from_config(Some("debug")).unwrap(),
            PolicyProfile::Debug
        );
        assert_eq!(PolicyProfile::Restricted.as_str(), "restricted");
    }

    #[test]
    fn rejects_unknown_policy_profile_with_typed_error() {
        assert!(matches!(
            PolicyProfile::from_config(Some("unsafe-fast")),
            Err(PolicyError::UnsupportedProfile { value }) if value == "unsafe-fast"
        ));
    }

    #[test]
    fn applies_policy_security_and_log_defaults() {
        assert_eq!(
            apply_security(SecurityProfile::Unconfined, PolicyProfile::Restricted),
            SecurityProfile::Default
        );
        assert_eq!(
            apply_security(SecurityProfile::Default, PolicyProfile::Debug),
            SecurityProfile::Unconfined
        );
        assert_eq!(
            apply_log_mode(LogMode::Auto, PolicyProfile::Debug),
            LogMode::On
        );
        assert_eq!(
            apply_log_mode(LogMode::Off, PolicyProfile::Debug),
            LogMode::Off
        );
    }

    #[test]
    fn applies_restricted_cgroup_defaults_without_overriding_explicit_values() {
        let defaults = apply_cgroup(None, PolicyProfile::Restricted).expect("defaults");
        assert_eq!(defaults.memory_limit, Some(256 * 1024 * 1024));
        assert_eq!(defaults.pids_limit, Some(64));

        let merged = apply_cgroup(
            Some(CgroupConfig {
                memory_limit: Some(512),
                cpu_quota: Some(10_000),
                cpu_period: None,
                pids_limit: None,
            }),
            PolicyProfile::Restricted,
        )
        .expect("merged");

        assert_eq!(merged.memory_limit, Some(512));
        assert_eq!(merged.cpu_quota, Some(10_000));
        assert_eq!(merged.pids_limit, Some(64));
    }
}
