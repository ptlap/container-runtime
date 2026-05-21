use crate::error::ModeError;
use crate::network::NetworkMode;
use crate::security::SecurityProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogMode {
    Auto,
    On,
    Off,
}

impl LogMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

pub fn parse_network_mode(value: &str) -> Result<NetworkMode, ModeError> {
    match value {
        "host" => Ok(NetworkMode::Host),
        "none" => Ok(NetworkMode::None),
        "bridge" => Ok(NetworkMode::Bridge),
        _ => Err(ModeError::InvalidNetworkMode {
            value: value.to_string(),
        }),
    }
}

pub fn parse_security_profile(value: &str) -> Result<SecurityProfile, ModeError> {
    match value {
        "default" => Ok(SecurityProfile::Default),
        "unconfined" => Ok(SecurityProfile::Unconfined),
        _ => Err(ModeError::InvalidSecurityProfile {
            value: value.to_string(),
        }),
    }
}

pub fn parse_log_mode(value: &str) -> Result<LogMode, ModeError> {
    match value {
        "auto" => Ok(LogMode::Auto),
        "on" => Ok(LogMode::On),
        "off" => Ok(LogMode::Off),
        _ => Err(ModeError::InvalidLogMode {
            value: value.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes_from_state_strings() {
        assert_eq!(parse_network_mode("host").unwrap(), NetworkMode::Host);
        assert_eq!(parse_network_mode("none").unwrap(), NetworkMode::None);
        assert_eq!(parse_network_mode("bridge").unwrap(), NetworkMode::Bridge);
        assert_eq!(
            parse_security_profile("default").unwrap(),
            SecurityProfile::Default
        );
        assert_eq!(
            parse_security_profile("unconfined").unwrap(),
            SecurityProfile::Unconfined
        );
        assert_eq!(parse_log_mode("auto").unwrap(), LogMode::Auto);
        assert_eq!(parse_log_mode("on").unwrap(), LogMode::On);
        assert_eq!(parse_log_mode("off").unwrap(), LogMode::Off);
    }

    #[test]
    fn rejects_invalid_modes_with_typed_errors() {
        assert!(matches!(
            parse_network_mode("invalid"),
            Err(ModeError::InvalidNetworkMode { value }) if value == "invalid"
        ));
        assert!(matches!(
            parse_security_profile("invalid"),
            Err(ModeError::InvalidSecurityProfile { value }) if value == "invalid"
        ));
        assert!(matches!(
            parse_log_mode("invalid"),
            Err(ModeError::InvalidLogMode { value }) if value == "invalid"
        ));
    }

    #[test]
    fn formats_log_modes_for_state() {
        assert_eq!(LogMode::Auto.as_str(), "auto");
        assert_eq!(LogMode::On.as_str(), "on");
        assert_eq!(LogMode::Off.as_str(), "off");
    }
}
