use crate::error::HealthcheckError;
use crate::spec::config::Healthcheck;

pub fn command_args(healthcheck: &Healthcheck) -> Result<Vec<String>, HealthcheckError> {
    let Some((kind, rest)) = healthcheck.test.split_first() else {
        return Err(HealthcheckError::EmptyTest);
    };

    match kind.as_str() {
        "NONE" => Err(HealthcheckError::Disabled),
        "CMD" => {
            if rest.is_empty() {
                return Err(HealthcheckError::MissingCommand { kind: "CMD" });
            }
            Ok(rest.to_vec())
        }
        "CMD-SHELL" => {
            if rest.is_empty() {
                return Err(HealthcheckError::MissingCommand { kind: "CMD-SHELL" });
            }
            Ok(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                rest.join(" "),
            ])
        }
        _ => Ok(healthcheck.test.clone()),
    }
}

pub fn attempts(healthcheck: &Healthcheck) -> u32 {
    healthcheck.retries.unwrap_or(0).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_cmd_healthcheck_args() {
        let healthcheck = Healthcheck {
            test: vec!["CMD".to_string(), "/bin/true".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert_eq!(
            command_args(&healthcheck).expect("valid healthcheck"),
            ["/bin/true".to_string()]
        );
    }

    #[test]
    fn builds_cmd_shell_healthcheck_args() {
        let healthcheck = Healthcheck {
            test: vec![
                "CMD-SHELL".to_string(),
                "echo".to_string(),
                "ok".to_string(),
            ],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert_eq!(
            command_args(&healthcheck).expect("valid healthcheck"),
            [
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo ok".to_string()
            ]
        );
    }

    #[test]
    fn rejects_disabled_healthcheck_args_with_typed_error() {
        let healthcheck = Healthcheck {
            test: vec!["NONE".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert!(matches!(
            command_args(&healthcheck),
            Err(HealthcheckError::Disabled)
        ));
    }

    #[test]
    fn rejects_empty_cmd_with_typed_error() {
        let healthcheck = Healthcheck {
            test: vec!["CMD".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert!(matches!(
            command_args(&healthcheck),
            Err(HealthcheckError::MissingCommand { kind: "CMD" })
        ));
    }

    #[test]
    fn computes_healthcheck_attempts_from_retries() {
        let default_retries = Healthcheck {
            test: vec!["CMD".to_string(), "true".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };
        let configured_retries = Healthcheck {
            test: vec!["CMD".to_string(), "true".to_string()],
            interval: None,
            timeout: None,
            retries: Some(3),
        };

        assert_eq!(attempts(&default_retries), 1);
        assert_eq!(attempts(&configured_retries), 4);
    }
}
