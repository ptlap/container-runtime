use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

pub const EXTERNAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
pub const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to spawn external command {command}: {source}")]
    Spawn {
        command: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to wait for external command {command}: {source}")]
    Wait {
        command: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to read output from external command {command}: {source}")]
    Read {
        command: String,
        #[source]
        source: io::Error,
    },

    #[error("external command timed out after {timeout_ms}ms: {command}")]
    TimedOut { command: String, timeout_ms: u128 },
}

pub fn output(
    mut command: Command,
    description: impl Into<String>,
    timeout: Duration,
) -> Result<Output, CommandError> {
    let description = description.into();
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().map_err(|source| CommandError::Spawn {
        command: description.clone(),
        source,
    })?;
    wait_with_output(child, description, timeout)
}

pub fn status(
    mut command: Command,
    description: impl Into<String>,
    timeout: Duration,
) -> Result<ExitStatus, CommandError> {
    let description = description.into();
    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| CommandError::Spawn {
            command: description.clone(),
            source,
        })?;
    wait(child, description, timeout)
}

pub fn wait_with_output(
    mut child: Child,
    description: String,
    timeout: Duration,
) -> Result<Output, CommandError> {
    let stdout = child.stdout.take().map(read_pipe);
    let stderr = child.stderr.take().map(read_pipe);
    let status = wait_child(&mut child, &description, timeout)?;
    let stdout = join_pipe(stdout, &description)?;
    let stderr = join_pipe(stderr, &description)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub fn wait(
    mut child: Child,
    description: impl Into<String>,
    timeout: Duration,
) -> Result<ExitStatus, CommandError> {
    let description = description.into();
    wait_child(&mut child, &description, timeout)
}

fn wait_child(
    child: &mut Child,
    description: &str,
    timeout: Duration,
) -> Result<ExitStatus, CommandError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandError::TimedOut {
                    command: description.to_string(),
                    timeout_ms: timeout.as_millis(),
                });
            }
            Ok(None) => thread::sleep(COMMAND_POLL_INTERVAL),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandError::Wait {
                    command: description.to_string(),
                    source,
                });
            }
        }
    }
}

fn read_pipe(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        pipe.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn join_pipe(
    pipe: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    description: &str,
) -> Result<Vec<u8>, CommandError> {
    let Some(pipe) = pipe else {
        return Ok(Vec::new());
    };
    let output = pipe.join().map_err(|_| CommandError::Read {
        command: description.to_string(),
        source: io::Error::other("output reader thread panicked"),
    })?;
    output.map_err(|source| CommandError::Read {
        command: description.to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn kills_a_command_that_exceeds_the_deadline() {
        let mut command = Command::new("sleep");
        command.arg("10");
        let error = output(command, "sleep 10", Duration::from_millis(20))
            .expect_err("command should time out");
        assert!(matches!(error, CommandError::TimedOut { .. }));
    }

    #[test]
    fn captures_output_without_waiting_unbounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf hello; printf error >&2"]);
        let output = output(command, "sh -c printf", Duration::from_secs(1))
            .expect("command should complete");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"error");
    }
}
