use crate::audit_log::AuditEvent;
use crate::cgroup::{read_stats, running_cgroup_path, CgroupStats};
use crate::error::EventError;
use crate::state::{self, ContainerStatus};
use anyhow::Result;
use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSnapshot {
    memory_events: BTreeMap<String, u64>,
    pids_events: BTreeMap<String, u64>,
    cpu_nr_throttled: Option<u64>,
    cpu_throttled_usec: Option<u64>,
}

impl EventSnapshot {
    pub fn from_stats(stats: &CgroupStats) -> Self {
        Self {
            memory_events: stats.memory.events.clone(),
            pids_events: stats.pids.events.clone(),
            cpu_nr_throttled: stats.cpu.nr_throttled,
            cpu_throttled_usec: stats.cpu.throttled_usec,
        }
    }

    fn fields(&self) -> BTreeMap<String, u64> {
        let mut fields = BTreeMap::new();
        for (name, value) in &self.memory_events {
            fields.insert(format!("memory.{name}"), *value);
        }
        for (name, value) in &self.pids_events {
            fields.insert(format!("pids.{name}"), *value);
        }
        if let Some(value) = self.cpu_nr_throttled {
            fields.insert("cpu.nr_throttled".to_string(), value);
        }
        if let Some(value) = self.cpu_throttled_usec {
            fields.insert("cpu.throttled_usec".to_string(), value);
        }

        fields
    }
}

pub fn snapshot_event(id: &str, snapshot: &EventSnapshot) -> AuditEvent {
    AuditEvent::new(id, "cgroup", "snapshot").with_fields(snapshot.fields())
}

pub fn collect_counter_events(
    id: &str,
    previous: &EventSnapshot,
    current: &EventSnapshot,
) -> Vec<AuditEvent> {
    let mut events = Vec::new();
    append_counter_events(
        &mut events,
        id,
        "memory",
        &previous.memory_events,
        &current.memory_events,
    );
    append_counter_events(
        &mut events,
        id,
        "pids",
        &previous.pids_events,
        &current.pids_events,
    );

    if let (Some(previous), Some(current)) = (previous.cpu_nr_throttled, current.cpu_nr_throttled) {
        if current > previous {
            events.push(counter_event(
                id,
                "cpu",
                "nr_throttled",
                current,
                current - previous,
            ));
        }
    }

    if let (Some(previous), Some(current)) =
        (previous.cpu_throttled_usec, current.cpu_throttled_usec)
    {
        if current > previous {
            events.push(counter_event(
                id,
                "cpu",
                "throttled_usec",
                current,
                current - previous,
            ));
        }
    }

    events
}

pub fn stream_counter_events(
    id: &str,
    snapshot: bool,
    once: bool,
    interval: Duration,
    mut emit: impl FnMut(AuditEvent) -> Result<()>,
) -> Result<()> {
    if interval.is_zero() {
        return Err(EventError::InvalidInterval.into());
    }

    let cgroup_path = running_cgroup_path(id)?;
    let mut previous = EventSnapshot::from_stats(&read_stats(&cgroup_path)?);
    if snapshot {
        emit(snapshot_event(id, &previous))?;
    }
    if once {
        return Ok(());
    }

    loop {
        thread::sleep(interval);

        let state = state::load_current(id)?;
        if state.status != ContainerStatus::Running {
            emit(
                AuditEvent::new(id, "lifecycle", "stopped")
                    .with_status(container_status_name(&state.status)),
            )?;
            break;
        }

        let current_stats = read_stats(&cgroup_path)?;
        let current = EventSnapshot::from_stats(&current_stats);
        for event in collect_counter_events(id, &previous, &current) {
            emit(event)?;
        }
        previous = current;
    }

    Ok(())
}

fn container_status_name(status: &ContainerStatus) -> &'static str {
    match status {
        ContainerStatus::Created => "created",
        ContainerStatus::Running => "running",
        ContainerStatus::Stopped => "stopped",
    }
}

fn append_counter_events(
    events: &mut Vec<AuditEvent>,
    id: &str,
    source: &str,
    previous: &BTreeMap<String, u64>,
    current: &BTreeMap<String, u64>,
) {
    for (name, current_value) in current {
        let previous_value = previous.get(name).copied().unwrap_or(0);
        if *current_value > previous_value {
            events.push(counter_event(
                id,
                source,
                name,
                *current_value,
                *current_value - previous_value,
            ));
        }
    }
}

fn counter_event(id: &str, source: &str, name: &str, value: u64, delta: u64) -> AuditEvent {
    AuditEvent::new(id, source, name)
        .with_value(value)
        .with_delta(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_counter_events_for_increasing_values() {
        let previous = EventSnapshot {
            memory_events: BTreeMap::from([("oom_kill".to_string(), 1)]),
            pids_events: BTreeMap::from([("max".to_string(), 0)]),
            cpu_nr_throttled: Some(2),
            cpu_throttled_usec: Some(100),
        };
        let current = EventSnapshot {
            memory_events: BTreeMap::from([("oom_kill".to_string(), 3)]),
            pids_events: BTreeMap::from([("max".to_string(), 1)]),
            cpu_nr_throttled: Some(5),
            cpu_throttled_usec: Some(140),
        };

        let events = collect_counter_events("demo", &previous, &current);

        assert_eq!(events.len(), 4);
        assert!(events
            .iter()
            .any(|event| event.source == "memory" && event.name == "oom_kill"));
        assert!(events
            .iter()
            .any(|event| event.source == "pids" && event.name == "max"));
        assert!(events
            .iter()
            .any(|event| event.source == "cpu" && event.name == "nr_throttled"));
        assert!(events
            .iter()
            .any(|event| event.source == "cpu" && event.name == "throttled_usec"));
    }

    #[test]
    fn ignores_counter_events_without_increase() {
        let previous = EventSnapshot {
            memory_events: BTreeMap::from([("oom".to_string(), 1)]),
            pids_events: BTreeMap::new(),
            cpu_nr_throttled: Some(2),
            cpu_throttled_usec: Some(100),
        };
        let current = EventSnapshot {
            memory_events: BTreeMap::from([("oom".to_string(), 1)]),
            pids_events: BTreeMap::new(),
            cpu_nr_throttled: Some(2),
            cpu_throttled_usec: Some(100),
        };

        assert!(collect_counter_events("demo", &previous, &current).is_empty());
    }

    #[test]
    fn builds_snapshot_event_fields() {
        let snapshot = EventSnapshot {
            memory_events: BTreeMap::from([("oom_kill".to_string(), 2)]),
            pids_events: BTreeMap::from([("max".to_string(), 1)]),
            cpu_nr_throttled: Some(3),
            cpu_throttled_usec: Some(40),
        };

        let event = snapshot_event("demo", &snapshot);
        let fields = event.fields.expect("snapshot should include fields");

        assert_eq!(event.source, "cgroup");
        assert_eq!(event.name, "snapshot");
        assert_eq!(fields.get("memory.oom_kill"), Some(&2));
        assert_eq!(fields.get("pids.max"), Some(&1));
        assert_eq!(fields.get("cpu.nr_throttled"), Some(&3));
        assert_eq!(fields.get("cpu.throttled_usec"), Some(&40));
    }

    #[test]
    fn rejects_zero_event_interval_with_typed_error() {
        let error = stream_counter_events("demo", false, true, Duration::ZERO, |_| Ok(()))
            .expect_err("zero interval should be rejected");

        assert!(matches!(
            error.downcast_ref::<EventError>(),
            Some(EventError::InvalidInterval)
        ));
    }
}
