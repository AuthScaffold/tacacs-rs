//! Text and JSON output of the detailed agent runtime health.

use std::fmt::Write;

use clap::Args;
use serde_json::{Value, json};
use tacacsrs_ipc::{HealthClient, IpcEndpoint, proto};

use crate::statistics::OutputFormat;

#[derive(Debug, Args)]
pub(crate) struct DetailsArgs {
    /// Output representation.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

pub(crate) async fn query(endpoint: &IpcEndpoint, args: &DetailsArgs) -> anyhow::Result<String> {
    let mut client = HealthClient::connect(endpoint).await?;
    let reply = client.details().await?;
    render(&reply, args.format)
}

/// Converts a wire enum name such as `LISTENER_STATE_BOUND` to `bound`.
///
/// A value that this build does not know shows as `unknown-<number>`.
fn label(name: Option<&'static str>, raw: i32, prefix: &str) -> String {
    name.map_or_else(
        || format!("unknown-{raw}"),
        |name| {
            name.strip_prefix(prefix)
                .unwrap_or(name)
                .to_ascii_lowercase()
                .replace('_', "-")
        },
    )
}

fn lifecycle(raw: i32) -> String {
    let name = proto::RuntimeLifecycle::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "RUNTIME_LIFECYCLE_")
}

fn datastore(raw: i32) -> String {
    let name = proto::DatastoreState::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "DATASTORE_STATE_")
}

fn service(raw: i32) -> String {
    let name = proto::RuntimeService::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "RUNTIME_SERVICE_")
}

fn listener_state(raw: i32) -> String {
    let name = proto::ListenerState::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "LISTENER_STATE_")
}

fn upstream(raw: i32) -> String {
    let name = proto::UpstreamAvailability::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "UPSTREAM_AVAILABILITY_")
}

fn degradation(raw: i32) -> String {
    let name = proto::DegradationReason::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "DEGRADATION_REASON_")
}

fn component_status(raw: i32) -> String {
    let name = proto::ComponentHealthStatus::try_from(raw)
        .ok()
        .map(|value| value.as_str_name());
    label(name, raw, "COMPONENT_HEALTH_STATUS_")
}

fn to_json(reply: &proto::HealthDetailsReply) -> Value {
    let revisions = reply.revisions.unwrap_or_default();
    let watchdog = reply.watchdog.unwrap_or_default();
    json!({
        "lifecycle": lifecycle(reply.lifecycle),
        "startup": reply.startup,
        "liveness": reply.liveness,
        "readiness": reply.readiness,
        "listening": reply.listening,
        "applied-configuration": reply.applied_configuration,
        "datastore": datastore(reply.datastore),
        "notifications-connected": reply.notifications_connected,
        "listeners": reply.listeners.iter().map(|listener| json!({
            "service": service(listener.service),
            "enabled": listener.enabled,
            "state": listener_state(listener.state),
        })).collect::<Vec<_>>(),
        "eligible-server-count": reply.eligible_server_count,
        "upstream-availability": upstream(reply.upstream_availability),
        "watchdog": {
            "armed": watchdog.armed,
            "server-set-epoch": watchdog.server_set_epoch,
        },
        "degradation-reasons": reply
            .degradation_reasons
            .iter()
            .map(|reason| degradation(*reason))
            .collect::<Vec<_>>(),
        "revisions": {
            "runtime-generation": revisions.runtime_generation,
            "applied-policy": revisions.applied_policy,
            "materialized-source": revisions.materialized_source,
            "materialized-credentials": revisions.materialized_credentials,
            "source-recovery": revisions.source_recovery,
        },
        "credential-validity": reply.credential_validity.map(|validity| json!({
            "valid-from-unix-seconds": validity.valid_from_unix_seconds,
            "valid-until-unix-seconds": validity.valid_until_unix_seconds,
        })),
        "components": reply.components.iter().map(|component| json!({
            "group": component.group,
            "name": component.name,
            "status": component_status(component.status),
            "description": component.description,
            "duration-micros": component.duration_micros,
        })).collect::<Vec<_>>(),
    })
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn serving(value: bool) -> &'static str {
    if value {
        "serving"
    } else {
        "not-serving"
    }
}

fn optional<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

pub(crate) fn render(
    reply: &proto::HealthDetailsReply,
    format: OutputFormat,
) -> anyhow::Result<String> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(&to_json(reply))?);
    }
    let mut output = String::new();
    writeln!(output, "Lifecycle: {}", lifecycle(reply.lifecycle))?;
    writeln!(
        output,
        "Probes: startup={} liveness={} readiness={}",
        serving(reply.startup),
        serving(reply.liveness),
        serving(reply.readiness)
    )?;
    writeln!(output, "Listening: {}", yes_no(reply.listening))?;
    writeln!(output, "Applied configuration: {}", yes_no(reply.applied_configuration))?;
    writeln!(output, "Datastore: {}", datastore(reply.datastore))?;
    writeln!(output, "Notifications connected: {}", yes_no(reply.notifications_connected))?;
    for listener in &reply.listeners {
        writeln!(
            output,
            "Listener {}: enabled={} state={}",
            service(listener.service),
            yes_no(listener.enabled),
            listener_state(listener.state)
        )?;
    }
    writeln!(output, "Eligible servers: {}", reply.eligible_server_count)?;
    writeln!(output, "Upstream availability: {}", upstream(reply.upstream_availability))?;
    let watchdog = reply.watchdog.unwrap_or_default();
    writeln!(
        output,
        "Upstream watchdog: armed={} server-set-epoch={}",
        yes_no(watchdog.armed),
        watchdog.server_set_epoch
    )?;
    let reasons: Vec<_> = reply
        .degradation_reasons
        .iter()
        .map(|reason| degradation(*reason))
        .collect();
    if reasons.is_empty() {
        writeln!(output, "Degradation reasons: none")?;
    } else {
        writeln!(output, "Degradation reasons: {}", reasons.join(", "))?;
    }
    let revisions = reply.revisions.unwrap_or_default();
    writeln!(
        output,
        "Revisions: runtime-generation={} applied-policy={} materialized-source={} \
         materialized-credentials={} source-recovery={}",
        optional(revisions.runtime_generation),
        optional(revisions.applied_policy),
        optional(revisions.materialized_source),
        optional(revisions.materialized_credentials),
        optional(revisions.source_recovery)
    )?;
    match reply.credential_validity {
        Some(validity) => writeln!(
            output,
            "Credential validity (Unix seconds): from={} until={}",
            optional(validity.valid_from_unix_seconds),
            optional(validity.valid_until_unix_seconds)
        )?,
        None => writeln!(output, "Credential validity: none applied")?,
    }
    for component in &reply.components {
        write!(
            output,
            "Component {}/{}: {}",
            component.group,
            component.name,
            component_status(component.status)
        )?;
        match &component.description {
            Some(description) => writeln!(output, " ({description})")?,
            None => writeln!(output)?,
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_wire_values_are_shown_and_known_values_use_short_names() {
        let mut reply = proto::HealthDetailsReply {
            lifecycle: 99,
            degradation_reasons: vec![proto::DegradationReason::DatastoreStale as i32, 77],
            components: vec![proto::ComponentHealth {
                group: "component".to_owned(),
                name: "kubesonic-loopback-registration".to_owned(),
                status: proto::ComponentHealthStatus::Degraded as i32,
                description: Some("waiting".to_owned()),
                duration_micros: 5,
            }],
            ..Default::default()
        };
        reply.set_datastore(proto::DatastoreState::Unavailable);
        let text = render(&reply, OutputFormat::Text).unwrap();
        assert!(text.contains("Lifecycle: unknown-99"));
        assert!(text.contains("Datastore: unavailable"));
        assert!(text.contains("Degradation reasons: datastore-stale, unknown-77"));
        assert!(text
            .contains("Component component/kubesonic-loopback-registration: degraded (waiting)"));
        let value: Value =
            serde_json::from_str(&render(&reply, OutputFormat::Json).unwrap()).unwrap();
        assert_eq!(value["degradation-reasons"], json!(["datastore-stale", "unknown-77"]));
        assert_eq!(value["revisions"]["runtime-generation"], Value::Null);
        assert_eq!(value["components"][0]["status"], "degraded");
    }
}
