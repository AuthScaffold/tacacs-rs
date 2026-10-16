//! Human-readable and RFC 7951 diagnostic output from one read-only snapshot.

use std::fmt::Write;

use anyhow::{Context, ensure};
use clap::{Args, ValueEnum};
use serde_json::Value;
use tacacsrs_ipc::{DiagnosticsClient, IpcEndpoint};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Args)]
pub(crate) struct StatisticsArgs {
    /// Exact configured server name. Omit to include the bounded server set.
    #[arg(long)]
    pub server: Option<String>,
    /// Output representation.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

pub(crate) async fn query(endpoint: IpcEndpoint, args: &StatisticsArgs) -> anyhow::Result<String> {
    let client = DiagnosticsClient::connect(endpoint).await?;
    let json = client.statistics_json(args.server.as_deref()).await?;
    render(&json, args.format)
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.escape_default().to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        _ => "unknown".to_owned(),
    }
}

fn row(output: &mut String, title: &str, value: &Value) -> std::fmt::Result {
    writeln!(output, "  {title}: {}", scalar(value))
}

pub(crate) fn render(json: &str, format: OutputFormat) -> anyhow::Result<String> {
    let value: Value =
        serde_json::from_str(json).context("Agent returned invalid operational JSON")?;
    let root = value
        .get("ietf-system-tacacs-plus:tacacs-plus")
        .context("Operational subtree is missing")?;
    let servers = root
        .get("server")
        .and_then(Value::as_array)
        .context("Operational server list is missing")?;
    ensure!(
        root["tacacsrs:runtime-generation"].as_str().is_some(),
        "Runtime generation is missing"
    );
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(&value)?);
    }
    let mut output = String::new();
    writeln!(output, "Runtime generation: {}", scalar(&root["tacacsrs:runtime-generation"]))?;
    for server in servers {
        let diagnostics = &server["tacacsrs:diagnostics"];
        writeln!(output, "\nServer: {}", scalar(&server["name"]))?;
        row(&mut output, "Address", &diagnostics["address"])?;
        row(&mut output, "Port", &diagnostics["port"])?;
        row(&mut output, "Connection state", &diagnostics["state"])?;
        row(&mut output, "Configured single-connect", &diagnostics["configured-single-connect"])?;
        row(
            &mut output,
            "Connection timeout (seconds)",
            &diagnostics["connection-timeout-seconds"],
        )?;
        row(&mut output, "Source address", &diagnostics["source-address"])?;
        row(&mut output, "Routing instance", &diagnostics["routing-instance"])?;
        row(&mut output, "Counter epoch", &server["tacacsrs:counter-epoch"])?;
        row(&mut output, "Counters started", &server["statistics"]["discontinuity-time"])?;
        for (key, title) in [
            ("connection-opens", "Connection attempts"),
            ("tacacsrs:connection-successes", "Successful connections"),
            ("connection-closes", "Graceful closes"),
            ("connection-aborts", "Aborts"),
            ("connection-failures", "Failed connections"),
            ("connection-timeouts", "Connection timeouts"),
            ("messages-sent", "Packets sent"),
            ("messages-received", "Packets received"),
            ("errors-received", "Protocol error replies"),
            ("sessions", "Completed sessions"),
            ("cert-errors", "Certificate errors"),
        ] {
            row(&mut output, title, &server["statistics"][key])?;
        }
        for key in [
            "connecting",
            "connected",
            "expected-replies",
            "last-attempt",
            "last-success",
            "last-disconnect",
            "last-disconnect-reason",
            "handshake-attempts",
            "handshake-successes",
            "handshake-failures",
            "read-errors",
            "write-errors",
            "receive-timeouts",
            "send-timeouts",
            "resets",
            "peer-disconnects",
            "malformed-disconnects",
            "no-response-disconnects",
            "credential-expiry-disconnects",
            "other-disconnects",
            "packets-since-reset-sent",
            "packets-since-reset-received",
            "watchdog-preflights",
            "watchdog-successes",
            "watchdog-failures",
            "watchdog-preflights-since-reset",
            "connections-omitted",
        ] {
            row(&mut output, key, &diagnostics[key])?;
        }
        for operation in ["authentication", "authorization", "accounting"] {
            writeln!(output, "  {operation}:")?;
            for field in [
                "requests",
                "passed",
                "denied",
                "errors",
                "consecutive-failures",
            ] {
                row(&mut output, &format!("  {field}"), &diagnostics[operation][field])?;
            }
        }
        writeln!(output, "  TLS errors:")?;
        for key in [
            "tls-read-errors",
            "tls-write-errors",
            "tls-certificate-errors",
            "tls-revoked-certificates",
            "tls-untrusted-ca",
            "tls-expired-certificates",
            "tls-protocol-mismatches",
            "tls-cipher-mismatches",
            "tls-other-errors",
        ] {
            row(&mut output, &format!("  {key}"), &diagnostics[key])?;
        }
        if let Some(routes) = diagnostics["routing"].as_array() {
            for route in routes {
                writeln!(
                    output,
                    "  Routing {}: eligible={} on-hold={}",
                    scalar(&route["operation"]),
                    scalar(&route["eligible"]),
                    scalar(&route["on-hold"])
                )?;
            }
        }
        if let Some(connections) = diagnostics["connection"].as_array() {
            for connection in connections {
                connection_text(&mut output, "Active connection", connection)?;
            }
        }
        if !diagnostics["last-connection"].is_null() {
            connection_text(
                &mut output,
                "Last established connection",
                &diagnostics["last-connection"],
            )?;
        }
        if let Some(unsupported) = diagnostics["unsupported"].as_array() {
            writeln!(
                output,
                "  Unsupported: {}",
                unsupported
                    .iter()
                    .map(scalar)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
    }
    if servers.is_empty() {
        writeln!(output, "No configured servers.")?;
    }
    Ok(output)
}

fn connection_text(output: &mut String, label: &str, connection: &Value) -> std::fmt::Result {
    writeln!(output, "  {label} {}:", scalar(&connection["connection-id"]))?;
    for key in [
        "peer-address",
        "address-family",
        "established-at",
        "single-connect",
        "tls-enabled",
        "tls-version",
        "tls-cipher",
        "fips-enabled",
    ] {
        if key.starts_with("tls-") && key != "tls-enabled" && connection["tls-enabled"] == false {
            row(output, &format!("  {key}"), &Value::String("not-applicable".to_owned()))?;
        } else {
            row(output, &format!("  {key}"), &connection[key])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_values_are_not_zero_and_terminal_controls_are_escaped() {
        let json = r#"{"ietf-system-tacacs-plus:tacacs-plus":{"tacacsrs:runtime-generation":"7","server":[{"name":"server\u001b[31m","statistics":{"messages-sent":"18446744073709551615"}}]}}"#;
        let text = render(json, OutputFormat::Text).unwrap();
        assert!(text.contains("18446744073709551615"));
        assert!(text.contains("Connection state: unknown"));
        assert!(!text.contains('\u{1b}'));
        assert_eq!(
            serde_json::from_str::<Value>(&render(json, OutputFormat::Json).unwrap()).unwrap(),
            serde_json::from_str::<Value>(json).unwrap()
        );
        assert!(render("{}", OutputFormat::Text).is_err());
    }
}
