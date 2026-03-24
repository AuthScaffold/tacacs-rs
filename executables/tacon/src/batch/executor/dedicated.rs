use anyhow::Context;
use futures::future::join_all;

use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::DedicatedConnection;

use crate::cli::Cli;
use crate::commands::accounting::build_accounting_request;
use crate::connection::establish_stream;

use super::common::{load_test_iterations, run_load_test};
use super::super::types::{BatchRequest, LoadTestConfig, RequestResult};

/// Probes the server for single-connection support by sending a lightweight
/// accounting record that logs tacon's invocation. Returns `true` if the
/// server echoed `TAC_PLUS_SINGLE_CONNECT_FLAG`.
pub(super) async fn probe_single_connect(cli: &Cli) -> bool {
    let result = async {
        let stream = establish_stream(cli)
            .await
            .context("Probe connection failed")?;
        let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
        let mut connection = DedicatedConnection::new(stream, obfuscation_key);

        let args = redact_secret_args(std::env::args());
        let request = build_accounting_request("tacon", "batch", "localhost", "tacon", Some(&args));

        connection
            .send_accounting(request, TacacsFlags::empty())
            .await
            .context("Probe accounting exchange failed")
    }
    .await;

    match result {
        Ok(exchange) => {
            log::info!(
                "Probe reply: {:?}, single_connect_supported: {}",
                exchange.reply,
                exchange.single_connect_supported
            );
            exchange.single_connect_supported
        }
        Err(error) => {
            log::warn!("Single-connect probe failed, falling back to dedicated: {error}");
            false
        }
    }
}

const SECRET_FLAGS: &[&str] = &["-k", "--obfuscation-key", "--psk-key"];

/// Replaces the value following any secret flag with `***`.
fn redact_secret_args(args: impl Iterator<Item = String>) -> Vec<String> {
    let mut result = Vec::new();
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            result.push("***".to_owned());
            redact_next = false;
        } else if SECRET_FLAGS.contains(&arg.as_str()) {
            result.push(arg);
            redact_next = true;
        } else if let Some((flag, _)) = arg.split_once('=') {
            if SECRET_FLAGS.contains(&flag) {
                result.push(format!("{flag}=***"));
            } else {
                result.push(arg);
            }
        } else {
            result.push(arg);
        }
    }
    result
}

/// Executes a single batch request using a dedicated connection (no background
/// tasks, no session multiplexing).
async fn execute_single_request_dedicated(
    cli: &Cli,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let stream = establish_stream(cli)
                .await
                .map_err(|error| format!("Connection failed: {error}"))?;

            let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
            let mut connection = DedicatedConnection::new(stream, obfuscation_key);

            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };
            let tacacs_request =
                build_accounting_request(&req.user, &req.port, &req.rem_addr, &req.cmd, cmd_args);

            connection
                .send_accounting(tacacs_request, req.custom_flags.to_tacacs_flags())
                .await
                .map(|result| format!("Accounting success: {:?}", result.reply))
                .map_err(|error| format!("Accounting failed: {error}"))
        }
        BatchRequest::Authentication(req) => {
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }
        BatchRequest::Authorization(req) => {
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

pub(super) async fn execute_requests_dedicated(
    cli: &Cli,
    requests: &[BatchRequest],
    parallel: bool,
) -> Vec<RequestResult> {
    if parallel {
        let futures: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let cli = cli.clone();
                async move {
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result: execute_single_request_dedicated(&cli, request).await,
                    }
                }
            })
            .collect();
        join_all(futures).await
    } else {
        let mut results = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            log::info!("Executing request {}/{}", index + 1, requests.len());
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_single_request_dedicated(cli, request).await,
            });
        }
        results
    }
}

pub(super) async fn run_dedicated_load_test(
    cli: &Cli,
    requests: &[BatchRequest],
    load_config: &LoadTestConfig,
) -> super::super::types::LoadTestResult {
    let cli = cli.clone();
    run_load_test(
        requests.len() * load_config.repetitions,
        load_test_iterations(requests, load_config.repetitions),
        load_config.max_parallel,
        move |rep, idx, request| {
            let cli = cli.clone();
            async move {
                execute_single_request_dedicated(&cli, request)
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!("Request failed at rep {}, request {}: {error}", rep + 1, idx + 1)
                    })
            }
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::redact_secret_args;

    fn redact(args: &[&str]) -> Vec<String> {
        redact_secret_args(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn passthrough_when_no_secrets() {
        assert_eq!(
            redact(&["tacon", "--server-addr", "1.2.3.4:49"]),
            ["tacon", "--server-addr", "1.2.3.4:49"]
        );
    }

    #[test]
    fn redacts_obfuscation_key_long_flag() {
        assert_eq!(
            redact(&["tacon", "--obfuscation-key", "s3cret", "batch", "f.json"]),
            ["tacon", "--obfuscation-key", "***", "batch", "f.json"],
        );
    }

    #[test]
    fn redacts_obfuscation_key_short_flag() {
        assert_eq!(
            redact(&["tacon", "-k", "s3cret", "batch", "f.json"]),
            ["tacon", "-k", "***", "batch", "f.json"],
        );
    }

    #[test]
    fn redacts_psk_key() {
        assert_eq!(redact(&["tacon", "--psk-key", "top_secret"]), ["tacon", "--psk-key", "***"],);
    }

    #[test]
    fn redacts_equals_syntax() {
        assert_eq!(
            redact(&["tacon", "--obfuscation-key=s3cret", "--psk-key=top"]),
            ["tacon", "--obfuscation-key=***", "--psk-key=***"],
        );
    }

    #[test]
    fn secret_flag_at_end_without_value() {
        // Edge case: flag at end with no following value — just passes through
        assert_eq!(redact(&["tacon", "-k"]), ["tacon", "-k"]);
    }
}
