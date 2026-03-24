use futures::future::join_all;
use std::sync::Arc;

use tacacsrs_agent_client::ServiceClient;

use crate::cli::Cli;

use super::common::{
    load_test_iterations, run_load_test, service_client, to_service_accounting_request,
    validate_service_mode_request,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, BatchRequest, LoadTestConfig, RequestResult};

async fn execute_single_request_via_service(
    client: &ServiceClient,
    request: &BatchRequest,
) -> Result<String, String> {
    validate_service_mode_request(request)?;

    match request {
        BatchRequest::Accounting(req) => client
            .send_accounting(to_service_accounting_request(req))
            .await
            .map(|response| format!("Accounting success: {response:?}"))
            .map_err(|error| format!("Accounting failed: {error}")),
        BatchRequest::Authentication(req) => {
            log::warn!("Authentication not yet implemented for user: {}", req.user);
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }
        BatchRequest::Authorization(req) => {
            log::warn!("Authorization not yet implemented for user: {}", req.user);
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

pub async fn execute_batch_via_service(
    cli: &Cli,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = service_client(cli)?;

    if let Some(description) = &batch.metadata.description {
        log::info!("Executing batch: {description}");
        println!("Batch: {description}");
    }

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test_via_service(cli, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests through central service (parallel: {})",
        batch.metadata.parallel
    );

    if batch.metadata.parallel {
        let futures: Vec<_> = batch
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let client = client.clone();
                async move {
                    let result = execute_single_request_via_service(&client, request).await;
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result,
                    }
                }
            })
            .collect();
        Ok(join_all(futures).await)
    } else {
        let mut results = Vec::with_capacity(batch.requests.len());
        for (index, request) in batch.requests.iter().enumerate() {
            let result = execute_single_request_via_service(&client, request).await;
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result,
            });
        }
        Ok(results)
    }
}

async fn execute_batch_load_test_via_service(
    cli: &Cli,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = Arc::new(service_client(cli)?);

    log::info!(
        "Service load testing mode enabled: {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel
    );
    println!(
        "\n=== Load Testing Mode ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len()
    );

    let result = run_load_test(
        batch.requests.len() * load_config.repetitions,
        load_test_iterations(&batch.requests, load_config.repetitions),
        load_config.max_parallel,
        move |rep, idx, request| {
            let client = Arc::clone(&client);
            async move {
                execute_single_request_via_service(client.as_ref(), request)
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!(
                            "Request failed at rep {}, request {} ({}): {}",
                            rep + 1,
                            idx + 1,
                            request.type_name(),
                            error
                        )
                    })
            }
        },
    )
    .await;
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::validate_service_mode_request;
    use super::*;
    use crate::batch::types::{AccountingRequest, CustomFlags};

    #[test]
    fn test_service_mode_rejects_custom_flags_and_session_ids_in_batch_requests() {
        let request = BatchRequest::Accounting(AccountingRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_addr: "127.0.0.1".to_owned(),
            cmd: "show".to_owned(),
            cmd_args: vec![],
            custom_flags: CustomFlags {
                custom_flag_1: true,
                custom_flag_2: false,
            },
            session_id: None,
        });
        assert!(validate_service_mode_request(&request).is_err());

        let request = BatchRequest::Accounting(AccountingRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_addr: "127.0.0.1".to_owned(),
            cmd: "show".to_owned(),
            cmd_args: vec![],
            custom_flags: CustomFlags::default(),
            session_id: Some(7),
        });
        assert!(validate_service_mode_request(&request).is_err());
    }
}
