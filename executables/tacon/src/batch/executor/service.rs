use futures::future::join_all;
use std::sync::Arc;

use tacacsrs_agent_client::{
    AuthorizationAuthenticationContext as IpcAuthorizationContext, AuthorizationOperation,
    ServiceClient,
};

use super::common::{
    load_test_iterations, run_load_test, service_client, to_service_accounting_request,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, BatchRequest, LoadTestConfig, RequestResult};
use super::super::types::AuthorizationAuthenticationContext;

async fn execute_single_request_via_service(
    client: &ServiceClient,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => client
            .send_accounting(to_service_accounting_request(req))
            .await
            .map(|response| format!("Accounting success: {response:?}"))
            .map_err(|error| format!("Accounting failed: {error}")),
        BatchRequest::Authentication(req) => {
            Err(format!(
                "PAP authentication is not supported in batch files; use the authentication command with a prompt or --password-stdin (user: {})",
                req.user
            ))
        }
        BatchRequest::Authorization(req) => {
            let context = match req.authentication_context {
                AuthorizationAuthenticationContext::Ascii => IpcAuthorizationContext::TacacsAscii,
                AuthorizationAuthenticationContext::Pap => IpcAuthorizationContext::TacacsPap,
                AuthorizationAuthenticationContext::Unauthenticated => {
                    IpcAuthorizationContext::Unauthenticated
                }
            };
            let mut builder = AuthorizationOperation::builder(
                req.user.clone(),
                u32::from(req.privilege_level),
                context,
            )
            .port(req.port.clone())
            .remote_address(req.rem_addr.clone())
            .service("shell");
            builder = match &req.cmd {
                Some(command) => builder.command(command).command_args(req.cmd_args.clone()),
                None => builder.command(""),
            };
            client
                .send_authorization(builder.build().map_err(|error| error.to_string())?)
                .await
                .map(|response| format!("Authorization success: {response:?}"))
                .map_err(|error| format!("Authorization failed: {error}"))
        }
    }
}

pub async fn execute_batch_via_service(
    endpoint: &str,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = service_client(endpoint).await?;

    if let Some(description) = &batch.metadata.description {
        log::info!("Executing batch: {description}");
        println!("Batch: {description}");
    }

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test_via_service(endpoint, batch, load_config).await;
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
    endpoint: &str,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = Arc::new(service_client(endpoint).await?);

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
