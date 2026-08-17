use anyhow::Context;
use futures::future::join_all;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::ConnectOptions;

use crate::connection::{
    establish_dedicated_connection as establish_dedicated_server_connection, Connection,
};

use super::common::{execute_single_request, load_test_iterations, run_load_test};
use super::super::types::{BatchRequest, LoadTestConfig, RequestResult};

/// Runs a single batch request using a dedicated connection (no background
/// tasks, no session multiplexing).
async fn execute_single_request_dedicated(
    connection: &Connection,
    request: &BatchRequest,
) -> Result<String, String> {
    execute_single_request(connection, request).await
}

async fn establish_dedicated_connection(
    server: &TacacsPlusServer,
    options: &ConnectOptions,
) -> anyhow::Result<Connection> {
    establish_dedicated_server_connection(server, options)
        .await
        .context("Failed to establish dedicated TACACS+ connection")
}

pub(super) async fn execute_requests_dedicated(
    server: &TacacsPlusServer,
    requests: &[BatchRequest],
    parallel: bool,
    options: &ConnectOptions,
) -> Vec<RequestResult> {
    let connection = match establish_dedicated_connection(server, options).await {
        Ok(connection) => connection,
        Err(error) => {
            let message = format!("Connection failed: {error:#}");
            return requests
                .iter()
                .enumerate()
                .map(|(index, request)| RequestResult {
                    index,
                    request_type: request.type_name(),
                    result: Err(message.clone()),
                })
                .collect();
        }
    };

    if parallel {
        let futures: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let connection = connection.clone();
                async move {
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result: execute_single_request_dedicated(&connection, request).await,
                    }
                }
            })
            .collect();
        join_all(futures).await
    } else {
        let mut results = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            log::info!("Running request {}/{}", index + 1, requests.len());
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_single_request_dedicated(&connection, request).await,
            });
        }
        results
    }
}

pub(super) async fn run_dedicated_load_test(
    server: &TacacsPlusServer,
    requests: &[BatchRequest],
    load_config: &LoadTestConfig,
    options: &ConnectOptions,
) -> anyhow::Result<super::super::types::LoadTestResult> {
    let connection = establish_dedicated_connection(server, options).await?;

    Ok(run_load_test(
        requests.len() * load_config.repetitions,
        load_test_iterations(requests, load_config.repetitions),
        load_config.max_parallel,
        move |rep, idx, request| {
            let connection = connection.clone();
            async move {
                execute_single_request_dedicated(&connection, request)
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!("Request failed at rep {}, request {}: {error}", rep + 1, idx + 1)
                    })
            }
        },
    )
    .await)
}
