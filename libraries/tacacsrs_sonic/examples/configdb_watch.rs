use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tacacsrs_config::TacacsPlus;
use tacacsrs_datastore::ConfigDatastore;
use tacacsrs_sonic::{SonicConfigDb, SonicConnection};
use tokio_stream::StreamExt;

const LOCAL_REDIS_URL: &str = "redis://127.0.0.1:6379";
const DEFAULT_CONFIG_DB: i64 = 4;
const DEFAULT_DEBOUNCE_MS: u64 = 250;

#[derive(Debug, Parser)]
#[command(name = "configdb-watch")]
#[command(about = "Watch SONiC ConfigDB TACACS+ rows through tacacsrs-sonic")]
struct Cli {
    /// Redis connection URL. Use `<redis://127.0.0.1:6379>` for local Docker/WSL Redis.
    #[arg(long, default_value = LOCAL_REDIS_URL)]
    redis_url: String,

    /// Redis database index that stores `SONiC` `CONFIG_DB`.
    #[arg(long, default_value_t = DEFAULT_CONFIG_DB)]
    redis_db: i64,

    /// Debounce window for coalescing Redis keyspace notifications.
    #[arg(long, default_value_t = DEFAULT_DEBOUNCE_MS)]
    debounce_ms: u64,

    /// Stop after this many change events. Omit to watch until interrupted.
    #[arg(long)]
    max_events: Option<usize>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let settings = SonicConnection {
        url: cli.redis_url,
        db_index: cli.redis_db,
        debounce: Duration::from_millis(cli.debounce_ms),
        credential_watch_root: None,
    };
    let datastore = SonicConfigDb::new(settings);

    println!("datastore: {}", datastore.label());
    println!("redis_url: {}", datastore.settings().url);
    println!("redis_db: {}", datastore.settings().db_index);
    println!("debounce_ms: {}", datastore.settings().debounce.as_millis());

    let initial = datastore
        .load()
        .await
        .context("load initial TACACS+ snapshot from SONiC ConfigDB")?;
    print_snapshot("initial", &initial);

    if cli.max_events == Some(0) {
        return Ok(());
    }

    println!("watching for TACPLUS keyspace notifications");
    let mut changes = datastore
        .subscribe()
        .await
        .context("subscribe to SONiC ConfigDB changes")?;

    let mut observed = 0usize;
    while let Some(event) = changes.next().await {
        observed += 1;
        println!("change_event: {observed}");
        match event {
            tacacsrs_datastore::ConfigChangeEvent::Changed(change) => {
                println!("  result: changed");
                println!("  added_servers: {:?}", change.delta.added_servers);
                println!("  removed_servers: {:?}", change.delta.removed_servers);
                println!("  modified_servers: {:?}", change.delta.modified_servers);
                println!("  root_metadata_changed: {}", change.delta.root_metadata_changed);
                print_snapshot("current", &change.config);
            }
            tacacsrs_datastore::ConfigChangeEvent::CandidateRejected => {
                println!("  result: candidate_rejected");
            }
        }

        if cli
            .max_events
            .is_some_and(|max_events| observed >= max_events)
        {
            break;
        }
    }

    Ok(())
}

fn print_snapshot(label: &str, config: &TacacsPlus) {
    println!("{label}_server_count: {}", config.server.len());
    for server in &config.server {
        println!("  server: {}", server.name);
        println!("    endpoint: {}:{}", server.address, server.port);
        println!("    server_type: {:?}", server.server_type);
        println!("    timeout_seconds: {}", server.timeout);
        println!("    single_connection: {}", server.single_connection);
        println!("    domain_name: {}", optional_value(server.domain_name.as_deref()));
        println!("    sni_enabled: {}", optional_bool(server.sni_enabled));
        println!("    source_ip: {}", optional_value(server.source_ip.as_deref()));
        println!("    source_interface: {}", optional_value(server.source_interface.as_deref()));
        println!("    vrf_instance: {}", optional_value(server.vrf_instance.as_deref()));
        println!("    shared_secret_configured: {}", server.shared_secret.is_some());
    }
}

fn optional_value(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "-",
    }
}
