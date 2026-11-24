//! One source list for runtime factories, CLI selectors, and the generated man page.

macro_rules! registered_sources {
    ($register:ident) => {
        $register! {
            inline => ("server_addresses", |command: clap::Command| command),
            file => ("config", |command: clap::Command| command),
            sonic => ("sonic", |command: clap::Command| command
                .arg(clap::Arg::new("sonic").long("sonic").action(clap::ArgAction::SetTrue)
                    .help("Get TACACS+ and local forwarder configuration from SONiC ConfigDB")
                    .conflicts_with_all([
                        "inline-upstream",
                        "local_services",
                        "proxy_endpoint",
                        "proxy_shared_secret",
                        "proxy_credential_source",
                        "service_mode",
                    ]))
                .arg(clap::Arg::new("sonic_redis_url").long("sonic-redis-url")
                    .value_name("URL").requires("sonic")
                    .help("Override the SONiC ConfigDB Redis URL (default: unix:///var/run/redis/redis.sock?db=4)"))
                .arg(clap::Arg::new("sonic_redis_db").long("sonic-redis-db")
                    .value_name("INDEX").value_parser(clap::value_parser!(i64)).requires("sonic")
                    .help("Override the SONiC ConfigDB database index (default: 4)"))),
            kubesonic => ("kubesonic", |command: clap::Command| command
                .arg(clap::Arg::new("kubesonic").long("kubesonic")
                    .action(clap::ArgAction::SetTrue).exclusive(true)
                    .help("Use KubeSONiC ConfigDB and TACACSD_ environment inputs")))
        }
    };
}

pub(crate) use registered_sources;
