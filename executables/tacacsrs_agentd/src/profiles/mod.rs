//! Registered application profiles.
//!
//! Each profile parses its controls before Tokio starts. Parsing selects the
//! components of the process and makes no I/O. The host in
//! `tacacsrs_agent::host` then prepares, registers, and runs the components.

use std::path::PathBuf;
use std::time::Duration;

use tacacsrs_agent::PolicyInput;
use tacacsrs_composition::{Component, Value};
use tacacsrs_config::tacacsrs::RuntimePolicy;
use tacacsrs_networking::CertificateVerification;

use crate::cli::Cli;
use crate::components::{self, HostInputs};
use crate::process::ProcessOptions;

pub(crate) struct Registration {
    pub(crate) selector: &'static str,
    pub(crate) parse: fn(Cli) -> anyhow::Result<SelectedProfile>,
}

macro_rules! source_factories {
    ($($source:ident => ($selector:literal, $configure:expr)),+ $(,)?) => {
        $(pub(crate) mod $source;)+
        pub(crate) const REGISTRATIONS: &[Registration] = &[
            $(Registration { selector: $selector, parse: $source::parse }),+
        ];
    };
}
crate::source_registry::registered_sources!(source_factories);

pub(crate) fn select(cli: Cli) -> anyhow::Result<SelectedProfile> {
    select_registered(cli, REGISTRATIONS)
}

fn select_registered(cli: Cli, registrations: &[Registration]) -> anyhow::Result<SelectedProfile> {
    let mut selected = registrations.iter().filter(|registration| {
        cli.matches.value_source(registration.selector)
            == Some(clap::parser::ValueSource::CommandLine)
    });
    let registration = selected
        .next()
        .ok_or_else(|| anyhow::anyhow!("No registered source was selected"))?;
    anyhow::ensure!(selected.next().is_none(), "Select exactly one registered source");
    (registration.parse)(cli)
}

/// The process options and the selected components of one profile.
pub(crate) struct SelectedProfile {
    pub(crate) process: ProcessOptions,
    pub(crate) components: Vec<Box<dyn Component>>,
}

impl SelectedProfile {
    /// Selects the host-wide components, adds the host inputs, and then adds
    /// the source components.
    ///
    /// # Errors
    /// Returns a selection error.
    pub(crate) fn new(
        host: HostInputs,
        policy: PolicyInput,
        certificate_verification: CertificateVerification,
        source: Vec<Box<dyn Component>>,
    ) -> anyhow::Result<Self> {
        let mut selected = components::select(&host)?;
        selected.push(Box::new(Value::new("Runtime policy", policy)));
        selected.push(Box::new(Value::new("Certificate verification", certificate_verification)));
        selected.extend(source);
        Ok(Self {
            process: host.process,
            components: selected,
        })
    }

    /// Selects the components of a profile that the command line configures.
    ///
    /// The profile gets the HTTP credential evidence sources of the command
    /// line. `source` returns the source components.
    ///
    /// # Errors
    /// Returns a source or selection error.
    pub(crate) fn from_cli(
        cli: Cli,
        source: impl FnOnce(&Cli) -> anyhow::Result<Vec<Box<dyn Component>>>,
    ) -> anyhow::Result<Self> {
        let host = HostInputs {
            process: ProcessOptions::from_cli(&cli),
            statistics_file: cli.statistics_file.clone(),
            upstream_watchdog_interval: cli
                .upstream_watchdog_interval_seconds
                .map(|seconds| Duration::from_secs(seconds.get())),
            protected_inputs: protected_inputs(&cli),
            http_evidence: crate::http_evidence::settings(&cli)?,
        };
        let policy = cli
            .runtime_policy
            .clone()
            .map_or_else(|| PolicyInput::Canonical(RuntimePolicy::default()), PolicyInput::File);
        let certificate_verification = if cli.insecure_disable_certificate_verification {
            CertificateVerification::DisabledForDevelopment
        } else {
            CertificateVerification::Required
        };
        let source = source(&cli)?;
        Self::new(host, policy, certificate_verification, source)
    }
}

/// Returns the input files that the statistics file must not replace.
fn protected_inputs(cli: &Cli) -> Vec<PathBuf> {
    let mut protected_inputs = Vec::new();
    protected_inputs.extend(
        cli.config
            .iter()
            .chain(cli.runtime_policy.iter())
            .chain(cli.local_services.iter())
            .cloned(),
    );
    protected_inputs.extend(
        cli.client_certificate
            .iter()
            .chain(cli.client_key.iter())
            .map(PathBuf::from),
    );
    protected_inputs.extend(
        cli.http_crl_certificate
            .chunks_exact(2)
            .map(|values| PathBuf::from(&values[1])),
    );
    protected_inputs.extend(
        cli.http_ocsp_source
            .chunks_exact(4)
            .flat_map(|values| [PathBuf::from(&values[2]), PathBuf::from(&values[3])]),
    );
    protected_inputs.extend(
        cli.http_ocsp_certificate
            .chunks_exact(3)
            .flat_map(|values| [PathBuf::from(&values[1]), PathBuf::from(&values[2])]),
    );
    protected_inputs
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use clap::{Args, FromArgMatches, Parser};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use tacacsrs_config::source::ConfigDatastore;
    use tacacsrs_config::tacacsrs::LocalServices;
    use tacacsrs_config::{
        TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType,
    };
    use tacacsrs_config::source::{
        ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDelta, ConfigObservation,
        DatastoreRuntimePolicy,
    };

    use super::*;
    use tacacsrs_agent::components::{DatastoreSourceComponent, LocalServicesInput};

    struct NotificationSource;

    struct NotificationSession {
        changes: mpsc::Receiver<ConfigChangeEvent>,
        worker: JoinHandle<()>,
    }

    impl Drop for NotificationSession {
        fn drop(&mut self) {
            self.worker.abort();
        }
    }

    #[async_trait]
    impl ConfigObservation for NotificationSession {
        async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
            Ok(self.changes.recv().await)
        }
    }

    fn snapshot() -> TacacsPlus {
        TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "fixture",
                    TacacsPlusServerType::all(),
                    "127.0.0.1",
                    49,
                )
                .with_shared_secret("test-key"),
            )
            .build()
            .unwrap()
    }

    #[async_trait]
    impl ConfigDatastore for NotificationSource {
        async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
            let (sender, changes) = mpsc::channel(2);
            let worker = tokio::spawn(async move {
                for source in [snapshot(), TacacsPlus::empty()] {
                    let config = Arc::new(source);
                    sender
                        .send(ConfigChangeEvent::Changed(ConfigChange {
                            local_services: None,
                            delta: ConfigDelta::diff(None, &config),
                            config,
                        }))
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                sender.closed().await;
            });
            Ok(Box::new(NotificationSession { changes, worker }))
        }
        fn runtime_policy(&self) -> DatastoreRuntimePolicy {
            DatastoreRuntimePolicy::new(ChangeNotificationMode::Continuous)
        }
        async fn load(&self) -> anyhow::Result<TacacsPlus> {
            Ok(snapshot())
        }
        fn label(&self) -> &'static str {
            "registered-fixture"
        }
    }

    #[tokio::test]
    async fn added_registration_drives_background_notifications_through_shared_startup() {
        fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
            SelectedProfile::from_cli(cli, |_| {
                Ok(vec![Box::new(DatastoreSourceComponent::new(
                    "Notification fixture",
                    Arc::new(NotificationSource),
                    LocalServicesInput::Fixed(LocalServices {
                        client_api_enabled: false,
                        tacacs_proxy_enabled: true,
                        tacacs_proxy_endpoint: Some("127.0.0.1:0".to_owned()),
                        ..LocalServices::default()
                    }),
                ))])
            })
        }
        let registration = Registration {
            selector: "fixture",
            parse,
        };
        let matches = crate::cli::CommonArgs::augment_args(
            clap::Command::new("fixture").arg(
                clap::Arg::new("fixture")
                    .long("fixture")
                    .action(clap::ArgAction::SetTrue),
            ),
        )
        .try_get_matches_from(["agentd", "--fixture"])
        .unwrap();
        let profile =
            select_registered(Cli::from_arg_matches(&matches).unwrap(), &[registration]).unwrap();
        let host = tacacsrs_agent::host::bootstrap(profile.components)
            .await
            .unwrap();
        let service = host.runtime().service().clone();
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let monitor = tokio::spawn(async move { host.run_until(stop.cancelled()).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while service.server_count() != 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            while service.server_count() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("Registered notification must update the native catalog");
        cancellation.cancel();
        monitor.await.unwrap().unwrap();
    }

    #[test]
    fn registered_selectors_remain_exclusive_and_visible_in_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for flag in ["--server-addr", "--config", "--sonic", "--kubesonic"] {
            assert!(help.contains(flag), "Registered selector missing from help: {flag}");
        }
        for flags in [
            vec!["--sonic", "--kubesonic"],
            vec!["--config", "config.json", "--sonic"],
            vec!["--server-addr", "127.0.0.1", "--sonic"],
            vec!["--kubesonic", "--worker-threads", "2"],
            vec!["--kubesonic", "--host-integration", "none"],
            vec!["--kubesonic", "--runtime-policy", "policy.json"],
        ] {
            assert!(Cli::try_parse_from(["agentd"].into_iter().chain(flags)).is_err());
        }
        assert!(Cli::try_parse_from(["agentd", "--kubesonic"]).is_ok());
    }

    #[tokio::test]
    async fn cancellation_drops_pending_profile_preparation_before_listener_binding() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Preparation(Arc<AtomicBool>);
        impl Drop for Preparation {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct PendingSource {
            _owner: Preparation,
            entered: Option<tokio::sync::oneshot::Sender<()>>,
        }

        #[async_trait]
        impl Component for PendingSource {
            fn name(&self) -> &'static str {
                "Pending source"
            }

            async fn prepare(&mut self) -> anyhow::Result<()> {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).unwrap();
                }
                std::future::pending().await
            }

            fn register(
                self: Box<Self>,
                _composition: &mut tacacsrs_composition::Composition,
            ) -> anyhow::Result<()> {
                unreachable!("Preparation never completes")
            }
        }

        let directory = std::env::temp_dir().join(format!(
            "agentd-profile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("not-bound.sock");
        let cli = Cli::parse_from([
            "agentd",
            "--server-addr",
            "127.0.0.1",
            "--listen-endpoint",
            socket.to_str().unwrap(),
        ]);
        let dropped = Arc::new(AtomicBool::new(false));
        let owner = Preparation(dropped.clone());
        let (entered, started) = tokio::sync::oneshot::channel();
        let profile = SelectedProfile::from_cli(cli, |_| {
            Ok(vec![Box::new(PendingSource {
                _owner: owner,
                entered: Some(entered),
            })])
        })
        .unwrap();
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(tacacsrs_agent::host::run_until(profile.components, async move {
            stop.cancelled().await;
            Ok(())
        }));
        started.await.unwrap();
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(!socket.exists());
        std::fs::remove_dir(directory).unwrap();
    }
}
