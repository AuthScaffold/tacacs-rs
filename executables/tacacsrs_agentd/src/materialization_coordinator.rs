//! Desired-source credential materialization and known-good publication state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tacacsrs_agent::{ProxyDownstreamObfuscation, TacacsClientService};
use tacacsrs_config::{
    TacacsPlus, TacacsPlusServer, ValidationOptions, enumerate_server, inspect_central_references,
    validation,
};
use tacacsrs_credential_resolution::{
    CredentialChangeScope, CredentialKind, CredentialReference, CredentialResolver,
    MaterializationError, ResolutionPlan, materialize_servers,
};
use tokio::sync::Mutex;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyKey {
    kind: CredentialKind,
    reference: CredentialReference,
}

struct CoordinatorState {
    desired_source: Option<Arc<TacacsPlus>>,
    desired_runtime_source: Option<Arc<TacacsPlus>>,
    desired_proxy_policy: Option<ProxyDownstreamObfuscation>,
    desired_dependencies: Option<BTreeMap<DependencyKey, BTreeSet<String>>>,
    active_servers: Vec<Arc<TacacsPlusServer>>,
    source_generation: u64,
    active_source_generation: Option<u64>,
    materialization_attempt: u64,
}

impl Default for CoordinatorState {
    fn default() -> Self {
        Self {
            desired_source: None,
            desired_runtime_source: None,
            desired_proxy_policy: None,
            desired_dependencies: Some(BTreeMap::new()),
            active_servers: Vec::new(),
            source_generation: 0,
            active_source_generation: None,
            materialization_attempt: 0,
        }
    }
}

pub(crate) struct MaterializationCoordinator {
    state: Mutex<CoordinatorState>,
    resolver: Arc<dyn CredentialResolver>,
    validation_options: ValidationOptions,
}

pub(crate) struct MaterializationAttempt {
    attempt: u64,
    source_generation: u64,
    runtime_source: Arc<TacacsPlus>,
    proxy_policy: ProxyDownstreamObfuscation,
    selected_servers: BTreeSet<String>,
}

pub(crate) struct PreparedMaterialization {
    attempt: MaterializationAttempt,
    candidates: Vec<TacacsPlusServer>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PublicationOutcome {
    Published,
    Superseded,
}

impl MaterializationCoordinator {
    pub(crate) fn new(
        resolver: Arc<dyn CredentialResolver>,
        validation_options: ValidationOptions,
    ) -> Self {
        Self {
            state: Mutex::new(CoordinatorState::default()),
            resolver,
            validation_options,
        }
    }

    pub(crate) async fn accept_source(
        &self,
        desired_source: TacacsPlus,
        runtime_source: TacacsPlus,
        proxy_policy: ProxyDownstreamObfuscation,
    ) -> MaterializationAttempt {
        let dependencies = dependency_index(&runtime_source);
        let runtime_source = Arc::new(runtime_source);
        let selected_servers = runtime_source
            .server
            .iter()
            .map(|server| server.name.clone())
            .collect();
        let mut state = self.state.lock().await;
        state.source_generation = state.source_generation.wrapping_add(1);
        state.materialization_attempt = state.materialization_attempt.wrapping_add(1);
        state.desired_source = Some(Arc::new(desired_source));
        state.desired_runtime_source = Some(Arc::clone(&runtime_source));
        state.desired_proxy_policy = Some(proxy_policy.clone());
        state.desired_dependencies = dependencies;
        MaterializationAttempt {
            attempt: state.materialization_attempt,
            source_generation: state.source_generation,
            runtime_source,
            proxy_policy,
            selected_servers,
        }
    }

    pub(crate) async fn credential_change(
        &self,
        scope: &CredentialChangeScope,
    ) -> Option<MaterializationAttempt> {
        let mut state = self.state.lock().await;
        let runtime_source = Arc::clone(state.desired_runtime_source.as_ref()?);
        let proxy_policy = state.desired_proxy_policy.clone()?;
        let selected_servers = if state.active_source_generation == Some(state.source_generation) {
            match (scope, state.desired_dependencies.as_ref()) {
                (CredentialChangeScope::Known { kind, reference }, Some(dependencies)) => {
                    dependencies
                        .get(&DependencyKey {
                            kind: *kind,
                            reference: reference.clone(),
                        })
                        .cloned()
                        .unwrap_or_default()
                }
                _ => all_server_names(&runtime_source),
            }
        } else {
            all_server_names(&runtime_source)
        };
        if selected_servers.is_empty() {
            return None;
        }
        state.materialization_attempt = state.materialization_attempt.wrapping_add(1);
        Some(MaterializationAttempt {
            attempt: state.materialization_attempt,
            source_generation: state.source_generation,
            runtime_source,
            proxy_policy,
            selected_servers,
        })
    }

    pub(crate) async fn materialize(
        &self,
        attempt: MaterializationAttempt,
    ) -> Result<PreparedMaterialization, MaterializationError> {
        let servers = attempt
            .selected_servers
            .iter()
            .map(|server_name| enumerate_server(&attempt.runtime_source, server_name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MaterializationError::enumeration())?;
        let candidates =
            materialize_servers(servers, self.resolver.as_ref(), &self.validation_options).await?;
        Ok(PreparedMaterialization {
            attempt,
            candidates,
        })
    }

    pub(crate) async fn publish(
        &self,
        prepared: PreparedMaterialization,
        service: &TacacsClientService,
    ) -> anyhow::Result<PublicationOutcome> {
        let mut state = self.state.lock().await;
        if prepared.attempt.attempt != state.materialization_attempt
            || prepared.attempt.source_generation != state.source_generation
        {
            return Ok(PublicationOutcome::Superseded);
        }

        let candidate_by_name = prepared
            .candidates
            .into_iter()
            .map(|server| (server.name.clone(), server))
            .collect::<BTreeMap<_, _>>();
        let active_by_name = state
            .active_servers
            .iter()
            .map(|server| (server.name.as_str(), Arc::clone(server)))
            .collect::<BTreeMap<_, _>>();
        let mut next_active = Vec::with_capacity(prepared.attempt.runtime_source.server.len());
        for desired in &prepared.attempt.runtime_source.server {
            let server = if let Some(candidate) = candidate_by_name.get(&desired.name) {
                active_by_name
                    .get(desired.name.as_str())
                    .filter(|active| active.as_ref() == candidate)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(candidate.clone()))
            } else {
                active_by_name
                    .get(desired.name.as_str())
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("active server transaction is incomplete"))?
            };
            next_active.push(server);
        }

        let published = TacacsPlus {
            client_credentials: Vec::new(),
            server_credentials: Vec::new(),
            server: next_active
                .iter()
                .map(|server| server.as_ref().clone())
                .collect(),
        };
        ensure_publishable(&published, &self.validation_options)?;
        service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                next_active.clone(),
                prepared.attempt.proxy_policy,
            )
            .await?;
        state.active_servers = next_active;
        state.active_source_generation = Some(state.source_generation);
        Ok(PublicationOutcome::Published)
    }

    #[cfg(test)]
    pub(crate) async fn active_servers(&self) -> Vec<Arc<TacacsPlusServer>> {
        self.state.lock().await.active_servers.clone()
    }
}

fn all_server_names(source: &TacacsPlus) -> BTreeSet<String> {
    source
        .server
        .iter()
        .map(|server| server.name.clone())
        .collect()
}

fn dependency_index(source: &TacacsPlus) -> Option<BTreeMap<DependencyKey, BTreeSet<String>>> {
    let mut dependencies = BTreeMap::<DependencyKey, BTreeSet<String>>::new();
    for source_server in &source.server {
        let server = enumerate_server(source, &source_server.name).ok()?;
        let plan = ResolutionPlan::from_server(&server).ok()?;
        for request in plan.requests() {
            dependencies
                .entry(DependencyKey {
                    kind: request.kind(),
                    reference: request.reference().clone(),
                })
                .or_default()
                .insert(source_server.name.clone());
        }
    }
    Some(dependencies)
}

fn ensure_publishable(
    config: &TacacsPlus,
    validation_options: &ValidationOptions,
) -> anyhow::Result<()> {
    for server in &config.server {
        if !inspect_central_references(server)?.is_empty() {
            anyhow::bail!("active server transaction contains unresolved credentials");
        }
    }
    validation::validate_config_with_options(config, validation_options)
        .map_err(|_| anyhow::anyhow!("active server transaction failed validation"))
}

#[cfg(test)]
impl MaterializationAttempt {
    fn selected_server_names(&self) -> &BTreeSet<String> {
        &self.selected_servers
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use tacacsrs_agent::{
        EnabledServices, ProxyDownstreamObfuscation, RuntimeHealthPublisher, ServiceConfig,
        TacacsClientService,
    };
    use tacacsrs_agent_client::IpcEndpoint;
    use tacacsrs_config::crypto_types::SymmetricKeyFormat;
    use tacacsrs_config::{TacacsPlus, ValidationOptions, parse_yang_json};
    use tacacsrs_credential_resolution::{
        CredentialChangeScope, CredentialReference, CredentialRequest, CredentialResolver,
        ProviderErrorKind, ResolutionError, ResolvedCredential, SecretBytes, SymmetricKeyMaterial,
    };

    use super::*;

    struct MutableResolver {
        unavailable: Mutex<BTreeSet<String>>,
        material: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl CredentialResolver for MutableResolver {
        async fn resolve(
            &self,
            request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            let reference = request
                .reference()
                .symmetric_key()
                .expect("test uses EPSK references");
            if self
                .unavailable
                .lock()
                .expect("unavailable lock")
                .contains(reference)
            {
                return Err(ResolutionError::provider(
                    ProviderErrorKind::Unavailable,
                    request.context(),
                ));
            }
            let key = self
                .material
                .lock()
                .expect("material lock")
                .get(reference)
                .cloned()
                .expect("test material");
            Ok(ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
                key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
                key: SecretBytes::new(key),
            }))
        }
    }

    fn resolver(entries: &[(&str, &[u8])]) -> Arc<MutableResolver> {
        Arc::new(MutableResolver {
            unavailable: Mutex::new(BTreeSet::new()),
            material: Mutex::new(
                entries
                    .iter()
                    .map(|(reference, material)| ((*reference).to_owned(), material.to_vec()))
                    .collect(),
            ),
        })
    }

    fn source(reference: &str, address: &str) -> TacacsPlus {
        parse_yang_json(&format!(
            r#"{{
                "ietf-system-tacacs-plus:tacacs-plus": {{
                    "server": [{{
                        "name": "primary",
                        "server-type": "authentication authorization accounting",
                        "address": "{address}",
                        "port": 449,
                        "client-identity": {{
                            "tls13-epsk": {{
                                "central-keystore-reference": "{reference}",
                                "external-identity": "client"
                            }}
                        }}
                    }}]
                }}
            }}"#,
        ))
        .expect("test source")
    }

    fn service() -> TacacsClientService {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        TacacsClientService::waiting_for_configuration(
            ServiceConfig {
                enabled_services: EnabledServices::CLIENT_API,
                endpoint: IpcEndpoint::default_local(),
                proxy_endpoint: None,
                proxy_downstream_obfuscation: ProxyDownstreamObfuscation::default(),
                tacacs_plus: TacacsPlus::empty(),
                preferred_probe_interval: Duration::from_secs(1),
                #[cfg(unix)]
                socket_mode: 0o660,
                disable_certificate_verification: false,
            },
            health,
        )
        .expect("test service")
    }

    fn known(reference: &str) -> CredentialChangeScope {
        CredentialChangeScope::Known {
            kind: CredentialKind::SymmetricKey,
            reference: CredentialReference::SymmetricKey(reference.to_owned()),
        }
    }

    #[tokio::test]
    async fn dependency_index_maps_direct_and_bundle_nested_references() {
        let source = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "client-credentials": [{
                        "id": "bundle",
                        "tls13-epsk": {
                            "central-keystore-reference": "bundle-reference",
                            "external-identity": "client"
                        }
                    }],
                    "server": [
                        {
                            "name": "bundle-server",
                            "server-type": "authentication authorization accounting",
                            "address": "192.0.2.10",
                            "port": 449,
                            "client-identity": {"credentials-reference": "bundle"}
                        },
                        {
                            "name": "direct-server",
                            "server-type": "authentication authorization accounting",
                            "address": "192.0.2.11",
                            "port": 449,
                            "client-identity": {
                                "tls13-epsk": {
                                    "central-keystore-reference": "direct-reference",
                                    "external-identity": "client"
                                }
                            }
                        }
                    ]
                }
            }"#,
        )
        .expect("dependency source");
        let coordinator = MaterializationCoordinator::new(
            resolver(&[
                ("bundle-reference", b"bundle-material"),
                ("direct-reference", b"direct-material"),
            ]),
            ValidationOptions::default(),
        );
        let service = service();
        let baseline = coordinator
            .accept_source(source.clone(), source, ProxyDownstreamObfuscation::Unobfuscated)
            .await;
        let prepared = coordinator.materialize(baseline).await.expect("baseline");
        coordinator
            .publish(prepared, &service)
            .await
            .expect("publish baseline");

        let bundle = coordinator
            .credential_change(&known("bundle-reference"))
            .await
            .expect("bundle dependency");
        assert_eq!(bundle.selected_server_names(), &BTreeSet::from(["bundle-server".to_owned()]),);
        let direct = coordinator
            .credential_change(&known("direct-reference"))
            .await
            .expect("direct dependency");
        assert_eq!(direct.selected_server_names(), &BTreeSet::from(["direct-server".to_owned()]),);
        let unknown = coordinator
            .credential_change(&CredentialChangeScope::Unknown)
            .await
            .expect("unknown scope");
        assert_eq!(
            unknown.selected_server_names(),
            &BTreeSet::from(["bundle-server".to_owned(), "direct-server".to_owned()]),
        );
    }

    #[tokio::test]
    async fn equal_rematerialization_retains_active_server_arc() {
        let resolver = resolver(&[("object-a", b"same-material")]);
        let coordinator = MaterializationCoordinator::new(
            Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
            ValidationOptions::default(),
        );
        let service = service();
        let desired = source("object-a", "192.0.2.20");
        let attempt = coordinator
            .accept_source(desired.clone(), desired, ProxyDownstreamObfuscation::Unobfuscated)
            .await;
        let prepared = coordinator.materialize(attempt).await.expect("materialize");
        coordinator
            .publish(prepared, &service)
            .await
            .expect("publish");
        let first = coordinator.active_servers().await[0].clone();

        let attempt = coordinator
            .credential_change(&known("object-a"))
            .await
            .expect("credential attempt");
        let prepared = coordinator
            .materialize(attempt)
            .await
            .expect("rematerialize");
        coordinator
            .publish(prepared, &service)
            .await
            .expect("republish");
        let second = coordinator.active_servers().await[0].clone();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn changed_reference_with_equal_material_switches_dependency_and_retains_arc() {
        let resolver = resolver(&[
            ("object-a", b"same-material"),
            ("object-b", b"same-material"),
        ]);
        let coordinator = MaterializationCoordinator::new(
            Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
            ValidationOptions::default(),
        );
        let service = service();
        let first_source = source("object-a", "192.0.2.25");
        let first_attempt = coordinator
            .accept_source(
                first_source.clone(),
                first_source,
                ProxyDownstreamObfuscation::Unobfuscated,
            )
            .await;
        let first_prepared = coordinator.materialize(first_attempt).await.expect("first");
        coordinator
            .publish(first_prepared, &service)
            .await
            .expect("publish first");
        let first = coordinator.active_servers().await[0].clone();

        let second_source = source("object-b", "192.0.2.25");
        let second_attempt = coordinator
            .accept_source(
                second_source.clone(),
                second_source,
                ProxyDownstreamObfuscation::Unobfuscated,
            )
            .await;
        let second_prepared = coordinator
            .materialize(second_attempt)
            .await
            .expect("second");
        coordinator
            .publish(second_prepared, &service)
            .await
            .expect("publish second");
        let second = coordinator.active_servers().await[0].clone();

        assert!(Arc::ptr_eq(&first, &second));
        assert!(coordinator
            .credential_change(&known("object-a"))
            .await
            .is_none());
        assert_eq!(
            coordinator
                .credential_change(&known("object-b"))
                .await
                .expect("new dependency")
                .selected_server_names(),
            &BTreeSet::from(["primary".to_owned()]),
        );
    }

    #[tokio::test]
    async fn stale_materialization_completion_cannot_publish() {
        let coordinator = MaterializationCoordinator::new(
            resolver(&[
                ("object-a", b"first-material"),
                ("object-b", b"second-material"),
            ]),
            ValidationOptions::default(),
        );
        let service = service();
        let first = source("object-a", "192.0.2.30");
        let first_attempt = coordinator
            .accept_source(first.clone(), first, ProxyDownstreamObfuscation::Unobfuscated)
            .await;
        let first_prepared = coordinator.materialize(first_attempt).await.expect("first");
        let second = source("object-b", "192.0.2.31");
        let second_attempt = coordinator
            .accept_source(second.clone(), second, ProxyDownstreamObfuscation::Unobfuscated)
            .await;

        assert_eq!(
            coordinator
                .publish(first_prepared, &service)
                .await
                .expect("stale result"),
            PublicationOutcome::Superseded,
        );
        assert_eq!(service.server_count(), 0);
        let second_prepared = coordinator
            .materialize(second_attempt)
            .await
            .expect("second");
        assert_eq!(
            coordinator
                .publish(second_prepared, &service)
                .await
                .expect("publish second"),
            PublicationOutcome::Published,
        );
        assert_eq!(service.server_count(), 1);
    }

    #[tokio::test]
    async fn failed_new_reference_recovers_from_matching_credential_event() {
        let resolver = resolver(&[
            ("object-a", b"first-material"),
            ("object-b", b"second-material"),
        ]);
        let coordinator = MaterializationCoordinator::new(
            Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
            ValidationOptions::default(),
        );
        let service = service();
        let first = source("object-a", "192.0.2.40");
        let first_attempt = coordinator
            .accept_source(first.clone(), first, ProxyDownstreamObfuscation::Unobfuscated)
            .await;
        let first_prepared = coordinator.materialize(first_attempt).await.expect("first");
        coordinator
            .publish(first_prepared, &service)
            .await
            .expect("publish first");
        let known_good = coordinator.active_servers().await[0].clone();

        resolver
            .unavailable
            .lock()
            .expect("unavailable lock")
            .insert("object-b".to_owned());
        let second = source("object-b", "192.0.2.41");
        let second_attempt = coordinator
            .accept_source(second.clone(), second, ProxyDownstreamObfuscation::Unobfuscated)
            .await;
        assert!(coordinator.materialize(second_attempt).await.is_err());
        assert!(Arc::ptr_eq(&known_good, &coordinator.active_servers().await[0],));

        resolver
            .unavailable
            .lock()
            .expect("unavailable lock")
            .remove("object-b");
        let recovery = coordinator
            .credential_change(&known("object-b"))
            .await
            .expect("recovery attempt");
        let prepared = coordinator.materialize(recovery).await.expect("recover");
        coordinator
            .publish(prepared, &service)
            .await
            .expect("publish recovery");
        let recovered = coordinator.active_servers().await[0].clone();
        assert_eq!(recovered.address, "192.0.2.41");
        assert!(!Arc::ptr_eq(&known_good, &recovered));
    }
}
