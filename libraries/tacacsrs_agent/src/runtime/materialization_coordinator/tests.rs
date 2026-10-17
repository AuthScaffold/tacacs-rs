use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crate::{
    EnabledServices, PreparedProxyPolicy, RuntimeHealthPublisher, ServiceConfig,
    TacacsClientService,
};
use tacacsrs_credential_resolution::SymmetricKeyFormat;
use tacacsrs_config::{TacacsPlus, ValidationOptions, parse_yang_json};
use tacacsrs_credential_resolution::{
    CredentialChangeScope, CredentialReference, CredentialRequest, CredentialResolver,
    ProviderErrorKind, ResolutionError, ResolvedCredential, SecretBytes, SymmetricKeyMaterial,
};

use super::*;

struct MutableResolver {
    unavailable: Mutex<BTreeSet<String>>,
    material: Mutex<BTreeMap<String, Vec<u8>>>,
    validity: Mutex<BTreeMap<String, tacacsrs_credential_resolution::CredentialValidity>>,
}

struct BlockingResolver {
    inner: Arc<MutableResolver>,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl CredentialResolver for BlockingResolver {
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        if request.reference().symmetric_key() == Some("object-a") {
            self.started.notify_one();
            self.release.notified().await;
        }
        self.inner.resolve(request).await
    }
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
            validity: self
                .validity
                .lock()
                .unwrap()
                .get(reference)
                .copied()
                .unwrap_or_default(),
            key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
            key: SecretBytes::new(key),
        }))
    }
}

fn resolver(entries: &[(&str, &[u8])]) -> Arc<MutableResolver> {
    Arc::new(MutableResolver {
        unavailable: Mutex::new(BTreeSet::new()),
        validity: Mutex::new(BTreeMap::new()),
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
    service_with_health(health)
}

fn service_with_health(health: RuntimeHealthPublisher) -> TacacsClientService {
    TacacsClientService::waiting_for_configuration(
        ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: TacacsPlus::empty(),
            validation_options: ValidationOptions::default(),
            runtime_policy: crate::RuntimePolicy::new(
                crate::FailoverStrategy::default(),
                crate::FailoverStrategy::default(),
                crate::OperationPolicies::default(),
                Duration::from_secs(1),
            )
            .expect("test runtime policy"),
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

#[tokio::test(start_paused = true)]
async fn validity_survives_partial_refresh_and_expiry_blocks_publication() {
    use std::time::SystemTime;
    use tacacsrs_credential_resolution::CredentialValidity;
    let resolver = resolver(&[
        ("object-a", b"valid-material-long-enough"),
        ("object-b", b"other-valid-material-long-enough"),
    ]);
    resolver.validity.lock().unwrap().insert(
        "object-a".to_owned(),
        CredentialValidity::new(None, Some(SystemTime::now() + Duration::from_secs(10))).unwrap(),
    );
    let coordinator =
        MaterializationCoordinator::new(resolver.clone(), ValidationOptions::default());
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = service_with_health(health.clone());
    let mut canonical = source("object-a", "192.0.2.20");
    let mut secondary = source("object-b", "192.0.2.21").server.remove(0);
    secondary.name = "secondary".to_owned();
    canonical.server.push(secondary);
    let attempt = coordinator
        .accept_source(canonical.clone(), canonical.clone(), PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    let lifetime = health.snapshot().credential_lifetime().unwrap();
    tokio::time::advance(Duration::from_secs(5)).await;
    let refresh = coordinator
        .credential_change(&known("object-b"))
        .await
        .unwrap();
    let prepared = coordinator.materialize(refresh).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(health.snapshot().credential_lifetime(), Some(lifetime));
    service
        .reload_runtime_policy(crate::RuntimePolicy::default())
        .await
        .unwrap();
    assert_eq!(health.snapshot().credential_lifetime(), Some(lifetime));
    let revision = health.snapshot().materialization_revision().unwrap();
    let refresh = coordinator
        .credential_change(&known("object-b"))
        .await
        .unwrap();
    let prepared = coordinator.materialize(refresh).await.unwrap();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(coordinator.publish(prepared, &service).await.is_err());
    assert_eq!(health.snapshot().materialization_revision(), Some(revision));
    coordinator
        .expire_material(MaterialExpiry::Credentials, revision, &service, &health)
        .await
        .unwrap();
    assert_eq!(service.server_count(), 0);
    resolver.validity.lock().unwrap().clear();
    let refresh = coordinator
        .credential_change(&known("object-b"))
        .await
        .unwrap();
    let prepared = coordinator.materialize(refresh).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(service.server_count(), 2);
    assert_eq!(coordinator.state.lock().await.desired_source.as_deref(), Some(&canonical));
}

#[tokio::test(start_paused = true)]
async fn validity_expiring_after_preparation_cannot_publish() {
    use std::time::SystemTime;
    use tacacsrs_credential_resolution::CredentialValidity;
    let resolver = resolver(&[("object-a", b"valid-material-long-enough")]);
    resolver.validity.lock().unwrap().insert(
        "object-a".to_owned(),
        CredentialValidity::new(None, Some(SystemTime::now() + Duration::from_secs(1))).unwrap(),
    );
    let coordinator = MaterializationCoordinator::new(resolver, ValidationOptions::default());
    let canonical = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(canonical.clone(), canonical, PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    let service = service();
    assert!(coordinator.publish(prepared, &service).await.is_err());
    assert!(coordinator.active_servers().await.is_empty());
    assert_eq!(service.server_count(), 0);
}

#[tokio::test]
async fn pending_filter_blocks_old_source_refresh_and_keeps_credential_revision() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[("object-a", b"valid-material-long-enough")]),
        ValidationOptions::default(),
    );
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = service_with_health(health.clone());
    let original = source("object-a", "192.0.2.20");
    let baseline = coordinator
        .accept_source(original.clone(), original, PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(baseline).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    let candidate = source("object-a", "192.0.2.21");
    let revision = coordinator.admit_source(candidate.clone()).await;
    assert!(coordinator
        .credential_change(&known("object-a"))
        .await
        .is_none());
    let filtered = coordinator
        .accept_filtered_source(revision, candidate.clone(), PreparedProxyPolicy::unobfuscated())
        .await
        .unwrap();
    assert_eq!(filtered.revision.source(), revision);
    assert_eq!(filtered.revision.credentials().value(), 1);
    let prepared = coordinator.materialize(filtered).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(coordinator.active_servers().await[0].address, "192.0.2.21");
    assert_eq!(coordinator.state.lock().await.desired_source.as_deref(), Some(&candidate));
    assert_eq!(
        health
            .snapshot()
            .materialization_revision()
            .unwrap()
            .source(),
        revision
    );
}

#[tokio::test]
async fn source_and_credential_revisions_are_independent_and_commit_with_health() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[("object-a", b"valid-material-long-enough")]),
        ValidationOptions::default(),
    );
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = service_with_health(health.clone());
    let canonical = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(canonical.clone(), canonical.clone(), PreparedProxyPolicy::unobfuscated())
        .await;
    assert_eq!(attempt.revision.source().value(), 1);
    assert_eq!(attempt.revision.credentials().value(), 0);
    let prepared = coordinator.materialize(attempt.clone()).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(health.snapshot().materialization_revision(), Some(attempt.revision));
    assert!(coordinator
        .credential_change(&known("unreferenced"))
        .await
        .is_none());
    let rotation = coordinator
        .credential_change(&known("object-a"))
        .await
        .unwrap();
    assert_eq!(rotation.revision.source(), attempt.revision.source());
    assert_eq!(rotation.revision.credentials().value(), 1);
    assert_eq!(health.snapshot().materialization_revision(), Some(attempt.revision));
    let prepared = coordinator.materialize(rotation.clone()).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(health.snapshot().materialization_revision(), Some(rotation.revision));
    service
        .reload_runtime_policy(crate::RuntimePolicy::default())
        .await
        .unwrap();
    assert_eq!(health.snapshot().materialization_revision(), Some(rotation.revision));
    let applied_policy = health.snapshot().applied_policy_revision().unwrap();
    assert!(
        !coordinator
            .report_credential_result(&attempt, &health, true)
            .await
    );
    assert!(!health
        .snapshot()
        .degradation_reasons()
        .contains(&crate::DegradationReason::CredentialResolutionFailed));
    let refresh = coordinator
        .accept_source(canonical.clone(), canonical.clone(), PreparedProxyPolicy::unobfuscated())
        .await;
    assert_eq!(refresh.revision.source().value(), 2);
    assert_eq!(refresh.revision.credentials(), rotation.revision.credentials());
    assert_eq!(coordinator.state.lock().await.desired_source.as_deref(), Some(&canonical));
    let prepared = coordinator.materialize(refresh.clone()).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_eq!(health.snapshot().materialization_revision(), Some(refresh.revision));
    assert_eq!(health.snapshot().applied_policy_revision(), Some(applied_policy));
    service
        .reload_materialized_servers_with_proxy_downstream_obfuscation(
            coordinator.active_servers().await,
            PreparedProxyPolicy::unobfuscated(),
        )
        .await
        .unwrap();
    assert!(health.snapshot().materialization_revision().is_none());
}

#[tokio::test]
async fn cancellation_after_runtime_publication_retains_matching_active_material() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[
            ("object-a", b"valid-baseline-psk-material"),
            ("object-b", b"second-baseline-psk-material"),
        ]),
        ValidationOptions::default(),
    );
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = service_with_health(health.clone());
    let mut candidate = source("object-a", "192.0.2.20");
    let mut secondary = source("object-b", "192.0.2.21").server.remove(0);
    secondary.name = "secondary".to_owned();
    candidate.server.push(secondary);
    let original = candidate.clone();
    let attempt = coordinator
        .accept_source(candidate.clone(), candidate, PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    health.set_degraded(crate::DegradationReason::CredentialResolutionFailed, true);
    service.pause_next_publication();
    {
        let publishing = coordinator.publish(prepared, &service);
        tokio::pin!(publishing);
        tokio::select! {
            result = &mut publishing => panic!("publication must pause: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(1), async {
                while service.server_count() != 2 { tokio::task::yield_now().await; }
            }) => result.expect("runtime publication must complete"),
        }
        let active = tokio::time::timeout(Duration::from_secs(1), coordinator.active_servers())
            .await
            .expect("retirement must not retain the coordinator lock");
        assert_eq!(active.len(), 2);
    }
    assert_eq!(service.server_count(), 2);
    let active = coordinator.active_servers().await;
    assert_eq!(active.len(), 2, "coordinator must commit before post-publication cancellation");
    assert_eq!(active[0].address, "192.0.2.20");
    assert_eq!(health.snapshot().runtime_generation().unwrap().value(), 1);
    assert_eq!(
        health
            .snapshot()
            .materialization_revision()
            .unwrap()
            .source()
            .value(),
        1
    );
    assert!(!health
        .snapshot()
        .degradation_reasons()
        .contains(&crate::DegradationReason::CredentialResolutionFailed));
    assert_eq!(coordinator.state.lock().await.desired_source.as_deref(), Some(&original));
    let refresh = coordinator
        .credential_change(&known("object-a"))
        .await
        .unwrap();
    assert_eq!(refresh.selected_server_names(), &BTreeSet::from(["primary".to_owned()]));
    let refreshed = coordinator.materialize(refresh).await.unwrap();
    coordinator.publish(refreshed, &service).await.unwrap();
    assert!(Arc::ptr_eq(&active[1], &coordinator.active_servers().await[1]));
    assert_eq!(health.snapshot().runtime_generation().unwrap().value(), 2);
}

#[tokio::test]
async fn cancellation_before_runtime_publication_leaves_active_material_unchanged() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[("object-a", b"valid-baseline-psk-material")]),
        ValidationOptions::default(),
    );
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = service_with_health(health.clone());
    let candidate = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(candidate.clone(), candidate, PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    let previous_health = health.snapshot();
    let held = service.hold_publication().await;
    {
        let publishing = coordinator.publish(prepared, &service);
        tokio::pin!(publishing);
        assert!(futures_util::poll!(&mut publishing).is_pending());
    }
    drop(held);
    assert_eq!(service.server_count(), 0);
    assert!(coordinator.active_servers().await.is_empty());
    assert_eq!(health.snapshot(), previous_health);
}

#[tokio::test]
async fn invalid_native_credentials_cannot_replace_active_generation() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[("object-a", b"valid-baseline-psk-material")]),
        ValidationOptions::default(),
    );
    let service = service();
    let baseline = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(baseline.clone(), baseline, PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    let active = coordinator.active_servers().await;

    let invalid = TacacsPlus {
        client_credentials: Vec::new(),
        server_credentials: Vec::new(),
        server: vec![tacacsrs_config::TacacsPlusServerBuilder::new(
            "primary",
            tacacsrs_config::TacacsPlusServerType::all(),
            "192.0.2.21",
            449,
        )
        .with_tls_client_certificate(
            Some(b"not-a-der-certificate".to_vec()),
            Some(b"private-test-material".to_vec()),
        )
        .build()],
    };
    let attempt = coordinator
        .accept_source(invalid.clone(), invalid, PreparedProxyPolicy::unobfuscated())
        .await;
    let result = match coordinator.materialize(attempt).await {
        Ok(prepared) => coordinator.publish(prepared, &service).await,
        Err(error) => Err(error),
    };
    assert!(result.is_err(), "invalid native material must fail before publication");
    assert!(Arc::ptr_eq(&active[0], &coordinator.active_servers().await[0]));
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
            ("bundle-reference", b"bundle-material-long-enough"),
            ("direct-reference", b"direct-material-long-enough"),
        ]),
        ValidationOptions::default(),
    );
    let service = service();
    let baseline = coordinator
        .accept_source(source.clone(), source, PreparedProxyPolicy::unobfuscated())
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
    let old = coordinator.materialize(bundle).await.unwrap();
    let direct = coordinator
        .credential_change(&known("direct-reference"))
        .await
        .expect("direct dependency");
    assert_eq!(
        direct.selected_server_names(),
        &BTreeSet::from(["bundle-server".to_owned(), "direct-server".to_owned()])
    );
    assert_eq!(coordinator.publish(old, &service).await.unwrap(), PublicationOutcome::Superseded);
    let current = coordinator.materialize(direct).await.unwrap();
    coordinator.publish(current, &service).await.unwrap();
    let direct = coordinator
        .credential_change(&known("direct-reference"))
        .await
        .unwrap();
    assert_eq!(direct.selected_server_names(), &BTreeSet::from(["direct-server".to_owned()]));
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
    let resolver = resolver(&[("object-a", b"same-material-long-enough")]);
    let coordinator = MaterializationCoordinator::new(
        Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
        ValidationOptions::default(),
    );
    let service = service();
    let desired = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(desired.clone(), desired, PreparedProxyPolicy::unobfuscated())
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
        ("object-a", b"same-material-long-enough"),
        ("object-b", b"same-material-long-enough"),
    ]);
    let coordinator = MaterializationCoordinator::new(
        Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
        ValidationOptions::default(),
    );
    let service = service();
    let first_source = source("object-a", "192.0.2.25");
    let first_attempt = coordinator
        .accept_source(first_source.clone(), first_source, PreparedProxyPolicy::unobfuscated())
        .await;
    let first_prepared = coordinator.materialize(first_attempt).await.expect("first");
    coordinator
        .publish(first_prepared, &service)
        .await
        .expect("publish first");
    let first = coordinator.active_servers().await[0].clone();

    let second_source = source("object-b", "192.0.2.25");
    let second_attempt = coordinator
        .accept_source(second_source.clone(), second_source, PreparedProxyPolicy::unobfuscated())
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
async fn blocked_old_resolution_cannot_replace_new_yang_snapshot() {
    let resolver = Arc::new(BlockingResolver {
        inner: resolver(&[
            ("object-a", b"first-material-long-enough"),
            ("object-b", b"second-material-long-enough"),
        ]),
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let coordinator = Arc::new(MaterializationCoordinator::new(
        Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
        ValidationOptions::default(),
    ));
    let service = service();
    let first = source("object-a", "192.0.2.30");
    let first_attempt = coordinator
        .accept_source(first.clone(), first, PreparedProxyPolicy::unobfuscated())
        .await;
    let preparing = Arc::clone(&coordinator);
    let old_task = tokio::spawn(async move { preparing.materialize(first_attempt).await });
    tokio::time::timeout(Duration::from_secs(5), resolver.started.notified())
        .await
        .expect("old resolution must reach the barrier");

    let current_source = source("object-b", "192.0.2.31");
    let current_attempt = coordinator
        .accept_source(
            current_source.clone(),
            current_source.clone(),
            PreparedProxyPolicy::unobfuscated(),
        )
        .await;
    let prepared = coordinator.materialize(current_attempt).await.unwrap();
    assert_eq!(
        coordinator.publish(prepared, &service).await.unwrap(),
        PublicationOutcome::Published
    );
    resolver.release.notify_one();
    let old_prepared = tokio::time::timeout(Duration::from_secs(5), old_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        coordinator.publish(old_prepared, &service).await.unwrap(),
        PublicationOutcome::Superseded
    );
    assert_eq!(coordinator.active_servers().await[0].address, "192.0.2.31");
    let state = coordinator.state.lock().await;
    assert_eq!(state.desired_source.as_deref(), Some(&current_source));
    assert_eq!(state.desired_runtime_source.as_deref(), Some(&current_source));
}

#[tokio::test]
async fn credential_rotation_preserves_authoritative_yang_references() {
    let resolver = resolver(&[("object-a", b"first-material-long-enough")]);
    let coordinator = MaterializationCoordinator::new(
        Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
        ValidationOptions::default(),
    );
    let service = service();
    let desired = source("object-a", "192.0.2.20");
    let attempt = coordinator
        .accept_source(desired.clone(), desired.clone(), PreparedProxyPolicy::unobfuscated())
        .await;
    let prepared = coordinator.materialize(attempt).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    let original = coordinator.active_servers().await[0].clone();

    resolver
        .unavailable
        .lock()
        .unwrap()
        .insert("object-a".to_owned());
    let failed = coordinator
        .credential_change(&known("object-a"))
        .await
        .unwrap();
    assert!(coordinator.materialize(failed).await.is_err());
    assert!(Arc::ptr_eq(&original, &coordinator.active_servers().await[0]));
    assert_eq!(coordinator.state.lock().await.desired_source.as_deref(), Some(&desired));

    resolver
        .material
        .lock()
        .unwrap()
        .insert("object-a".to_owned(), b"second-material-long-enough".to_vec());
    resolver.unavailable.lock().unwrap().remove("object-a");
    let rotated = coordinator
        .credential_change(&known("object-a"))
        .await
        .unwrap();
    let prepared = coordinator.materialize(rotated).await.unwrap();
    coordinator.publish(prepared, &service).await.unwrap();
    assert_ne!(original.as_ref(), coordinator.active_servers().await[0].as_ref());
    let state = coordinator.state.lock().await;
    assert_eq!(state.desired_source.as_deref(), Some(&desired));
    assert_eq!(state.desired_runtime_source.as_deref(), Some(&desired));
}

#[tokio::test]
async fn stale_materialization_completion_cannot_publish() {
    let coordinator = MaterializationCoordinator::new(
        resolver(&[
            ("object-a", b"first-material-long-enough"),
            ("object-b", b"second-material-long-enough"),
        ]),
        ValidationOptions::default(),
    );
    let service = service();
    let first = source("object-a", "192.0.2.30");
    let first_attempt = coordinator
        .accept_source(first.clone(), first, PreparedProxyPolicy::unobfuscated())
        .await;
    let first_prepared = coordinator.materialize(first_attempt).await.expect("first");
    let second = source("object-b", "192.0.2.31");
    let second_attempt = coordinator
        .accept_source(second.clone(), second, PreparedProxyPolicy::unobfuscated())
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
async fn failed_attempt_identity_becomes_superseded_after_new_source() {
    let resolver = resolver(&[
        ("first", b"first-material-long-enough"),
        ("second", b"second-material-long-enough"),
    ]);
    let coordinator = MaterializationCoordinator::new(resolver, ValidationOptions::default());
    let first_source = source("first", "192.0.2.10");
    let first = coordinator
        .accept_source(first_source.clone(), first_source, PreparedProxyPolicy::unobfuscated())
        .await;
    let second_source = source("second", "192.0.2.11");
    let second = coordinator
        .accept_source(second_source.clone(), second_source, PreparedProxyPolicy::unobfuscated())
        .await;

    assert!(!coordinator.is_current_attempt(&first).await);
    assert!(coordinator.is_current_attempt(&second).await);
}

#[tokio::test]
async fn failed_new_reference_recovers_from_matching_credential_event() {
    let resolver = resolver(&[
        ("object-a", b"first-material-long-enough"),
        ("object-b", b"second-material-long-enough"),
    ]);
    let coordinator = MaterializationCoordinator::new(
        Arc::clone(&resolver) as Arc<dyn CredentialResolver>,
        ValidationOptions::default(),
    );
    let service = service();
    let first = source("object-a", "192.0.2.40");
    let first_attempt = coordinator
        .accept_source(first.clone(), first, PreparedProxyPolicy::unobfuscated())
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
        .accept_source(second.clone(), second, PreparedProxyPolicy::unobfuscated())
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
