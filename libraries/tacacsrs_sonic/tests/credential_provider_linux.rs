#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::Path;

use tacacsrs_config::parse_yang_json;
use tacacsrs_credential_resolution::{
    CredentialResolver, ResolutionErrorKind, ResolutionPlan, ResolvedCredential,
};
use tacacsrs_sonic::{
    SonicCredentialInitializationError, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};
use tempfile::TempDir;

type UnsafeObjectScenario = (&'static str, fn(&Path));

fn configure_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

fn create_root() -> (TempDir, std::path::PathBuf, SonicCredentialPolicy) {
    let temp = tempfile::tempdir().expect("temporary root");
    let root = temp.path().join("epsk");
    fs::create_dir(&root).expect("create EPSK root");
    configure_mode(&root, 0o750);
    let metadata = fs::metadata(&root).expect("root metadata");
    let policy = SonicCredentialPolicy::new(metadata.uid(), metadata.gid());
    (temp, root, policy)
}

fn write_object(root: &Path, id: &str, bytes: &[u8]) {
    let path = root.join(id);
    fs::write(&path, bytes).expect("write EPSK object");
    configure_mode(&path, 0o640);
}

fn resolver(root: &Path, policy: SonicCredentialPolicy) -> SonicCredentialResolver {
    SonicCredentialResolver::open(
        SonicCredentialRoots::new(root, root.join("unused-acms-root")),
        policy,
    )
    .expect("open provider")
}

fn epsk_plan(reference: &str) -> ResolutionPlan {
    let reference = serde_json::to_string(reference).expect("serialize reference");
    let json = format!(
        r#"{{
            "ietf-system-tacacs-plus:tacacs-plus": {{
                "server": [{{
                    "name": "provider-test",
                    "server-type": "accounting",
                    "address": "192.0.2.50",
                    "port": 449,
                    "client-identity": {{
                        "tls13-epsk": {{
                            "central-keystore-reference": {reference},
                            "external-identity": "client"
                        }}
                    }}
                }}]
            }}
        }}"#
    );
    let config = parse_yang_json(&json).expect("central EPSK config");
    ResolutionPlan::from_server(&config.server[0]).expect("resolution plan")
}

fn certificate_plan() -> ResolutionPlan {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "certificate-test",
                    "server-type": "accounting",
                    "address": "192.0.2.51",
                    "port": 449,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "key-object",
                                "certificate": "certificate-object"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("central certificate config");
    ResolutionPlan::from_server(&config.server[0]).expect("resolution plan")
}

#[tokio::test]
async fn safe_regular_epsk_resolves_to_zeroizing_secret_bytes() {
    let (_temp, root, policy) = create_root();
    let expected = vec![0x5a; 32];
    write_object(&root, "valid-object", &expected);
    let provider = resolver(&root, policy);
    let plan = epsk_plan("valid-object");

    let material = provider
        .resolve(&plan.requests()[0])
        .await
        .expect("resolve EPSK");
    let ResolvedCredential::SymmetricKey(secret) = material else {
        panic!("expected symmetric key");
    };
    assert_eq!(secret.expose_secret(), expected);
}

#[tokio::test]
async fn unsafe_epsk_objects_are_rejected_with_sanitized_errors() {
    let scenarios: &[UnsafeObjectScenario] = &[
        ("wrong-mode", |root| {
            write_object(root, "wrong-mode", &[0x11; 32]);
            configure_mode(&root.join("wrong-mode"), 0o644);
        }),
        ("empty-object", |root| write_object(root, "empty-object", &[])),
        ("short-object", |root| write_object(root, "short-object", &[0x22; 15])),
        ("oversized", |root| write_object(root, "oversized", &vec![0x33; 4097])),
        ("directory", |root| {
            fs::create_dir(root.join("directory")).expect("create object directory");
            configure_mode(&root.join("directory"), 0o640);
        }),
        ("hard-link", |root| {
            write_object(root, "hard-link", &[0x44; 32]);
            fs::hard_link(root.join("hard-link"), root.join("hard-link-copy"))
                .expect("create hard link");
        }),
        ("symlink", |root| {
            write_object(root, "symlink-target", &[0x55; 32]);
            symlink("symlink-target", root.join("symlink")).expect("create symlink");
        }),
        ("fifo", |root| {
            let root_fd = rustix::fs::open(
                root,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .expect("open root");
            rustix::fs::mkfifoat(&root_fd, "fifo", rustix::fs::Mode::from_raw_mode(0o640))
                .expect("create FIFO");
        }),
        ("socket", |root| {
            UnixListener::bind(root.join("socket")).expect("create Unix socket");
            configure_mode(&root.join("socket"), 0o640);
        }),
    ];

    for (id, arrange) in scenarios {
        let (_temp, root, policy) = create_root();
        arrange(&root);
        let provider = resolver(&root, policy);
        let plan = epsk_plan(id);
        let error = provider
            .resolve(&plan.requests()[0])
            .await
            .expect_err("unsafe object must fail");
        assert_eq!(error.kind(), ResolutionErrorKind::InvalidMaterial, "scenario {id}");
        let rendered = format!("{error:?} {provider:?}");
        assert!(!rendered.contains(id));
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
    }
}

#[tokio::test]
async fn wrong_file_owner_and_group_are_rejected_when_privileged() {
    let (_temp, root, policy) = create_root();
    let root_metadata = fs::metadata(&root).expect("root metadata");
    if root_metadata.uid() != 0 {
        return;
    }

    write_object(&root, "wrong-owner", &[0x66; 32]);
    rustix::fs::chown(root.join("wrong-owner"), Some(rustix::fs::Uid::from_raw(1)), None)
        .expect("change owner");
    write_object(&root, "wrong-group", &[0x77; 32]);
    rustix::fs::chown(root.join("wrong-group"), None, Some(rustix::fs::Gid::from_raw(1)))
        .expect("change group");

    let provider = resolver(&root, policy);
    for id in ["wrong-owner", "wrong-group"] {
        let plan = epsk_plan(id);
        let error = provider
            .resolve(&plan.requests()[0])
            .await
            .expect_err("unsafe ownership must fail");
        assert_eq!(error.kind(), ResolutionErrorKind::InvalidMaterial);
        assert!(!error.to_string().contains(id));
    }
}

#[tokio::test]
async fn missing_and_invalid_references_fail_before_secret_reads() {
    let (_temp, root, policy) = create_root();
    let provider = resolver(&root, policy);

    let missing = epsk_plan("missing-object");
    let error = provider
        .resolve(&missing.requests()[0])
        .await
        .expect_err("missing object must fail");
    assert_eq!(error.kind(), ResolutionErrorKind::NotFound);

    for invalid in [
        "../escape",
        "/absolute",
        "C:\\absolute",
        "contains/slash",
        "contains\\slash",
        "_bad-start",
        "-bad-start",
        "nonascii-é",
        &"a".repeat(65),
    ] {
        let plan = epsk_plan(invalid);
        let error = provider
            .resolve(&plan.requests()[0])
            .await
            .expect_err("invalid reference must fail");
        assert_eq!(error.kind(), ResolutionErrorKind::InvalidMaterial);
        assert!(!error.to_string().contains(invalid));
    }
}

#[tokio::test]
async fn opaque_id_boundaries_resolve_only_from_the_epsk_root() {
    let (temp, root, policy) = create_root();
    let acms_root = temp.path().join("acms");
    fs::create_dir(&acms_root).expect("create ACMS root");
    configure_mode(&acms_root, 0o750);
    let one_byte_id = "a";
    let maximum_id = format!("b{}", "_".repeat(63));
    write_object(&root, one_byte_id, &[0x81; 16]);
    write_object(&root, &maximum_id, &[0x82; 32]);
    write_object(&acms_root, "acms-only", &[0x83; 32]);
    let provider =
        SonicCredentialResolver::open(SonicCredentialRoots::new(&root, &acms_root), policy)
            .expect("open provider");

    for (id, expected) in [
        (one_byte_id, &[0x81; 16][..]),
        (&maximum_id, &[0x82; 32][..]),
    ] {
        let plan = epsk_plan(id);
        let ResolvedCredential::SymmetricKey(secret) = provider
            .resolve(&plan.requests()[0])
            .await
            .expect("boundary ID resolves")
        else {
            panic!("expected symmetric key");
        };
        assert_eq!(secret.expose_secret(), expected);
    }

    let plan = epsk_plan("acms-only");
    let error = provider
        .resolve(&plan.requests()[0])
        .await
        .expect_err("EPSK requests cannot read the ACMS root");
    assert_eq!(error.kind(), ResolutionErrorKind::NotFound);
}

#[tokio::test]
async fn deferred_certificate_requests_are_rejected_without_accessing_acms() {
    let (_temp, root, policy) = create_root();
    let provider = resolver(&root, policy);
    let plan = certificate_plan();

    let error = provider
        .resolve(&plan.requests()[0])
        .await
        .expect_err("certificate provider is deferred");
    assert_eq!(error.kind(), ResolutionErrorKind::InvalidMaterial);
}

#[tokio::test]
async fn reloadable_provider_recovers_when_protected_root_appears() {
    let temp = tempfile::tempdir().expect("temporary parent");
    if fs::metadata(temp.path()).expect("parent metadata").uid() != 0 {
        return;
    }
    let root = temp.path().join("late-epsk-root");
    let provider = SonicCredentialResolver::reloadable(
        SonicCredentialRoots::new(&root, temp.path().join("unused-acms-root")),
        SonicCredentialPolicy::production_from_root_group(),
    );
    let plan = epsk_plan("late-object");

    let error = provider
        .resolve(&plan.requests()[0])
        .await
        .expect_err("missing root must be unavailable");
    assert_eq!(error.kind(), ResolutionErrorKind::Unavailable);

    fs::create_dir(&root).expect("create late root");
    configure_mode(&root, 0o750);
    write_object(&root, "late-object", &[0x88; 32]);

    let material = provider
        .resolve(&plan.requests()[0])
        .await
        .expect("reloadable provider recovers");
    let ResolvedCredential::SymmetricKey(secret) = material else {
        panic!("expected symmetric key");
    };
    assert_eq!(secret.expose_secret(), &[0x88; 32]);
}

#[test]
fn root_metadata_is_validated_before_provider_construction() {
    let (_temp, root, policy) = create_root();
    configure_mode(&root, 0o755);

    let error = SonicCredentialResolver::open(
        SonicCredentialRoots::new(&root, root.join("unused-acms-root")),
        policy,
    )
    .expect_err("unsafe root mode must fail");
    assert_eq!(error, SonicCredentialInitializationError::InvalidRootMetadata);
    assert!(!format!("{error:?}").contains(root.to_string_lossy().as_ref()));
}
