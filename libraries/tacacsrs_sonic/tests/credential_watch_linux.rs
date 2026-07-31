#![cfg(target_os = "linux")]

use std::fs;
use std::time::Duration;

use tacacsrs_sonic::spawn_credential_change_notifier;

#[tokio::test]
async fn watcher_ignores_temporary_files_and_coalesces_atomic_object_events() {
    let temp = tempfile::tempdir().expect("temporary credential parent");
    let root = temp.path().join("epsk");
    fs::create_dir(&root).expect("create EPSK root");
    let debounce = Duration::from_millis(40);
    let mut signals = spawn_credential_change_notifier(root.clone(), debounce)
        .await
        .expect("start credential watcher");

    let temporary = root.join(".object.tmp");
    fs::write(&temporary, b"partial").expect("write temporary object");
    assert!(
        tokio::time::timeout(debounce.saturating_mul(3), signals.recv())
            .await
            .is_err(),
        "temporary file should not trigger reload"
    );

    fs::rename(&temporary, root.join("object-1")).expect("atomic object rename");
    fs::write(root.join("object-2"), b"replacement").expect("second object event");
    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("object signal timeout")
        .expect("object signal stream");
    assert!(
        tokio::time::timeout(debounce.saturating_mul(3), signals.recv())
            .await
            .is_err(),
        "burst should coalesce to one signal"
    );
}

#[tokio::test]
async fn watcher_reports_provider_root_replacement() {
    let temp = tempfile::tempdir().expect("temporary credential parent");
    let root = temp.path().join("epsk");
    fs::create_dir(&root).expect("create EPSK root");
    let mut signals = spawn_credential_change_notifier(root.clone(), Duration::from_millis(20))
        .await
        .expect("start credential watcher");

    fs::rename(&root, temp.path().join("epsk-old")).expect("replace old root");
    fs::create_dir(&root).expect("create replacement root");

    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("root replacement signal timeout")
        .expect("root replacement signal stream");
}
