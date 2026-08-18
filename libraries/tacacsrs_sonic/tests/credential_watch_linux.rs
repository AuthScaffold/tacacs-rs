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
        "temporary file must not trigger a reload"
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
        "burst must produce one signal"
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

    fs::write(root.join("object-1"), b"replacement-material")
        .expect("write object in replacement root");
    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("replacement root object signal timeout")
        .expect("replacement root object signal stream");
}

#[tokio::test]
async fn watcher_observes_root_created_after_startup() {
    let temp = tempfile::tempdir().expect("temporary credential parent");
    let root = temp.path().join("epsk");
    let mut signals = spawn_credential_change_notifier(root.clone(), Duration::from_millis(20))
        .await
        .expect("start credential watcher before root exists");

    fs::create_dir(&root).expect("create EPSK root");
    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("root creation signal timeout")
        .expect("root creation signal stream");

    fs::write(root.join("object-1"), b"created-after-startup")
        .expect("write object after root creation");
    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("new root object signal timeout")
        .expect("new root object signal stream");
}

#[tokio::test]
async fn watcher_coalesces_delete_recreate_and_root_replacement_races() {
    let temp = tempfile::tempdir().expect("temporary credential parent");
    let root = temp.path().join("epsk");
    fs::create_dir(&root).expect("create EPSK root");
    let object = root.join("object-1");
    fs::write(&object, b"first-valid-material").expect("seed object");
    let debounce = Duration::from_millis(40);
    let mut signals = spawn_credential_change_notifier(root.clone(), debounce)
        .await
        .expect("start credential watcher");

    fs::remove_file(&object).expect("delete object");
    fs::write(&object, b"second-valid-material").expect("recreate object");
    fs::rename(&root, temp.path().join("epsk-old")).expect("move old root");
    fs::create_dir(&root).expect("recreate root");
    fs::write(root.join("object-1"), b"final-valid-material").expect("write final object");

    tokio::time::timeout(Duration::from_secs(2), signals.recv())
        .await
        .expect("race signal timeout")
        .expect("race signal stream");
    assert!(
        tokio::time::timeout(debounce.saturating_mul(3), signals.recv())
            .await
            .is_err(),
        "race burst must produce one signal"
    );
    assert_eq!(
        fs::read(root.join("object-1")).expect("read final object"),
        b"final-valid-material"
    );
}
