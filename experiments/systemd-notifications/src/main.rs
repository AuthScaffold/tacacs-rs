//! Isolated calls to the two candidate notification APIs.

fn main() {
    assert!(std::env::var_os("TACACSRS_NOTIFICATION_PROBE").is_some());
    assert!(std::env::var_os("NOTIFY_SOCKET").is_some());
    let candidate = std::env::args().nth(1).expect("candidate argument");
    eprintln!("notification started");
    let result = match candidate.as_str() {
        "sd-notify" => sd_notify::notify(&[sd_notify::NotifyState::Ready]),
        "libsystemd" => {
            libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
                .map(|_| ())
                .map_err(std::io::Error::other)
        }
        _ => panic!("unknown candidate: {candidate}"),
    };
    match result {
        Ok(()) => println!("notification sent"),
        Err(error) => {
            eprintln!("notification failed: {error}");
            std::process::exit(1);
        }
    }
}
