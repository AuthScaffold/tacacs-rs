use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=LIBSECCOMP_LIB_PATH");
    println!("cargo:rerun-if-env-changed=LIBSECCOMP_LINK_TYPE");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();

    if target_os == "linux"
        && target_arch == "x86_64"
        && target_env == "musl"
        && musl_uses_static_crt(&target)
    {
        assert!(
            libseccomp_static_link_is_available(),
            "session-wrapper cannot link dynamic libseccomp while using musl's static CRT. \
             Install a musl-targeted static libseccomp and build with \
             LIBSECCOMP_LINK_TYPE=static LIBSECCOMP_LIB_PATH=/path/to/lib, or use \
             RUSTFLAGS='-C target-feature=-crt-static' for a dynamically linked Alpine \
             development build. See executables/session_wrapper/README.alpine.md."
        );
    }
}

fn musl_uses_static_crt(target: &str) -> bool {
    if rustflags_disable_crt_static() {
        return false;
    }

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let Ok(output) = Command::new(rustc)
        .args(["--print", "cfg", "--target", target])
        .output()
    else {
        return true;
    };

    if !output.status.success() {
        return true;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line == r#"target_feature="crt-static""#)
}

fn rustflags_disable_crt_static() -> bool {
    let flags = rustflags();
    let mut disables_crt_static = false;

    for (index, flag) in flags.iter().enumerate() {
        let target_feature = if flag == "-C" {
            flags.get(index + 1).map(String::as_str)
        } else {
            flag.strip_prefix("-C")
        };

        if let Some(target_feature) = target_feature {
            if !target_feature.starts_with("target-feature=") {
                continue;
            }
            if target_feature.contains("-crt-static") {
                disables_crt_static = true;
            }
            if target_feature.contains("+crt-static") {
                disables_crt_static = false;
            }
        }
    }

    disables_crt_static
}

fn rustflags() -> Vec<String> {
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if !encoded.is_empty() {
        return encoded.split('\x1f').map(str::to_owned).collect();
    }

    env::var("RUSTFLAGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn libseccomp_static_link_is_available() -> bool {
    if env::var("LIBSECCOMP_LINK_TYPE").is_ok_and(|link_type| link_type == "static") {
        return true;
    }

    let mut search_dirs = Vec::new();
    if let Ok(path) = env::var("LIBSECCOMP_LIB_PATH") {
        search_dirs.push(path);
    }
    search_dirs.extend([
        "/usr/lib".to_owned(),
        "/usr/local/lib".to_owned(),
        "/lib".to_owned(),
    ]);

    search_dirs
        .iter()
        .any(|dir| Path::new(dir).join("libseccomp.a").is_file())
}
