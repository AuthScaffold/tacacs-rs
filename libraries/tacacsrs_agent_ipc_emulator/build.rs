fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: No other thread in this build script accesses the environment.
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .type_attribute(".", "#[allow(clippy::derive_partial_eq_without_eq)]")
        .compile_protos(&["proto/tacacsrs_agent_mock_controller.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/tacacsrs_agent_mock_controller.proto");
    Ok(())
}
