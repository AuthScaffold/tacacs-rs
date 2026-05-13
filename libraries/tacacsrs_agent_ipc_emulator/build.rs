fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run in a single process context for this crate and
    // only need to point prost/tonic code generation at the vendored protoc.
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure()
        .type_attribute(".", "#[allow(clippy::derive_partial_eq_without_eq)]")
        .compile_protos(&["proto/tacacsrs_agent_mock_controller.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/tacacsrs_agent_mock_controller.proto");
    Ok(())
}
