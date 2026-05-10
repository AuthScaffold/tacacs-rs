fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run in a single process context for this crate and
    // only need to point prost/tonic code generation at the vendored protoc.
    std::env::set_var("PROTOC", protoc);

    // Prost emits `PartialEq` (without `Eq`) for some composite message shapes.
    // Keep clippy strict elsewhere and suppress only on the affected generated
    // authorization reply envelope types.
    let allow_partial_eq = "#[allow(clippy::derive_partial_eq_without_eq)]";
    tonic_prost_build::configure()
        .type_attribute("tacacsrs.agent.v1.AuthorizationRequest", allow_partial_eq)
        .type_attribute("tacacsrs.agent.v1.AuthorizationResponse", allow_partial_eq)
        .type_attribute("tacacsrs.agent.v1.AuthorizationReply", allow_partial_eq)
        .type_attribute("tacacsrs.agent.v1.AuthorizationReply.result", allow_partial_eq)
        .compile_protos(&["proto/tacacsrs_agent.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/tacacsrs_agent.proto");
    Ok(())
}
