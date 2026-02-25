use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("include");

    // Create the include directory if it doesn't exist
    std::fs::create_dir_all(&output_dir).unwrap();

    let output_file = output_dir.join("tacacs.h");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(
            cbindgen::Config::from_file("cbindgen.toml").expect("Failed to load cbindgen.toml"),
        )
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_file);
}
