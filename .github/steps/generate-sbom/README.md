# Generate SBOM Action

This composite action generates Software Bill of Materials (SBOM) files for the tacacs-rs project using the CycloneDX standard.

## Purpose

Generates SBOM files to comply with supply chain security requirements, including:
- Executive Order on Improving the Nation's Cybersecurity
- Software supply chain transparency and security best practices

## Features

- Generates SBOM in CycloneDX format (OASIS standard)
- Supports both JSON and XML output formats
- Includes all workspace dependencies
- Lists dependency licenses and metadata
- Creates separate SBOM files for each workspace member

## Usage

```yaml
- name: Generate SBOM
  uses: ./.github/steps/generate-sbom
  with:
    output-format: json  # or xml
    manifest-path: executables/tacon/Cargo.toml
    describe: binaries
    target: x86_64-pc-windows-msvc
    target-in-filename: 'true'
```

## Inputs

- `output-format` (optional): Output format, either `json` or `xml`. Default: `json`
- `manifest-path` (optional): Path to the `Cargo.toml` to analyze. Default: unset
- `describe` (optional): CycloneDX describe mode. Default: unset
- `target` (optional): Rust target triple for dependency resolution. Default: host target
- `target-in-filename` (optional): Include the target triple in the generated filename. Default: `false`
- `features` (optional): Space-separated list of cargo features to enable. Default: unset
- `all-features` (optional): Enable all features when analyzing dependencies. Default: `false`

## Output

Generates SBOM files in the workspace directories.

For binary-targeted runs this includes files such as:
- `executables/tacon/tacon_bin_x86_64-unknown-linux-gnu.cdx.<format>`
- `executables/tacon/tacon_bin_x86_64-pc-windows-msvc.cdx.<format>`

When `manifest-path` and `describe: binaries` are not set, cargo-cyclonedx uses its default crate/workspace behavior and may emit files such as:
- `executables/tacon/tacon.cdx.<format>`
- `libraries/tacacsrs_messages/tacacsrs-messages.cdx.<format>`
- `libraries/tacacsrs_networking/tacacsrs-networking.cdx.<format>`

## Tool

Uses [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) to generate SBOMs.

## CycloneDX Standard

CycloneDX is a lightweight SBOM standard designed for use in application security contexts and supply chain component analysis. It is an OASIS Open standard and widely adopted across industries.

Learn more: https://cyclonedx.org/
