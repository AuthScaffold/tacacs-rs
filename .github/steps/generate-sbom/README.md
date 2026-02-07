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
    all-features: 'true' # optional, default 'false'
```

## Inputs

- `output-format` (optional): Output format, either `json` or `xml`. Default: `json`
- `all-features` (optional): Enable all features when analyzing dependencies. Default: `false`

## Output

Generates SBOM files in the workspace directories:
- `executables/tacon/tacon.cdx.<format>`
- `libraries/tacacsrs_messages/tacacsrs-messages.cdx.<format>`
- `libraries/tacacsrs_networking/tacacsrs-networking.cdx.<format>`

## Tool

Uses [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) to generate SBOMs.

## CycloneDX Standard

CycloneDX is a lightweight SBOM standard designed for use in application security contexts and supply chain component analysis. It is an OASIS Open standard and widely adopted across industries.

Learn more: https://cyclonedx.org/
