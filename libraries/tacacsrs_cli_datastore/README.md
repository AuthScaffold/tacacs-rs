# tacacsrs-cli-datastore

CLI and file-backed datastore support for TACACS+ configuration inputs.

This crate adapts already-parsed command-line fields into validated
`tacacsrs_config::TacacsPlus` snapshots. It also provides a file-watching
`ConfigDatastore` for daemon workflows that need to reload when a YANG config
file or CLI-provided TLS certificate/key file changes.
