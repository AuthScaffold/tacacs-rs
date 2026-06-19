# TACACS-rs Documentation

TACACS-rs is a Rust workspace for TACACS+ authentication, authorization, accounting, local agent IPC, SONiC integration, and compatibility surfaces for existing TACACS+ clients.

This site collects the project guides into a browsable static documentation set. Start with the CLI and daemon guides for day-to-day usage, then use the configuration and platform guides for deployment-specific work.

## Primary guides

- [tacon Usage Guide](tacon.md) - CLI client reference, connection modes, batch execution, and debugging flags.
- [tacacsrs-agentd Usage Guide](tacacsrs-agentd.md) - Central daemon deployment, local IPC, failover behavior, and TACACS+ proxy mode.
- [YANG Config Guide](yang-config-guide.md) - RFC 7951 TACACS+ configuration shape, parsing APIs, credential bundles, and TLS key material formats.
- [Plain TACACS+ to TACACS+ over TLS Transition Guide](tacacs-plus-tls-transition.md) - Host-by-host migration for existing plain TACACS+ clients.

## Platform and integration guides

- [Building for SONiC](sonic-build-guide.md) - Linux GNU binaries and Debian packages for SONiC switches.
- [SONiC ConfigDB Integration](sonic-configdb-integration.md) - Mapping SONiC TACACS+ ConfigDB data into TACACS-rs configuration.
- [Session Wrapper Deployment Guide](session-wrapper.md) - SSH `ForceCommand` integration and command authorization flow.
- [Session Wrapper Testing](session-wrapper-testing.md) - Linux smoke and integration checks for the session wrapper.

## Source repository

The source code, release assets, issue tracker, and discussion area are available in the [AuthScaffold/tacacs-rs GitHub repository](https://github.com/AuthScaffold/tacacs-rs).
