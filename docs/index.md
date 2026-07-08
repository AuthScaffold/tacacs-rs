# TACACS-rs Documentation

TACACS-rs is a Rust workspace for TACACS+ authentication, authorization, accounting, local agent IPC, SONiC integration, and compatibility surfaces for existing TACACS+ clients.

This site collects the project guides into a browsable static documentation set. The guides are organized by job: core tools first, then configuration and migration material, then platform-specific deployment guides.

## Start here

| Need | Guide |
| ---- | ----- |
| Send TACACS+ requests from the CLI | [tacon CLI](tacon.md) |
| Run the central local agent | [tacacsrs-agentd Daemon](tacacsrs-agentd.md) |
| Author RFC 7951 TACACS+ configuration | [YANG Configuration](yang-config-guide.md) |
| Move existing plain TACACS+ clients behind the local proxy | [Plain TACACS+ to TACACS+ over TLS](tacacs-plus-tls-transition.md) |
| Build or deploy on SONiC | [SONiC integration guides](#sonic-integration) |
| Deploy command authorization for SSH sessions | [Session Wrapper Deployment Guide](session-wrapper.md) |

## Guide boundaries

- [tacon CLI](tacon.md) covers client invocation, connection modes, batch files, and exit behavior.
- [tacacsrs-agentd Daemon](tacacsrs-agentd.md) covers daemon runtime behavior: local IPC, proxy mode, upstream encryption, connection reuse, and failover.
- [YANG Configuration](yang-config-guide.md) covers the RFC 7951 configuration model, parsing APIs, credential bundles, and generated-type workflow.
- [Plain TACACS+ to TACACS+ over TLS](tacacs-plus-tls-transition.md) covers operational migration for existing clients such as `pam_tacplus` and `audisp-tacplus`; it links back to the daemon guide for proxy reference details.

## SONiC integration

- [Building for SONiC](sonic-build-guide.md) covers Linux GNU binaries, Debian package-oriented validation, and container image builds.
- [SONiC ConfigDB Integration](sonic-configdb-integration.md) covers CONFIG_DB schema mapping, Redis notifications, hot reload behavior, and local smoke tests.
- [Running tacacsrs-agentd as a SONiC Docker container](sonic-agentd-container.md) covers the container run command, host networking rationale, Redis socket mount, and exposure checks.

## Session wrapper

- [Session Wrapper Deployment Guide](session-wrapper.md) covers SSH `ForceCommand`, login-shell integration, CLI options, security considerations, and troubleshooting.
- [Session Wrapper Testing](session-wrapper-testing.md) covers Linux smoke tests and integration checks for process mediation and descendant supervision.

## Source repository

The source code, release assets, issue tracker, and discussion area are available in the [AuthScaffold/tacacs-rs GitHub repository](https://github.com/AuthScaffold/tacacs-rs).
