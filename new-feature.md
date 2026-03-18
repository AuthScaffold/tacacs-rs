Introduce a **central TACACS+ client service** that can be used by multiple local services to perform TACACS+ operations for:

- Authentication (AuthN)
- Authorization (AuthZ)
- Accounting / Auditing

The service should accept a configured ordered list of TACACS+ servers, establish and maintain server connections, and execute TACACS+ transactions on behalf of local consumers.

This is primarily targeted at **Linux**, but it should also work on **Windows** so developers can build, test, and debug against it in a non-Linux environment.

The service should maintain **persistent connections** to TACACS+ servers rather than opening a new TACACS+ connection for each transaction.

### Initial scope
As the first integration target, update **TACON** to execute TACACS+ transactions through the central TACACS+ client service instead of handling TACACS+ server communication directly.

### IPC / service interface
The IPC protocol should be **gRPC-like**, but the transport and security model should follow the guidance in the repository wiki page on secure IPC for a central TACACS+ client on Linux:
https://github.com/AuthScaffold/tacacs-rs/wiki/Secure-IPC-for-a-Central-TACACS-Client-on-Linux

On Linux, the IPC transport should use a local **Unix domain socket**. The socket should be placed in a protected path such as `/run/tacacs.sock` so access can be restricted through filesystem permissions while still providing efficient local IPC.

On Windows, the IPC transport should use **named pipes** as the closest local IPC analogue to Unix domain sockets. If named-pipe support proves unnecessarily complex for the initial developer workflow, a loopback-only HTTP transport is an acceptable development fallback.

Regardless of transport, the IPC layer should use the **same packet/message format on both Linux and Windows**. If the service protocol is defined using JSON, FlatBuffers, Protobuf, or another schema format, that same on-the-wire message format should be used across platforms.

The implementation should aim for:
- A clean request/response API for TACACS+ transactions
- A transport appropriate for local secure IPC
- A design that can support Linux production usage and Windows developer workflows

#### Additional design guidance for the central TACACS+ client service:

- The RPC/API format should **not expose TACACS+ header information** directly to callers.
- The service interface should present a higher-level abstraction over TACACS+ transactions rather than mirroring the wire protocol.
- While some future transaction types, such as **ASCII authentication**, may require **multi-legged/session-oriented flows**, most transactions are expected to fit a **simple request/reply** model.
- The client that communicates with the TACACS+ client service can be designed to establish **IPC connections per session**.

Implications for the service design:
- Favor an RPC contract centered on TACACS+ operations and typed request/response payloads, rather than raw packet/header fields.
- Support both:
  - straightforward single request/reply transactions, and
  - extensible session-oriented flows for multi-step exchanges in the future.
- The IPC layer should make per-session client connections practical without requiring callers to manage TACACS+ protocol details.
- The message schema should be transport-independent so the same request and response encoding can be used over Unix domain sockets on Linux and named pipes or loopback HTTP on Windows.
- For session-oriented flows, the service should treat each client IPC connection as bound to a specific active TACACS+ server connection for the lifetime of that session.
- If that TACACS+ server connection fails, all IPC sessions bound to it should fail and receive an error response rather than being migrated to another server connection transparently.

### Failover behavior
A key requirement is robust TACACS+ server failover behavior.

For failover purposes, a server should be considered **non-responsive** if:
- an existing connection closes with a failure, or
- a new connection cannot be established within a reasonable timeout.

Given an ordered list of TACACS+ servers, the service should behave as follows:

1. The first server in the configured list is the preferred server and should be used for new sessions when it is available.
2. If the server currently assigned to new sessions becomes non-responsive, the service should fail over to the next server in the configured order.
3. If the end of the list is reached, server selection should wrap around to the first server.
4. While operating on a non-primary server, the service should periodically probe the preferred server to determine whether it has recovered.
5. Once the preferred server is available again, the service should route **new sessions** to it.
6. Existing sessions should remain bound to their current TACACS+ server connection until they complete, after which the previously active server connection can be disconnected.
7. If a TACACS+ server connection fails, all IPC sessions bound to that connection should fail and receive an error. Retrying the affected request is the responsibility of the IPC client.

### Goals
- Provide a single reusable TACACS+ client service for local consumers.
- Centralize TACACS+ connection management and session handling logic.
- Improve resilience through ordered failover and preferred-server recovery.
- Enable TACON to consume TACACS+ functionality through the service.
- Preserve a development workflow that works on Linux and remains usable on Windows for testing and debugging.

### Non-goals
- Implementing TACACS+ authentication in the initial version of the central service is out of scope.
- Implementing TACACS+ authorization in the initial version of the central service is out of scope.
- Expanding the first integration beyond the TACACS+ accounting flow currently supported by the codebase is out of scope.
- Authentication and authorization support are expected to be added in future work after the accounting-based service integration is in place.

### Acceptance criteria
- A local central TACACS+ client service can be started and can accept requests from local consumers.
- TACON can be configured to issue TACACS+ requests through the central TACACS+ client service instead of talking to TACACS+ servers directly.
- The initial implementation supports the TACACS+ accounting flow currently supported by the codebase.
- The service accepts a configured ordered list of TACACS+ servers and maintains persistent connections to those servers rather than opening a new TACACS+ connection per transaction.
- The service exposes a gRPC-like IPC API that presents TACACS+ operations as higher-level typed requests and responses rather than raw TACACS+ headers or packet fields.
- The IPC design and security model align with the secure IPC guidance in the repository wiki for Linux deployment.
- On Linux, the IPC transport uses a local Unix domain socket in a protected filesystem location.
- On Windows, the IPC transport uses named pipes, or a loopback-only HTTP transport if that is simpler for the initial development workflow.
- Linux and Windows use the same IPC request and response message format regardless of transport.
- When the preferred TACACS+ server is available, new sessions are assigned to it.
- A TACACS+ server is treated as non-responsive when an existing connection fails or when a new connection cannot be established within a reasonable timeout.
- When the server currently handling new sessions becomes non-responsive, the service assigns subsequent new sessions to the next configured server in order.
- When failover reaches the end of the configured server list, selection wraps around to the first server.
- While operating on a non-primary server, the service periodically probes the preferred server for recovery.
- When the preferred server recovers, the service assigns subsequent new sessions to it.
- Existing session-oriented IPC connections remain bound to their current TACACS+ server connection until the session completes; they are not transparently migrated during failover or failback.
- If a TACACS+ server connection fails, all IPC sessions bound to that connection fail with an error response, and retry is performed by the IPC client rather than the service.
- The implementation runs on Linux and is usable on Windows for development and debugging.


