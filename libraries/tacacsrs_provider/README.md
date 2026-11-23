# tacacsrs-provider

This crate defines the source contracts that the agent runtime consumes. The runtime gets a `SourceBundle` with a canonical datastore, credential capabilities, and canonical local services.

A source component supplies these inputs as separate values to the [agent host](../tacacsrs_agent/README.md#component-host). The source shares `SourceDatastore`, `CredentialProvider`, and `LocalServices`. This crate has no dependency on a dependency injection container.

A datastore change can contain local services. In that case, the runtime replaces the active local services and starts, stops, or moves the client API and proxy listeners. A source that gives the proxy endpoint after startup enables the proxy without an endpoint, and the proxy waits until a change supplies the endpoint.

`CredentialProvider` keeps a resolver paired with its optional change source. The type does not expose credential material through `Debug`.

Provider preparation owns its local resources. A caller can cancel preparation when it drops the future. Preparation must not change external state. A provider that changes external state during the application run supplies a `HostedService` from `tacacsrs-lifecycle`. The host registers that service as a separate component.
