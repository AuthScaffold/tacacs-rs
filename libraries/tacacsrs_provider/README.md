# tacacsrs-provider

This crate defines the source contracts that the agent runtime consumes. The runtime gets a `SourceBundle` with a canonical datastore, credential capabilities, and canonical local services.

A source component supplies these inputs as separate values to the [agent host](../tacacsrs_agent/README.md#component-host). The source shares `SourceDatastore`, `CredentialProvider`, and `LocalServices`. A host or another component can add a `CredentialLayer` that wraps the source resolver, or a `LocalServicesOverlay` that changes the source local services. The host applies the layers and the overlays in registration order. This crate has no dependency on a dependency injection container.

A datastore change can contain local services. In that case, the runtime applies the overlays again and replaces the active local services. The runtime then starts, stops, or moves the client API and the proxy listeners. A source that gives the proxy endpoint after startup enables the proxy without an endpoint. The proxy waits until a change gives the endpoint, and the proxy loop guard rejects every upstream destination until then.

`CredentialProvider` keeps a resolver paired with its optional change source. Resolver layers preserve the change source. The type does not expose credential material through `Debug`.

Provider preparation owns its local resources. A caller can cancel preparation when it drops the future. Preparation must not change external state. A provider that changes external state during the application run supplies a `HostedService` from `tacacsrs-lifecycle`. The host registers that service as a separate component.
