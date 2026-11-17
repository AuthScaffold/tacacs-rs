# tacacsrs-provider

This crate defines the source contracts consumed by the agent runtime. Provider crates return a `SourceBundle` with a canonical datastore, credential capabilities, canonical local services, and optional companions.

`CredentialProvider` keeps a resolver paired with its optional change source. Resolver layers preserve the change source. The type does not expose credential material through `Debug`.

Companion construction is inert. A companion starts work only inside `run`. The agent supplies readiness and cancellation, treats unexpected completion as fatal, and awaits cleanup under its shutdown deadline. A companion returns successfully after cancellation only when its cleanup finishes. Forced cancellation can interrupt external cleanup.

Provider preparation owns its local resources and remains cancellable by dropping its future. External mutations belong inside a companion's managed lifetime.
