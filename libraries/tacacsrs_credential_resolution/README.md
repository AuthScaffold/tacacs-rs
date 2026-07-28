# tacacsrs-credential-resolution

`tacacsrs-credential-resolution` defines provider-neutral contracts for planning and resolving central credential references found in an enumerated `tacacsrs-config` server.

The crate owns:

- deterministic typed request plans;
- an asynchronous resolver trait;
- typed certificate, private-key, symmetric-key, and trust-bag material;
- a closed result set that validates request/response slots and variants;
- sanitized typed failures;
- a deterministic fake resolver for tests.

It performs no filesystem, `SONiC`, `ConfigDB`, watcher, permission, retry, or runtime connection work. Providers inspect opaque references only through explicit request accessors. Debug and public error output omit opaque references and secret bytes.

```text
enumerated server
       |
       v
ResolutionPlan -> CredentialResolver -> ResolvedCredentialSet
       |                                      |
       +-- stable server/field context         +-- validated slots and variants
```

P3 supplies the `SONiC` provider and projects the closed result set into runtime networking inputs.
