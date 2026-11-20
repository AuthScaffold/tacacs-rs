# tacacsrs-lifecycle

This crate defines the lifecycle contracts that agent components share. It has no dependency on a dependency injection container, the agent, IPC, or a provider.

`ShutdownRequester` belongs to the host. It requests application shutdown. `ShutdownSignal` only observes that request. The host gives each hosted service a signal, so a service cannot stop the application through the signal.

`ApplicationLifetime` lets a component stop the application. A host can supply it through injection. `stop` requests a graceful stop with a successful result. `stop_with_error` requests the same graceful stop and records the first error. After shutdown, the host returns that error, so the process exits with a failure status. A stop request does not end a hosted service. Each service still returns after its `ShutdownSignal` completes.

`HostedService` is a named background service. The host starts each service once and joins it. The semantics match a .NET `BackgroundService`. A return of `Ok(())` before shutdown ends that service only, and the host continues. An error or a panic stops the host. A service that cannot recover must return an error or call `ApplicationLifetime::stop_with_error`. A service that continues in a degraded state reports that state through a health check.

`HealthGroup<G>` aggregates the `HealthMember<G>` checks of one typed group with the `health-checks` package. Each check has a two-second timeout. Consumers poll the group once each second while they wait. A group type declares whether an empty group is valid. A group assessment contains the aggregate status and the names of failed members. It does not contain check descriptions or error chains, so a check error cannot expose secret material through the assessment.

`HealthRegistry` contains every health check of the application, like `HealthCheckService` in .NET. Each `HealthRegistration` keeps the name of its group as a tag. `check_all` runs every check and returns one `HealthEntry` for each check. When a check returns an error or panics, the entry has a fixed description, so the text of the error does not appear. `ComponentHealth` is a group that no component waits for. A component adds a member to this group when it only wants to report its health.

`ApplicationReadiness` is a health check that reports whether the application is ready. The host supplies it. A component in another package can add it to its own health group without a dependency on the agent.
