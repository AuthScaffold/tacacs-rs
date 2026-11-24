# tacacsrs-composition

`tacacsrs-composition` composes an application from selectable components. It uses the [Dill](https://crates.io/crates/dill) dependency injection container and adds a ledger that checks each registration before any component is constructed.

## Bootstrap flow

A host builds the application in these steps:

1. The host selects the components from its inputs. Selection does no I/O.
2. `prepare_all` prepares each component in order. Preparation does fallible I/O, and the host drops it when shutdown is requested.
3. The host creates a `Composition`, declares its roles, deferred values, and required inputs, and then calls `register_all`.
4. `Composition::validate` checks the ledger and returns a `Graph`. No component is constructed before this step.
5. The host reads its required inputs with `Graph::one` and prepares its runtime.
6. The host supplies each deferred value with `Graph::supply`.
7. The host constructs the role members, for example `Graph::hosted_services`, and then calls `Graph::finish`.

## Registration forms

The ledger accepts only these registration forms:

- `shared` and `dependency` add one singleton that consumers inject as `Arc<T>`.
- `provide` adds the one singleton that provides an interface `I`.
- `require` makes validation fail unless exactly one registration provides `T`.
- `deferred` declares a value that the host supplies after validation. A consumer injects it as a normal `Arc<T>`.
- `role` declares a role interface. `member` adds an implementation with a unique `Named::NAME`. `hosted_service` adds a member of the `HostedService` role.
- `health_member` adds a check to a health group. `require_group` lets a consumer inject the group members.

## Health registry

Every composition provides one `HealthRegistry` from `tacacsrs-lifecycle`. The registry has the same function as `HealthCheckService` in `Microsoft.Extensions.Diagnostics.HealthChecks`. It contains each check that `health_member` adds, with the name of its group. A consumer injects `Arc<HealthRegistry>` and runs all checks. The consumer needs no list of the components or groups.

A group does not need a consumer. A component that only reports its health adds a member to the `ComponentHealth` group. Two group types cannot use the same name. A health member cannot inject the registry, because validation rejects the dependency cycle.

Every registration must be a singleton, and each type can be registered once. Builders cannot fail, so a component does its fallible work in `prepare` and registers prepared values.

## Validation

`validate` rejects these faults:

- A missing or ambiguous single dependency.
- A dependency form that no registration allows.
- An opaque dependency override that hides dependencies from validation.
- A required input without exactly one provider.
- A dependency cycle.
- A role implementation that bypasses its registration helper.
- A health group with invalid member names or a forbidden empty group.

After validation, `Graph::one` rejects a request that needs a deferred value that is not supplied. `Graph::members` applies the same check to each member. A member that needs no deferred value can be constructed before the host supplies the deferred values. It also makes sure that the runtime names and their order equal the registered names.

## Shutdown authority

The graph never holds the application or its shutdown authority. A host supplies read-only views as deferred values. Hosted services observe shutdown only through the `ShutdownSignal` that the host gives to `HostedService::run`.
