//! Ledger checks that run before construction.

use std::any::TypeId;
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use dill::{BuilderExt, Catalog};

use crate::composition::{Cardinality, Role};

/// Rejects a role implementation that a helper did not register.
pub(crate) fn check_roles(catalog: &Catalog, roles: &HashMap<TypeId, Role>) -> anyhow::Result<()> {
    for builder in catalog.builders() {
        let implementation = builder.instance_type();
        for (interface, role) in roles {
            anyhow::ensure!(
                !builder.interfaces_contain_type_id(interface)
                    || role.implementations.contains(&implementation.id),
                "{} provides a {} but is not registered as one",
                implementation.name,
                role.label
            );
        }
    }
    Ok(())
}

/// Makes sure that exactly one registration provides each required type.
pub(crate) fn check_required(
    catalog: &Catalog,
    required: &[(TypeId, &'static str)],
) -> anyhow::Result<()> {
    for (interface, name) in required {
        let count = providers(catalog, *interface).len();
        anyhow::ensure!(
            count == 1,
            "The host requires one {name}, but {count} registrations provide it"
        );
    }
    Ok(())
}

fn providers(catalog: &Catalog, interface: TypeId) -> Vec<TypeId> {
    catalog
        .builders()
        .filter(|builder| {
            builder.instance_type().id == interface
                || builder.interfaces_contain_type_id(&interface)
        })
        .map(|builder| builder.instance_type().id)
        .collect()
}

/// Checks each dependency form against the allowed forms.
///
/// The `registry` builder is exempt. It reads every health group, and its
/// dependencies must not let other consumers inject a group.
pub(crate) fn check_dependencies(
    catalog: &Catalog,
    allowed: &HashMap<TypeId, Cardinality>,
    registry: TypeId,
) -> anyhow::Result<()> {
    for builder in catalog
        .builders()
        .filter(|builder| builder.instance_type().id != registry)
    {
        let consumer = builder.instance_type().name;
        for dependency in builder.dependencies_get_all() {
            anyhow::ensure!(
                !dependency.is_bound,
                "{consumer} binds an opaque dependency for {}",
                dependency.iface.name
            );
            let cardinality = allowed.get(&dependency.spec.id).with_context(|| {
                format!(
                    "{consumer} uses the dependency form {}, which no registration allows",
                    dependency.spec.name
                )
            })?;
            if *cardinality == Cardinality::One {
                let count = providers(catalog, dependency.iface.id).len();
                anyhow::ensure!(
                    count == 1,
                    "{consumer} requires one {}, but {count} registrations provide it",
                    dependency.iface.name
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn check_cycles(catalog: &Catalog) -> anyhow::Result<()> {
    let edges: HashMap<TypeId, (&'static str, Vec<TypeId>)> = catalog
        .builders()
        .map(|builder| {
            let targets = builder
                .dependencies_get_all()
                .iter()
                .flat_map(|dependency| providers(catalog, dependency.iface.id))
                .collect();
            (builder.instance_type().id, (builder.instance_type().name, targets))
        })
        .collect();
    let mut finished = HashSet::new();
    for start in edges.keys() {
        visit(*start, &edges, &mut Vec::new(), &mut finished)?;
    }
    Ok(())
}

fn visit(
    node: TypeId,
    edges: &HashMap<TypeId, (&'static str, Vec<TypeId>)>,
    path: &mut Vec<TypeId>,
    finished: &mut HashSet<TypeId>,
) -> anyhow::Result<()> {
    if finished.contains(&node) {
        return Ok(());
    }
    let Some((name, targets)) = edges.get(&node) else {
        return Ok(());
    };
    anyhow::ensure!(!path.contains(&node), "Component {name} has a dependency cycle");
    path.push(node);
    for target in targets {
        visit(*target, edges, path, finished)?;
    }
    path.pop();
    finished.insert(node);
    Ok(())
}

/// Returns the first unsupplied deferred value that resolving `start` needs.
pub(crate) fn pending_dependency(
    catalog: &Catalog,
    start: TypeId,
    pending: &HashMap<TypeId, &'static str>,
) -> Option<&'static str> {
    let mut stack = providers(catalog, start);
    let mut seen = HashSet::new();
    while let Some(node) = stack.pop() {
        if !seen.insert(node) {
            continue;
        }
        if let Some(name) = pending.get(&node) {
            return Some(name);
        }
        for builder in catalog
            .builders()
            .filter(|builder| builder.instance_type().id == node)
        {
            for dependency in builder.dependencies_get_all() {
                stack.extend(providers(catalog, dependency.iface.id));
            }
        }
    }
    None
}
