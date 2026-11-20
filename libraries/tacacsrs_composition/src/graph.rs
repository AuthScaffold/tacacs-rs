//! A validated composition that constructs components on request.

use std::any::{type_name, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use dill::{AllOf, Catalog, OneOf};

use tacacsrs_lifecycle::HostedService;

use crate::checks::pending_dependency;
use crate::composition::{GroupRule, Role};
use crate::deferred::{find, Slot};

/// A validated composition.
///
/// The host reads its inputs with [`Self::one`], supplies the deferred values
/// with [`Self::supply`], and then constructs the role members. Dropping the
/// graph drops the catalog. The constructed values keep their dependencies
/// alive.
pub struct Graph {
    catalog: Catalog,
    roles: HashMap<TypeId, Role>,
    groups: Vec<GroupRule>,
    deferred: Vec<Arc<dyn Slot>>,
}

impl Graph {
    pub(crate) fn new(
        catalog: Catalog,
        roles: HashMap<TypeId, Role>,
        groups: Vec<GroupRule>,
        deferred: Vec<Arc<dyn Slot>>,
    ) -> Self {
        Self {
            catalog,
            roles,
            groups,
            deferred,
        }
    }

    /// Constructs or returns the one registration that provides `T`.
    ///
    /// # Errors
    /// Returns an error when no registration or more than one registration
    /// provides `T`, or when `T` needs a deferred value that is not supplied.
    pub fn one<T: ?Sized + Send + Sync + 'static>(&self) -> anyhow::Result<Arc<T>> {
        self.check_supplied(TypeId::of::<T>(), type_name::<T>())?;
        self.catalog
            .get::<OneOf<T>>()
            .with_context(|| format!("Could not resolve {}", type_name::<T>()))
    }

    /// Returns `true` when a registration provides `T`.
    #[must_use]
    pub fn contains<T: ?Sized + 'static>(&self) -> bool {
        self.catalog.builders_for::<T>().next().is_some()
    }

    /// Supplies the deferred value `T`.
    ///
    /// # Errors
    /// Returns an error when `T` is not declared as deferred or is already
    /// supplied.
    pub fn supply<T: Send + Sync + 'static>(&self, value: Arc<T>) -> anyhow::Result<()> {
        find::<T>(&self.deferred)
            .with_context(|| format!("{} is not a deferred value", type_name::<T>()))?
            .supply(value)
    }

    /// Constructs the members of role `I` in registration order.
    ///
    /// The `name` function reads the runtime name of a member. Construction
    /// starts only after the host supplies each deferred value that a member
    /// needs.
    ///
    /// # Errors
    /// Returns an error when the role is not declared, when a deferred value
    /// is not supplied, when construction fails, or when the runtime names
    /// differ from the registered names or their order.
    pub fn members<I: ?Sized + Send + Sync + 'static>(
        &self,
        name: fn(&I) -> &'static str,
    ) -> anyhow::Result<Vec<Arc<I>>> {
        let role = self
            .roles
            .get(&TypeId::of::<I>())
            .with_context(|| format!("The role {} is not declared", type_name::<I>()))?;
        self.check_supplied(TypeId::of::<I>(), role.label)?;
        let members = self
            .catalog
            .get::<AllOf<I>>()
            .with_context(|| format!("Could not construct the {} registrations", role.label))?;
        let names: Vec<_> = members.iter().map(|member| name(member)).collect();
        anyhow::ensure!(
            names == role.names,
            "The {} runtime names {names:?} differ from the registered names {:?}",
            role.label,
            role.names
        );
        Ok(members)
    }

    fn check_supplied(&self, start: TypeId, label: &str) -> anyhow::Result<()> {
        let pending: HashMap<_, _> = self
            .deferred
            .iter()
            .filter(|slot| !slot.is_supplied())
            .map(|slot| (slot.value_type().id, slot.value_type().name))
            .collect();
        if let Some(value) = pending_dependency(&self.catalog, start, &pending) {
            anyhow::bail!("{label} needs the deferred value {value}, which is not supplied");
        }
        Ok(())
    }

    /// Constructs the hosted services in registration order.
    ///
    /// # Errors
    /// Returns the errors of [`Self::members`].
    pub fn hosted_services(&self) -> anyhow::Result<Vec<Arc<dyn HostedService>>> {
        self.members::<dyn HostedService>(|service| service.name())
    }

    /// Checks the health group names after construction and drops the catalog.
    ///
    /// # Errors
    /// Returns an error when a required deferred value is not supplied or when
    /// runtime member names differ from their registered names or order.
    pub fn finish(self) -> anyhow::Result<()> {
        for group in &self.groups {
            self.check_supplied(group.interface, group.name)?;
            let names = (group.constructed_names)(&self.catalog)?;
            let registered = &self.roles[&group.interface].names;
            anyhow::ensure!(
                names == *registered,
                "The {} runtime names {names:?} differ from the registered names {registered:?}",
                group.name
            );
        }
        Ok(())
    }
}
