//! The Dill catalog builder and its registration ledger.
//!
//! Typed helpers record the dependency forms, role names, deferred values, and
//! health groups that each registration allows. Every registration must be a
//! singleton. [`Composition::validate`] checks the ledger and the Dill
//! metadata before it returns a [`Graph`]. No component is constructed before
//! that point.
//!
//! Every composition provides one [`HealthRegistry`]. The registry contains
//! the members of each health group, so a consumer can report the health of
//! all components without a list of them.

use std::any::{type_name, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use dill::{AllOf, BuilderExt, CatalogBuilder, OneOf, Singleton, TypedBuilder};

use tacacsrs_lifecycle::{
    validate_member_names, HealthGroupKind, HealthMember, HealthRegistry, HostedService,
};

use crate::checks::{check_cycles, check_dependencies, check_required, check_roles};
use crate::deferred::{Deferred, DeferredSlot, Slot};
use crate::registry::{Collector, RegistryBuilder};
use crate::Graph;

/// Gives a registered type a stable, secret-free diagnostic name.
pub trait Named {
    /// The name. It is unique in its role.
    const NAME: &'static str;
}

/// Checks the members of one health group before and after construction.
#[derive(Clone, Copy)]
pub(crate) struct GroupRule {
    pub(crate) name: &'static str,
    pub(crate) interface: TypeId,
    pub(crate) validate: fn(&[&'static str]) -> anyhow::Result<()>,
    pub(crate) constructed_names: fn(&dill::Catalog) -> anyhow::Result<Vec<&'static str>>,
}

/// The number of providers that an allowed dependency form accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cardinality {
    One,
    All,
}

/// The registrations of one role interface.
pub(crate) struct Role {
    pub(crate) label: &'static str,
    pub(crate) implementations: HashSet<TypeId>,
    pub(crate) names: Vec<&'static str>,
}

/// A catalog builder with the typed registration ledger.
pub struct Composition {
    catalog: CatalogBuilder,
    implementations: HashSet<TypeId>,
    allowed: HashMap<TypeId, Cardinality>,
    roles: HashMap<TypeId, Role>,
    groups: Vec<GroupRule>,
    deferred: Vec<Arc<dyn Slot>>,
    required: Vec<(TypeId, &'static str)>,
    health: Vec<Collector>,
}

impl Default for Composition {
    fn default() -> Self {
        let mut composition = Self {
            catalog: CatalogBuilder::default(),
            implementations: HashSet::new(),
            allowed: HashMap::new(),
            roles: HashMap::new(),
            groups: Vec::new(),
            deferred: Vec::new(),
            required: Vec::new(),
            health: Vec::new(),
        };
        composition.role::<dyn HostedService>("hosted service");
        composition
    }
}

impl Composition {
    /// Adds a shared value that consumers can inject as `Arc<T>`.
    ///
    /// # Errors
    /// Returns an error when `T` is already registered.
    pub fn shared<T: Send + Sync + 'static>(&mut self, value: Arc<T>) -> anyhow::Result<()> {
        self.dependency(value)
    }

    /// Adds a component that consumers can inject as `Arc<T>`.
    ///
    /// # Errors
    /// Returns an error when `T` is already registered or is not a singleton.
    pub fn dependency<T, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        T: Send + Sync + 'static,
        B: TypedBuilder<T> + 'static,
    {
        self.add(builder)?;
        self.allow::<OneOf<T>>(Cardinality::One);
        Ok(())
    }

    /// Adds the one component that consumers can inject as `Arc<I>`.
    ///
    /// # Errors
    /// Returns an error when `T` is already registered, is not a singleton, or
    /// does not provide `I`.
    pub fn provide<I, T, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        I: ?Sized + Send + Sync + 'static,
        T: Send + Sync + 'static,
        B: TypedBuilder<T> + 'static,
    {
        require_interface::<T, I>(&builder)?;
        self.add(builder)?;
        self.allow::<OneOf<I>>(Cardinality::One);
        Ok(())
    }

    /// Declares a value `T` that the host supplies after validation.
    ///
    /// Consumers can inject `Arc<T>`. The host must call [`Graph::supply`]
    /// before it constructs a root.
    ///
    /// # Errors
    /// Returns an error when `T` is already registered.
    pub fn deferred<T: Send + Sync + 'static>(&mut self) -> anyhow::Result<()> {
        let slot = DeferredSlot::<T>::new();
        self.add(Deferred(slot.clone()))?;
        self.allow::<OneOf<T>>(Cardinality::One);
        self.deferred.push(slot);
        Ok(())
    }

    /// Requires exactly one registration that provides `T`.
    ///
    /// The host reads `T` with [`Graph::one`]. Consumers can also inject
    /// `Arc<T>`. Validation fails when no registration or more than one
    /// registration provides `T`.
    pub fn require<T: ?Sized + Send + Sync + 'static>(&mut self) {
        self.allow::<OneOf<T>>(Cardinality::One);
        if self.required.iter().all(|(id, _)| *id != TypeId::of::<T>()) {
            self.required.push((TypeId::of::<T>(), type_name::<T>()));
        }
    }

    /// Declares a role interface `I` with a label for diagnostics.
    ///
    /// Only [`Self::member`] can register an implementation of a role. The
    /// host reads the members from the [`Graph`]. Consumers cannot inject a
    /// role unless a health group allows it. A second call keeps the first
    /// label.
    pub fn role<I: ?Sized + 'static>(&mut self, label: &'static str) {
        self.roles.entry(TypeId::of::<I>()).or_insert_with(|| Role {
            label,
            implementations: HashSet::new(),
            names: Vec::new(),
        });
    }

    /// Adds a member of role `I`.
    ///
    /// # Errors
    /// Returns an error when the role is not declared, for a duplicate type or
    /// name, for a scope that is not singleton, and when `T` does not provide
    /// `I`.
    pub fn member<I, T, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        I: ?Sized + 'static,
        T: Named + Send + Sync + 'static,
        B: TypedBuilder<T> + 'static,
    {
        require_interface::<T, I>(&builder)?;
        let name = T::NAME;
        let role = self
            .roles
            .get(&TypeId::of::<I>())
            .with_context(|| format!("The role {} is not declared", type_name::<I>()))?;
        let label = role.label;
        anyhow::ensure!(!name.trim().is_empty(), "A {label} registration has an empty name");
        anyhow::ensure!(
            !role.names.contains(&name),
            "More than one {label} registration is named {name}"
        );
        self.add(builder)?;
        let role = self
            .roles
            .get_mut(&TypeId::of::<I>())
            .context("The role disappeared during registration")?;
        role.names.push(name);
        role.implementations.insert(TypeId::of::<T>());
        Ok(())
    }

    /// Adds a hosted service root.
    ///
    /// # Errors
    /// Returns an error for a duplicate type or name, a scope that is not
    /// singleton, or when `S` does not provide [`HostedService`].
    pub fn hosted_service<S, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        S: Named + Send + Sync + 'static,
        B: TypedBuilder<S> + 'static,
    {
        self.member::<dyn HostedService, S, B>(builder)
    }

    /// Adds a check to health group `G`.
    ///
    /// A consumer can inject the members only after a call to
    /// [`Self::require_group`]. The [`HealthRegistry`] always contains the
    /// check, with `G::NAME` as its group.
    ///
    /// # Errors
    /// Returns an error for a duplicate type or member name, a scope that is
    /// not singleton, or when `M` does not provide [`HealthMember<G>`].
    pub fn health_member<G, M, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        G: HealthGroupKind,
        M: Named + Send + Sync + 'static,
        B: TypedBuilder<M> + 'static,
    {
        self.role::<dyn HealthMember<G>>(G::NAME);
        self.member::<dyn HealthMember<G>, M, B>(builder)?;
        let collector = Collector::of::<G>();
        if self
            .health
            .iter()
            .all(|existing| existing.interface != collector.interface)
        {
            anyhow::ensure!(
                self.health
                    .iter()
                    .all(|existing| existing.group != collector.group),
                "More than one health group is named {}",
                collector.group
            );
            self.health.push(collector);
        }
        Ok(())
    }

    /// Lets a consumer inject the members of group `G` as
    /// `Vec<Arc<dyn HealthMember<G>>>`.
    ///
    /// Validation checks the member names and the empty-group policy before it
    /// constructs a component. Call this method once for each group that a
    /// retained consumer uses.
    pub fn require_group<G: HealthGroupKind>(&mut self) {
        self.allow::<AllOf<dyn HealthMember<G>>>(Cardinality::All);
        let interface = TypeId::of::<dyn HealthMember<G>>();
        self.role::<dyn HealthMember<G>>(G::NAME);
        if self.groups.iter().all(|group| group.interface != interface) {
            self.groups.push(GroupRule {
                name: G::NAME,
                interface,
                validate: validate_member_names::<G>,
                constructed_names: |catalog| {
                    Ok(catalog
                        .get::<AllOf<dyn HealthMember<G>>>()
                        .with_context(|| format!("Could not construct the members of {}", G::NAME))?
                        .iter()
                        .map(|member| member.name())
                        .collect())
                },
            });
        }
    }

    fn allow<Spec: 'static>(&mut self, cardinality: Cardinality) {
        self.allowed.insert(TypeId::of::<Spec>(), cardinality);
    }

    fn add<T, B>(&mut self, builder: B) -> anyhow::Result<()>
    where
        T: Send + Sync + 'static,
        B: TypedBuilder<T> + 'static,
    {
        let scope = builder.scope_type();
        anyhow::ensure!(
            scope.id == TypeId::of::<Singleton>(),
            "{} uses scope {}. Components must be singletons",
            type_name::<T>(),
            scope.name
        );
        anyhow::ensure!(
            self.implementations.insert(TypeId::of::<T>()),
            "{} is registered more than once",
            type_name::<T>()
        );
        self.catalog.add_builder(builder);
        Ok(())
    }

    /// Validates the composition without constructing a component.
    ///
    /// # Errors
    /// Returns an error for a missing, ambiguous, unrecognized, or cyclic
    /// dependency, for a required value without exactly one provider, for a role that bypasses its registration helper, and for an
    /// invalid health group.
    pub fn validate(mut self) -> anyhow::Result<Graph> {
        let health = std::mem::take(&mut self.health);
        self.add(RegistryBuilder::new(health))
            .context("The health registry is registered by the composition")?;
        self.allow::<OneOf<HealthRegistry>>(Cardinality::One);
        self.catalog
            .validate()
            .map_err(|error| anyhow::anyhow!("Component dependencies are not valid: {error}"))?;
        let catalog = self.catalog.build();
        check_roles(&catalog, &self.roles)?;
        check_required(&catalog, &self.required)?;
        for group in &self.groups {
            (group.validate)(&self.roles[&group.interface].names)
                .with_context(|| format!("Health group {} is not valid", group.name))?;
        }
        check_dependencies(&catalog, &self.allowed, TypeId::of::<HealthRegistry>())?;
        check_cycles(&catalog)?;
        Ok(Graph::new(catalog, self.roles, self.groups, self.deferred))
    }
}

fn require_interface<T: Send + Sync + 'static, I: ?Sized + 'static>(
    builder: &impl TypedBuilder<T>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        TypeId::of::<T>() == TypeId::of::<I>()
            || builder.interfaces_contain_type_id(&TypeId::of::<I>()),
        "{} does not provide {}",
        type_name::<T>(),
        type_name::<I>()
    );
    Ok(())
}
