//! The application health registry as a Dill registration.
//!
//! [`Composition::health_member`](crate::Composition::health_member) records
//! one collector for each health group. Validation adds one builder that
//! provides [`HealthRegistry`]. The builder declares each group as a
//! dependency, so the cycle and deferred-value checks include the members.
//! A consumer injects `Arc<HealthRegistry>` and needs no list of components.

use std::any::{Any, TypeId};
use std::sync::{Arc, Mutex};

use dill::{
    AllOf, Builder, Catalog, CatalogBuilder, DependencyInfo, DependencySpec, InjectionContext,
    InjectionError, Singleton, TypeInfo, TypedBuilder,
};

use tacacsrs_lifecycle::{HealthGroupKind, HealthMember, HealthRegistration, HealthRegistry};

type Collect = fn(&Catalog, &InjectionContext) -> Result<Vec<HealthRegistration>, InjectionError>;

/// Constructs the members of one health group for the registry.
#[derive(Clone, Copy)]
pub(crate) struct Collector {
    pub(crate) group: &'static str,
    pub(crate) interface: TypeId,
    dependency: DependencyInfo,
    collect: Collect,
}

impl Collector {
    pub(crate) fn of<G: HealthGroupKind>() -> Self {
        Self {
            group: G::NAME,
            interface: TypeId::of::<dyn HealthMember<G>>(),
            dependency: DependencyInfo::of::<dyn HealthMember<G>, AllOf<dyn HealthMember<G>>>(),
            collect: |catalog, ctx| {
                let ctx = ctx.push_resolve::<AllOf<dyn HealthMember<G>>>();
                Ok(AllOf::<dyn HealthMember<G>>::get(catalog, &ctx)?
                    .into_iter()
                    .map(HealthRegistration::new)
                    .collect())
            },
        }
    }
}

/// The singleton builder of the [`HealthRegistry`].
pub(crate) struct RegistryBuilder {
    collectors: Vec<Collector>,
    value: Mutex<Option<Arc<HealthRegistry>>>,
}

impl RegistryBuilder {
    pub(crate) fn new(collectors: Vec<Collector>) -> Self {
        Self {
            collectors,
            value: Mutex::new(None),
        }
    }

    fn value(
        &self,
        catalog: &Catalog,
        ctx: &InjectionContext,
    ) -> Result<Arc<HealthRegistry>, InjectionError> {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(registry) = value.as_ref() {
            return Ok(registry.clone());
        }
        let ctx = ctx.push_build(self);
        let mut registrations = Vec::new();
        for collector in &self.collectors {
            registrations.extend((collector.collect)(catalog, &ctx)?);
        }
        // Validation already rejects duplicate group and member names.
        let registry = Arc::new(
            HealthRegistry::new(registrations)
                .map_err(|_| InjectionError::ambiguous::<HealthRegistry>(&ctx))?,
        );
        *value = Some(registry.clone());
        Ok(registry)
    }
}

impl Builder for RegistryBuilder {
    fn instance_type(&self) -> TypeInfo {
        TypeInfo::of::<HealthRegistry>()
    }

    fn scope_type(&self) -> TypeInfo {
        TypeInfo::of::<Singleton>()
    }

    fn interfaces(&self, _clb: &mut dyn FnMut(&TypeInfo) -> bool) {}

    fn dependencies(&self, clb: &mut dyn FnMut(&DependencyInfo) -> bool) {
        for collector in &self.collectors {
            if !clb(&collector.dependency) {
                return;
            }
        }
    }

    fn metadata<'a>(&'a self, _clb: &mut dyn FnMut(&'a dyn Any) -> bool) {}

    fn get_any(
        &self,
        catalog: &Catalog,
        ctx: &InjectionContext,
    ) -> Result<Arc<dyn Any + Send + Sync>, InjectionError> {
        Ok(self.value(catalog, ctx)?)
    }
}

impl TypedBuilder<HealthRegistry> for RegistryBuilder {
    fn get_with_context(
        &self,
        catalog: &Catalog,
        ctx: &InjectionContext,
    ) -> Result<Arc<HealthRegistry>, InjectionError> {
        self.value(catalog, ctx)
    }

    fn bind_interfaces(&self, _cat: &mut CatalogBuilder) {}
}
