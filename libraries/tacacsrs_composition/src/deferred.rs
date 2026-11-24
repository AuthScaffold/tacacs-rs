//! Values that the host supplies after validation.
//!
//! A deferred registration is a Dill builder over a write-once slot. Dill and
//! the ledger see a normal singleton, so validation covers its consumers. The
//! host supplies the value after validation and before it constructs a root.

use std::any::{Any, TypeId};
use std::sync::{Arc, OnceLock};

use dill::{
    Builder, Catalog, CatalogBuilder, DependencyInfo, InjectionContext, InjectionError, Singleton,
    TypeInfo, TypedBuilder,
};

/// A type-erased deferred slot.
pub(crate) trait Slot: Send + Sync {
    fn is_supplied(&self) -> bool;
    fn as_any(&self) -> &dyn Any;
    fn value_type(&self) -> TypeInfo;
}

/// The write-once value behind one deferred registration.
pub(crate) struct DeferredSlot<T: ?Sized>(OnceLock<Arc<T>>);

impl<T: Send + Sync + 'static> DeferredSlot<T> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(OnceLock::new()))
    }

    pub(crate) fn supply(&self, value: Arc<T>) -> anyhow::Result<()> {
        self.0.set(value).map_err(|_| {
            anyhow::anyhow!("The deferred value {} is already supplied", std::any::type_name::<T>())
        })
    }
}

impl<T: Send + Sync + 'static> Slot for DeferredSlot<T> {
    fn is_supplied(&self) -> bool {
        self.0.get().is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn value_type(&self) -> TypeInfo {
        TypeInfo::of::<T>()
    }
}

/// The Dill builder of a deferred value.
pub(crate) struct Deferred<T>(pub(crate) Arc<DeferredSlot<T>>);

impl<T: Send + Sync + 'static> Deferred<T> {
    fn value(&self, ctx: &InjectionContext) -> Result<Arc<T>, InjectionError> {
        self.0
             .0
            .get()
            .cloned()
            .ok_or_else(|| InjectionError::unregistered::<T>(ctx))
    }
}

impl<T: Send + Sync + 'static> Builder for Deferred<T> {
    fn instance_type(&self) -> TypeInfo {
        TypeInfo::of::<T>()
    }

    fn scope_type(&self) -> TypeInfo {
        TypeInfo::of::<Singleton>()
    }

    fn interfaces(&self, _clb: &mut dyn FnMut(&TypeInfo) -> bool) {}

    fn dependencies(&self, _clb: &mut dyn FnMut(&DependencyInfo) -> bool) {}

    fn metadata<'a>(&'a self, _clb: &mut dyn FnMut(&'a dyn Any) -> bool) {}

    fn get_any(
        &self,
        _cat: &Catalog,
        ctx: &InjectionContext,
    ) -> Result<Arc<dyn Any + Send + Sync>, InjectionError> {
        Ok(self.value(ctx)?)
    }
}

impl<T: Send + Sync + 'static> TypedBuilder<T> for Deferred<T> {
    fn get_with_context(
        &self,
        _cat: &Catalog,
        ctx: &InjectionContext,
    ) -> Result<Arc<T>, InjectionError> {
        self.value(ctx)
    }

    fn bind_interfaces(&self, _cat: &mut CatalogBuilder) {}
}

/// Finds the slot for `T`.
pub(crate) fn find<T: Send + Sync + 'static>(slots: &[Arc<dyn Slot>]) -> Option<&DeferredSlot<T>> {
    slots
        .iter()
        .filter(|slot| slot.value_type().id == TypeId::of::<T>())
        .find_map(|slot| slot.as_any().downcast_ref::<DeferredSlot<T>>())
}
