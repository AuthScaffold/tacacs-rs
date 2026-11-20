//! Selectable components and the bootstrap steps that apply them.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use crate::Composition;

/// One optional part of an application.
///
/// A host selects components from its inputs. Each selected component then
/// prepares under application cancellation and adds its registrations to one
/// [`Composition`]. A component gets runtime values only through injection.
/// It never receives the application itself. A host can let a component stop
/// the application through an injected value.
#[async_trait]
pub trait Component: Send {
    /// Returns a stable, secret-free name that is unique among components.
    fn name(&self) -> &'static str;

    /// Does fallible I/O before registration.
    ///
    /// The host drops this future when shutdown is requested. Work that must
    /// continue after startup belongs in a hosted service.
    ///
    /// # Errors
    /// Returns an error that stops startup.
    async fn prepare(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Adds the registrations of this component.
    ///
    /// This method must not start work or bind resources. A component that
    /// registers nothing is dropped.
    ///
    /// # Errors
    /// Returns an error that stops startup.
    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()>;
}

/// Makes sure that each component name is unique.
///
/// # Errors
/// Returns an error for a duplicate component name.
pub fn check_names(components: &[Box<dyn Component>]) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    for component in components {
        anyhow::ensure!(
            names.insert(component.name()),
            "More than one component is named {}",
            component.name()
        );
    }
    Ok(())
}

/// Prepares each component in order.
///
/// # Errors
/// Returns a name error or the first preparation error with the component name.
pub async fn prepare_all(components: &mut [Box<dyn Component>]) -> anyhow::Result<()> {
    check_names(components)?;
    for component in components {
        let name = component.name();
        component
            .prepare()
            .await
            .with_context(|| format!("Could not prepare component {name}"))?;
    }
    Ok(())
}

/// Registers each component in order.
///
/// # Errors
/// Returns a name error or the first registration error with the component name.
pub fn register_all(
    components: Vec<Box<dyn Component>>,
    composition: &mut Composition,
) -> anyhow::Result<()> {
    check_names(&components)?;
    for component in components {
        let name = component.name();
        component
            .register(composition)
            .with_context(|| format!("Could not register component {name}"))?;
    }
    Ok(())
}

/// A component that shares one prepared value.
///
/// Use this component for a host input that needs no preparation, for example
/// a policy that the host parsed from its command line.
pub struct Value<T> {
    name: &'static str,
    value: Arc<T>,
}

impl<T: Send + Sync + 'static> Value<T> {
    /// Creates a component named `name` that shares `value`.
    #[must_use]
    pub fn new(name: &'static str, value: T) -> Self {
        Self {
            name,
            value: Arc::new(value),
        }
    }
}

#[async_trait]
impl<T: Send + Sync + 'static> Component for Value<T> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.shared(self.value)
    }
}
