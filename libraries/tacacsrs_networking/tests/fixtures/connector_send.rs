//! Compile with `--cfg generic_adapter` for the passing generic service shape.
//! Without that flag, this reproduces a higher-ranked Send/lifetime error.

#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

trait Connection: Send + Sync {}

trait Factory: Send + Sync + 'static {
    type Connection: Send + Sync + ?Sized + 'static;
}

struct Shared<Transport: Send + Sync + ?Sized + 'static> {
    factory: Arc<dyn Factory<Connection = Transport>>,
}

impl<Transport: Send + Sync + ?Sized + 'static> Factory for Shared<Transport> {
    type Connection = Transport;
}

struct Engine<Connector: Factory> {
    connector: Arc<Connector>,
    connections: Vec<Arc<Connector::Connection>>,
    endpoint: (),
}

impl<Connector: Factory> Engine<Connector> {
    async fn lookup(&self) -> &() {
        std::future::ready(()).await;
        &self.endpoint
    }
}

#[cfg(not(generic_adapter))]
struct Service {
    engine: Engine<Shared<dyn Connection>>,
}

#[cfg(not(generic_adapter))]
impl Service {
    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.engine.lookup().await;
        })
    }
}

#[cfg(generic_adapter)]
struct Service<Connector: Factory> {
    engine: Engine<Connector>,
}

#[cfg(generic_adapter)]
impl<Connector: Factory> Service<Connector> {
    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.engine.lookup().await;
        })
    }
}

fn main() {}
