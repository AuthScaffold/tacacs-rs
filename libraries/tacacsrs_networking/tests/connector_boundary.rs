//! Cross-crate compile checks for concrete and erased connector boundaries.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use tacacsrs_networking::{ConnectOptions, PreparedEndpoint, RequestDeadline};
use tacacsrs_networking::routed::{Endpoint, EndpointConnector, OperationKind, RoutedClient};

trait Connection: Send + Sync {}
impl Connection for () {}

struct ConcreteFactory;

#[async_trait]
impl EndpointConnector for ConcreteFactory {
    type Connection = ();

    async fn connect(
        &self,
        _endpoint: PreparedEndpoint,
        _operation: OperationKind,
    ) -> anyhow::Result<Arc<()>> {
        Ok(Arc::new(()))
    }
    async fn retire(&self, _connection: &()) {}
    fn close(&self, _connection: &()) {}
    async fn close_and_join(
        &self,
        _connection: &(),
        _deadline: RequestDeadline,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

struct ErasedFactory;

#[async_trait]
impl EndpointConnector for ErasedFactory {
    type Connection = dyn Connection;

    async fn connect(
        &self,
        _endpoint: PreparedEndpoint,
        _operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>> {
        Ok(Arc::new(()))
    }
    async fn retire(&self, _connection: &Self::Connection) {}
    fn close(&self, _connection: &Self::Connection) {}
    async fn close_and_join(
        &self,
        _connection: &Self::Connection,
        _deadline: RequestDeadline,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

struct SharedFactory<Transport: Send + Sync + ?Sized + 'static> {
    inner: Arc<dyn EndpointConnector<Connection = Transport>>,
}

#[async_trait]
impl<Transport: Send + Sync + ?Sized + 'static> EndpointConnector for SharedFactory<Transport> {
    type Connection = Transport;

    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<Transport>> {
        self.inner.connect(endpoint, operation).await
    }
    async fn retire(&self, connection: &Transport) {
        self.inner.retire(connection).await;
    }
    fn close(&self, connection: &Transport) {
        self.inner.close(connection);
    }
    async fn close_and_join(
        &self,
        connection: &Transport,
        deadline: RequestDeadline,
    ) -> anyhow::Result<()> {
        self.inner.close_and_join(connection, deadline).await
    }
}

fn assert_send(_: impl Send) {}
fn assert_send_sync<Value: Send + Sync>() {}

struct Service<Connector: EndpointConnector> {
    client: RoutedClient<Connector>,
}

#[async_trait]
trait RunService: Send + Sync {
    async fn run(&self) -> anyhow::Result<()>;
}

#[async_trait]
impl<Connector: EndpointConnector> RunService for Service<Connector> {
    async fn run(&self) -> anyhow::Result<()> {
        let endpoint = self
            .client
            .active_endpoint(OperationKind::Accounting)
            .await
            .unwrap();
        assert_eq!(endpoint.name(), "boundary");
        let binding = self
            .client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await?;
        binding.note_success().await;
        self.client
            .close_and_join(RequestDeadline::after(Duration::ZERO)?)
            .await?;
        assert!(self
            .client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        Ok(())
    }
}

async fn exercise<Connector: EndpointConnector>(connector: Connector) {
    let endpoint = Endpoint::new(
        "boundary",
        PreparedEndpoint::tcp("127.0.0.1:49", false, None, ConnectOptions::default()),
        OperationKind::ALL,
    );
    let client = RoutedClient::with_connector(vec![endpoint], connector);
    assert_send_sync::<RoutedClient<Connector>>();
    assert_send(client.active_endpoint(OperationKind::Accounting));
    assert_send(client.bind(OperationKind::Accounting, Duration::ZERO));
    assert_send(client.with_endpoints(Vec::new()));
    assert_send(client.close_and_join(RequestDeadline::after(Duration::ZERO).unwrap()));
    let service: Box<dyn RunService> = Box::new(Service { client });
    assert_send(service.run());
    service.run().await.unwrap();
}

#[tokio::test]
async fn concrete_factory_with_concrete_connection_is_send() {
    exercise(ConcreteFactory).await;
}

#[tokio::test]
async fn concrete_factory_with_erased_connection_is_send() {
    exercise(ErasedFactory).await;
}

#[tokio::test]
async fn shared_factory_with_concrete_connection_is_send() {
    exercise(SharedFactory {
        inner: Arc::new(ConcreteFactory),
    })
    .await;
}

#[tokio::test]
async fn shared_factory_with_erased_connection_is_send() {
    exercise(SharedFactory {
        inner: Arc::new(ErasedFactory),
    })
    .await;
}
