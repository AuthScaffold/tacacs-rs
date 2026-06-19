//! Error boundary for one proxied TACACS+ connection.

#[derive(Debug)]
pub(super) enum ProxyConnectionError {
    Downstream(anyhow::Error),
    Upstream(anyhow::Error),
}
