use super::MultiplexedConnection;

#[test]
fn test_connection_creation() {
    let _conn = MultiplexedConnection::new(Some(b"test_key"));
}

#[test]
fn test_connection_without_obfuscation() {
    let _conn = MultiplexedConnection::new(None);
}
