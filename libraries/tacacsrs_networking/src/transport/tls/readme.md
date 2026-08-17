# TLS transport

This module provides the TLS implementation of the shared `Transport` trait.

The module splits `tokio_openssl::SslStream<TcpStream>` with `tokio::io::split`, yielding read/write halves for asynchronous concurrent processing.
