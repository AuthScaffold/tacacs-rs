# TLS transport

This module provides the TLS implementation of the shared `Transport` trait.

`tokio_openssl::SslStream<TcpStream>` is split using `tokio::io::split`, yielding read/write halves for asynchronous concurrent processing.
