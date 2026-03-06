# TLS-PSK transport

This module provides the OpenSSL TLS-PSK implementation of the shared `Transport` trait.

`tokio_openssl::SslStream<TcpStream>` is split using `tokio::io::split` for concurrent read/write processing.
