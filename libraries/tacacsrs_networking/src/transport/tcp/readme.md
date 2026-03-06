# TCP transport

This module provides the plain TCP implementation of the shared `Transport` trait.

`TcpStream` uses `into_split`, producing owned read/write halves suitable for concurrent packet I/O.
