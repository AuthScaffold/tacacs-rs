# tacacsrs-unix-socket

Unix domain socket binding, advisory locking, and inode-aware cleanup for
cooperating Linux services.

This crate provides a single, reusable resource owner for Unix domain socket
listeners. It replaces the socket-owner logic that was duplicated in the central
TACACS+ agent raw proxy listener and the local client API (IPC) listener. The
crate holds no TACACS+, protobuf, or configuration types. It has no feature
flags.

## What it does

`prepare_unix_listener` binds one socket and returns the listener together with
a `UnixSocketCleanupGuard`:

```text
prepare_unix_listener(path, socket_mode)
  1. create the parent directory when it is absent
  2. take an exclusive advisory lock on <path>.lock
  3. remove only a stale, unowned socket at the path
  4. bind a Tokio UnixListener
  5. apply the requested socket permission bits
  -> (UnixListener, UnixSocketCleanupGuard)
```

The guard records the bound socket `(dev, ino)` identity. Its `cleanup` method,
and its `Drop` implementation, remove the socket path only when the path still
has the recorded identity. The guard therefore never deletes a successor socket
bound by another instance. The guard holds the advisory lock until it drops, and
it never removes the `<path>.lock` file.

## Security model

This crate assumes a trusted parent directory and cooperating, well-behaved
processes. The advisory lock and the `(dev, ino)` identity check coordinate
service instances that follow the same protocol. They are not atomic against a
hostile actor that can write to the parent directory and replace the path
between a check and the next operation. The identity check reduces accidental
removal of a successor socket, but it is best-effort. It does not defend against
a deliberate time-of-check to time-of-use attack. Operators must protect the
parent directory with correct ownership and permissions.

## Platform support

This crate supports Linux GNU only. It fails to compile on other targets.
