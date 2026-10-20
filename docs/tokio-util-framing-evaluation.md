# Tokio-util Framing Evaluation

## Decision

Reject the evaluated route. Keep the current transport and proxy readers.
The integration contains this document only. Experimental code and dependency edges remain in the separate prototype.

The first, unformatted proxy adapter removed eleven production lines, but increased buffer costs.
The prototype commit does not preserve that intermediate adapter.
A small ownership adapter bounded read-ahead and avoided a separate large-body allocation.
The final proxy implementation grew from 231 to 252 production lines.

That line count supports the structural assessment below. It is not the adoption criterion by itself.
Adoption requires that bespoke buffering disappears and that all ownership and delivery contracts stay explicit.

This result does not prove that every Tokio-util integration is unsuitable.
The evaluation included a working adapter at the existing proxy seam, not only incorrect use of `SinkExt::send`.
The bounded evaluation stopped after the repairs showed no clear reduction in custom buffering.

## Package And Cost

The evaluated package is [Tokio-util 0.7.19](https://docs.rs/crate/tokio-util/0.7.19).
Its package manifest declares the MIT license, Rust 1.71, and Rust edition 2021.
The cached supplier archive matches the checksum in the predecessor lockfile:

```text
494815d09bf52b5548659851081238f0ca39ff638363907596da739561c62c52
```

The archive and extracted manifest, license, and evaluated codec sources match byte for byte.
The selected prototype closure passed the Rust 1.88 check.
The workspace minimum remains Rust 1.88.

The predecessor lockfile already contains this exact package.
In the Linux dependency graph, the existing `h2` and `combine` packages already enable its `codec` feature.
Networking does not use Tokio-util in its production dependency closure.
The agent already uses Tokio-util for cancellation.

The evaluated `codec` feature enables the Unix-only `libc` dependency. Its remaining direct dependencies are already unconditional package dependencies.
Those dependencies are `bytes`, `futures-core`, `futures-sink`, `pin-project-lite`, and `tokio`.

The prototype adds a direct production `bytes = "=1.12.1"` edge to the agent.
It changes the existing agent Tokio-util requirement to `=0.7.19` and enables `codec`.
Networking gains test-only `bytes = "=1.12.1"` and `tokio-util = "=0.7.19"` edges, with `codec`.
The lockfile gains three dependency edges: `bytes` for both packages and `tokio-util` for networking.
No package identity is added, removed, or changed.
No system package, native library, tool installation, or integration dependency change was necessary.

## Ownership And Deletion Map

| Owner | Before | Evaluated result |
| --- | --- | --- |
| [Networking reader](../libraries/tacacsrs_networking/src/codec/reader.rs) | Stack header, checked exact body allocation, `read_exact`, packet construction, counters, deobfuscation | Retained. Stateless packet semantics and error variants still need an owner. |
| [Networking writer](../libraries/tacacsrs_networking/src/codec/writer.rs) | Contiguous serialization, `write_all`, complete-packet counter, protected key | Retained. `send` introduces flush and cancellation differences, not a useful deletion. |
| [Shared driver](../libraries/tacacsrs_networking/src/connection/multiplexed/mod.rs) | Owned read/write loops, routing, cancellation, bounded admission | Retained. Tokio-util does not replace these contracts. |
| [Proxy reader](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/packet_io.rs) | Five header/body progress fields and two incremental read loops | Removed experimentally. Replaced by `FramedRead`, a protocol-aware decoder, and a read-window adapter. |
| Proxy packet ownership | One checked body vector plus the existing input buffer | Added an explicit large-frame allocation handoff and a coalesced-tail copy. |
| Proxy timeout and obfuscation | Packet deadline, downstream error context, protected key, reply mode | Retained in the proxy owner. |

The final production proxy diff has 95 additions and 74 deletions, before its new test module.
That is a net increase of 21 lines. Manifest and test additions are not part of that count.

The adapter removes five progress fields and two incremental read loops.
However, the project must still coordinate protocol validation, error-stage mapping, input limits, allocation ownership, and coalesced-tail preservation.
These policies span `DownstreamCodec`, `ReadWindow`, and `DownstreamReader`.
This tested route relocates bespoke buffering without a clear structural simplification.
The networking reader and writer remain simpler in their existing owners.

No protocol API, routing model, delivery classification, compatibility alias, or optional execution path changed.
All rejected production changes remain outside integration.

## Observed Behavior

Fourteen networking probes and six new proxy probes exercised the evaluated APIs.
The existing 25 proxy cases also passed against the repaired adapter.

- Header checks reject lengths `65537` and `u32::MAX` before advertised-size reservation.
- The stock `LengthDelimitedCodec`, with a 65536-byte maximum, reserved a full frame for a header that TACACS+ parsing rejects. The networking probes and the proxy adapter therefore use protocol-aware decoders.
- The maximum accepted body remains 65536 bytes. The TACACS+ header remains 12 bytes.
- One-byte reads, fragmented headers and bodies, empty bodies, and coalesced packets preserve packet bytes.
- Header flags, sequence numbers, session IDs, obfuscation, routing, and retry policy remain in their existing owners.
- Cancelled `next` calls retain partial headers and bodies. The proxy retains the original packet deadline.
- EOF retains the header/body distinction through a custom decoder.
- A raw I/O error bypasses decoder EOF handling. The proxy adapter must restore its header/body error context.
- Contiguous output uses one write when the transport accepts the whole frame. Short writes preserve the complete byte sequence.

### Allocation And Read-Ahead Evidence

The existing unbuffered reader consumes a stack header before it allocates the checked body vector.
The shared driver and downstream proxy also have a default 8192-byte Tokio input buffer.
That fixed transport buffer is not an allocation from an unchecked advertised body length.

For an unobfuscated maximum packet, those byte owners request 8192 plus 65536 bytes.
This description excludes allocator overhead, stack values, and obfuscation copies.
Large accepted body reads can bypass `BufReader`. The 8192-byte comparison concerns the next header, not every syscall.

After a maximum packet, the existing buffered reader consumed 8192 additional bytes before it rejected the next oversized header.
The simple `FramedRead` route consumed 65548 additional bytes and retained a 65548-byte read capacity.
That capacity is bounded by an accepted frame. It is not a `u32::MAX` allocation.

A simple frame split still shares its allocation with the reader.
Conversion to a body vector therefore copies the 65536-byte body.
The probe observed a 65548-byte frame capacity plus a distinct 65536-byte body capacity: 131084 simultaneous byte-owner bytes.
It also compared allocation pointers, rather than inferring this copy from a length check.
The retained `BytesMut` keeps the original allocation alive during conversion.
The distinct body pointer therefore does not depend on allocator address reuse.

The repaired proxy limits input requests to 8192 bytes and restores the read capacity after a large packet.
It transfers the large allocation into the packet body.
Pointer equality and the checked `bytes` implementation establish allocation reuse in this controlled case.
In that case, the transferred capacity is 65548 bytes, not the predecessor's exact 65536-byte body capacity.

The repair copies any bytes after the large frame into a new read buffer.
The committed coalesced-packet probe passes, but its reads leave no bytes after the large frame.
That probe therefore does not exercise a non-empty tail copy.

The [`bytes` 1.12.1 conversion](https://docs.rs/crate/bytes/1.12.1/source/src/bytes_mut.rs) still moves the body to the allocation start with `ptr::copy`.
The handoff avoids a separate body allocation, not this in-place byte move.
The supplier archive and conversion source match the locked package checksum.
These probes compare owned capacities and pointers.
They do not measure global allocation counts, copy counts, allocator slack, or process RSS.

### Cancellation, Delivery, And Counters

Cancellation probes stopped a 16-byte `send` after zero, five, and sixteen written bytes.
The sink retained sixteen, eleven, and zero queued bytes respectively.
The final case waited in the transport's flush operation.
Reuse sent the retained bytes before the next packet, without a duplicate prefix.
Dropping the sink sent no additional bytes. Any written prefix remained on the wire.

None of those cancellations establishes `NotSent`.
Even the zero-written-byte case retains an admitted frame that later reuse can transmit.
The existing execution layer retains conservative `OutcomeUnknown` classification after submission.
The networking suite includes the existing deadline and retry contracts.
No new cancellation-to-delivery conversion entered production.

The actual `messages_sent` counter records complete writes, not successful sink flushes.
The existing writer does not call flush.
It counted one message after it wrote sixteen bytes to a transport with a pending flush.
It counted zero messages after cancellation with five written bytes.
The simple sink still reported `Pending` after all sixteen bytes reached the controlled writer.
Counting only completed `send` calls therefore changes the existing counter contract.

These are packet counters. The endpoint counter model does not contain wire-byte counters.

## Reproduction And Results

The predecessor is `0518d4753e24292da9866a3c4f71233f232353fb`.
The prototype branch is `refactor/general-prototypes/17-codec-evaluation`.
The integration branch is `refactor/general-iterations/17-codec-evaluation`.
The remote prototype commit is [`4f60508ceea1c8789a2d9ab7acfc555e6bf7f282`](https://github.com/AuthScaffold/tacacs-rs/commit/4f60508ceea1c8789a2d9ab7acfc555e6bf7f282).
That commit preserves all six experimental source files on the normal pushed prototype branch.
It is not an integration ancestor or an experimental pull request.

Generated `.iteration17-evidence` files are local scratch, not committed source.
Replay uses the committed tests and does not require that directory.

The canonical prototype changed-source manifest has SHA-256:

```text
e16abdee6cc55287601b88ce1594ae9543d0b4922c72d34fa2c71d98f625b793
```

The commands assume Linux GNU, a clone at `$HOME/tacacs-rs`, and the required toolchains and native dependencies.
The [development guide](../DEVELOPMENT.md) describes the build prerequisites.
Offline replay also requires the locked registry packages in the Cargo cache.
If the cache does not contain them, run `cargo +stable fetch --locked` in the prototype before the checks.

If the prototype folder is absent, restore it at the exact commit:

```bash
set -e
prototype="$HOME/tacacs-rs-17-codec-evaluation-prototype"
prototype_commit=4f60508ceea1c8789a2d9ab7acfc555e6bf7f282
if [ ! -e "$prototype" ]; then
    git -C "$HOME/tacacs-rs" fetch origin refs/heads/refactor/general-prototypes/17-codec-evaluation
    git -C "$HOME/tacacs-rs" worktree add --detach "$prototype" "$prototype_commit"
fi
test "$(git -C "$prototype" rev-parse HEAD)" = "$prototype_commit"
git -C "$prototype" diff --exit-code "$prototype_commit" --
```

An existing folder remains untouched. A different commit fails the final identity check.
Tracked source changes fail the diff check.
The following checks use a separate prototype cache.
The optional profile script configures the local build environment. It is not prototype source.

Run the following commands in the prototype, not in this documentation-only integration:

```bash
set -e
if [ -f /etc/profile.d/tacacs-rs.sh ]; then
    source /etc/profile.d/tacacs-rs.sh
fi
cd "$HOME/tacacs-rs-17-codec-evaluation-prototype"
export CARGO_TARGET_DIR="$HOME/.cache/tacacs-rs-17-codec-evaluation-prototype"
export CARGO_BUILD_JOBS=4
export PYTHONDONTWRITEBYTECODE=1
cargo +stable test --offline --locked -p tacacsrs-networking --lib codec::evaluation -- --nocapture
cargo +stable test --offline --locked -p tacacsrs-networking --lib
cargo +stable test --offline --locked -p tacacsrs-agent --lib services::tacacs_proxy::upstream_bridge -- --nocapture
cargo +nightly fmt --all -- --check
cargo +nightly clippy --offline --locked -p tacacsrs-networking -p tacacsrs-agent --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +stable doc --offline --locked -p tacacsrs-networking -p tacacsrs-agent --no-deps --all-features --document-private-items
cargo +1.88.0 check --offline --locked -p tacacsrs-networking -p tacacsrs-agent --all-targets --all-features
```

| Final check | Result |
| --- | --- |
| Networking characterization | Exit 0. 14 passed, no skips. |
| Networking unit suite | Exit 0. 279 passed, two ignored manual routing benchmarks. |
| Proxy bridge suite | Exit 0. 31 passed, no skips. |
| Nightly formatting | Exit 0. |
| Nightly Clippy | Exit 0. Existing unknown-lint warnings remain for `assert_is_empty` and `chunks_exact_to_as_chunks`. |
| Stable private documentation | Exit 0 with `RUSTDOCFLAGS="-D warnings"`. |
| Rust 1.88, both packages, all targets/features | Exit 0. |

Stable was Rust 1.96.0. Nightly was Rust 1.98.0-nightly, dated 2026-06-18.
Initial harness compilation and test-only Clippy errors were corrected before the final runs.
Those errors are not package rejection evidence. Characterization successes are not successful adoption gates.

The prototype budget was 45 minutes.
The measured window started at 09:18:59 UTC on 2026-10-20.
The rejection decision took eleven minutes and 58 seconds.
Final prototype checks finished within nineteen minutes and 27 seconds.
No candidate source change followed those final runs.

No operator service, credential, service-manager configuration, or host network policy changed.
No new unsafe code was necessary.
Independent interoperability, fuzzing, global allocation instrumentation, dependency audit, unused-dependency checks, dependency freshness checks, Miri, and whole-workspace gates did not run for this rejection.
Existing protocol fuzz targets do not exercise the experimental streaming adapters.
No integration Rust rebuild or cross-platform execution is claimed.
Both named direct reviews and the coordinator's publication gates remain separate requirements.
