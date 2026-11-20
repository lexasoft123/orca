# Relay benchmark: preliminary, incomplete

These results do **not** support a Rust rewrite decision. The requested large-scale, backpressure, CPU normalization, event-loop lag and Rust comparisons remain unmeasured. The run uses a local combined relay with SQLite, a local ES256 JWKS, real host challenge/proof, invite, phone authentication and host data ticket. It sends arbitrary opaque binary payloads; they are not actual E2EE-framed messages. It does not contact production. No production hooks were added.

## Architecture

The control socket verifies a signed token, parses and validates control JSON, verifies assignment, generates an ephemeral NaCl box challenge, and checks the host's HMAC response. Invite creation and phone authentication interact with the credential store; the data ticket binds the host data socket to the pending phone. SQLite is used locally; deployed installations may use Postgres. Three sockets are held per pair: host control, host data, phone. See `src/connections/host-session-registry.ts`, `src/relay-server.ts`, `src/authentication/relay-token-verifier.ts` and `src/credentials/credential-store.ts`.

Once paired, `wireSplice` forwards each ws `RawData` and binary flag to the other socket. It calculates the payload byte count and updates a counter; it does not parse JSON, verify crypto or issue database queries per forwarded frame. `ws` receives and unmasks client frames and writes new frames; `wireSplice` passes the received buffers to `ws.send` without an explicit application-level payload copy. This does not establish how many copies occur inside ws or the kernel. Over 256 KiB buffered, it enqueues frame objects, accounts bytes and pauses the source transport; it resumes below 64 KiB and retries every 25 ms. Queue and process limits close overloaded links, as does a ten-second wedge. See `src/connections/splice-forwarder.ts` and `packages/relay-contract/src/admission-budgets.ts`.

## Method and observations

2026-11-20, macOS Darwin arm64, Node v26.10.0, file descriptor limit 1,048,575. Hardware model and memory could not be read: `sysctl` returned operation not permitted. Client and relay run on the same machine, so contention and loopback performance limit generalization. Ten pairs were established serially; each pair sends the next frame only after the previous frame arrives at its host data socket. Reported latency is client send to host receive, including client scheduling and local networking, not independently measured relay-only latency. The run lasts five seconds per payload size and has no warmup or repetitions. Setup includes client key generation and token signing, invite creation and all three sockets; it is not an isolated token/assignment latency.

| Metric | Result |
| --- | ---: |
| Ten-pair total setup | 93.02 ms (107.5 pairs/s, serial) |
| Setup latency p50 / p95 / p99 | 6.79 / 33.80 / 33.80 ms |

| Binary payload | Frames/s | Latency p50 / p95 / p99 ms |
| --- | ---: | ---: |
| 64 B | 196,923 | 0.041 / 0.084 / 0.127 |
| 1 KiB | 160,526 | 0.064 / 0.116 / 0.146 |
| 16 KiB | 44,604 | 0.178 / 0.654 / 0.920 |

An attempted 100-pair setup stalled before completion and was interrupted; the cause was not determined. It is not evidence of a relay capacity limit. The harness now times out while awaiting control messages, but does not yet report which admission condition caused the stall. The configured cell capacity defaults to 900 requests; the separate contract hard cap defaults to 600 sockets, with supported values 600, 1,000 and 3,000. The ordinary socket admission ceiling reserves 100 host controls, and placement additionally subtracts the configured unobserved bound. Thus a 10,000-socket test requires a deliberate multi-cell or modified-limit experiment; it cannot be assumed valid on one default cell.

A V8 `--cpu-prof` of the relay covering startup, setup, all three load phases and shutdown yielded 11,867 samples. Top self-sample counts were idle 4,325, ws `_unmask` 2,687, `writev` 2,605, `(program)` 867, `FastBuffer` 199, and GC 75. These are sampled stacks over the whole run, not time-normalized per workload; native and idle attribution is imperfect. They do not establish CPU per 1,000 messages/s, saturation, or the fraction of total service cost attributable to splice. JSON, crypto and database work were not separately quantified. Profiles are generated locally rather than committed.

## Reproduce

From `cloud/` (dependencies and built workspace contracts are needed):

```sh
pnpm install --frozen-lockfile
pnpm --filter @orca-cloud/relay-contract build
pnpm --filter @orca-cloud/postgres-schema build
cd apps/relay
BENCH_PAIRS=10 BENCH_SECONDS=5 BENCH_PROFILE_DIR=/private/tmp/relay-bench-profile node --import tsx --conditions=orca-source bench/run.mjs
```

The harness defaults to ten pairs and five seconds per payload. Results vary with system load. The test sends opaque bytes, and its client and relay share a machine. It does not yet exercise slow consumers, measure memory, CPU rate or event-loop lag, or independently drive the relay to a measured one-core saturation point. `cargo` was not found in PATH, so no Rust baseline was built.

## Is Rust worth it?

Undetermined. The profile shows substantial ws unmask and socket-write samples in this short local workload, but does not quantify splice as a share of production CPU, establish the first bottleneck, or provide a Rust comparison. Expected user scale, traffic mix and hosting prices were not supplied, so cost per user cannot be calculated. A rewrite would have to preserve the shared TypeScript relay-contract used by desktop and mobile, its Zod schemas and the existing relay test suite; no rewrite or porting cost was measured. Further experiments must complete the missing measurements and resolve the large-setup stall before drawing a conclusion.
