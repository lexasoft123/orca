# Relay benchmark

Measured on 2026-11-20: macOS Darwin arm64, Node v26.10.0, `ulimit -n` 1,048,575. Hardware model and RAM were inaccessible (`sysctl` returned operation not permitted); the machine is shared with other work. All servers and clients were local, with SQLite and a local ES256 JWKS. The client and relay shared the machine, so client CPU and loopback contention affect results. Each observation below is one run, not a confidence interval or a production prediction.

## Architecture

The control socket verifies a signed token, parses and validates control JSON, verifies assignment, generates an ephemeral NaCl box challenge, and checks the host's HMAC response. Invite creation and phone authentication interact with the credential store; the data ticket binds the host data socket to the pending phone. Three sockets are held per pair: host control, host data, and phone. See `src/connections/host-session-registry.ts`, `src/relay-server.ts`, `src/authentication/relay-token-verifier.ts` and `src/credentials/credential-store.ts`.

Once paired, `wireSplice` forwards each ws `RawData` and binary flag to the other socket, counts bytes and invokes a counter; it does not parse JSON, verify crypto or issue database queries per frame. `ws` unmasks incoming client frames and writes new frames. `wireSplice` passes the received buffers to `ws.send` without an explicit application-level payload copy; this does not establish copy counts inside ws or the kernel. Over 256 KiB buffered, it enqueues frame objects, accounts bytes and pauses the source transport; it resumes below 64 KiB and retries every 25 ms. Queue and process limits close overloaded links, as does a ten-second wedge. See `src/connections/splice-forwarder.ts` and `packages/relay-contract/src/admission-budgets.ts`.

## Method

The harness starts a combined director/cell and SQLite in a temporary directory and performs real ES256 verification, host NaCl proof, invite, phone authentication and host data ticket binding. Each host uses a different account. Binary load frames are valid legacy NaCl-box bundles, a 24-byte nonce followed by ciphertext and a 16-byte authenticator; the client seals and checks a frame once per pair and payload size, then reuses it for the load. This is safe only as synthetic benchmark traffic. Relay payloads are opaque; client encryption is outside the timed forwarding loop.

Pairs are established serially. Each sends its next frame after receiving the previous one at the data socket, so this is a closed-loop load, not a controlled open-loop arrival rate. The load table is five seconds per payload with 100 pairs and no warmup. Send-to-receive latency includes client scheduling and local networking; it is not isolated relay-only delay. A `--import`-preloaded bench monitor uses `process.cpuUsage`, RSS and `monitorEventLoopDelay` (10 ms resolution), triggered by SIGUSR2 between phases; it adds no production hooks. CPU counters include Node worker threads and short transition intervals. Event-loop numbers include the monitor's 10 ms sampling floor. Raw result lines are in `measurements/`.

## Setup and limits

The original 100-pair stall was a harness bug: it reused a single account, exhausting the hard-coded 30 invite mints per account per minute. The 31st invite returned an error, which the harness mistook for a token; the phone closed with 4401 `invalid relay auth` while the harness waited on the host. The harness now checks the invite response, logs WebSocket close codes and HTTP statuses, and uses separate accounts and distinct synthetic forwarded sources. The original `192.0.2.N` address also exceeded a valid IPv4 octet for larger runs; the revised address rolls over octets. These forwarded headers are local synthetic inputs, not production traffic.

Bench-only environment settings are `ORCA_RELAY_CELL_CAPACITY=100000` (director capacity setting), `ORCA_RELAY_CELL_CONNECTION_HARD_CAP=3000` (largest contract-supported cap) and `ORCA_RELAY_CELL_CONNECTION_UNOBSERVED_BOUND=0` (removes the placement allowance). The code default capacity is 900; hard cap defaults to 600 and only 600, 1000 and 3000 are accepted. The ordinary admission ceiling reserves 100 sockets for control rebinds. With these settings, one run admitted 966 full pairs (2,898 sockets), opened the next host control, and rejected the next phone upgrade with HTTP 503. This is an admission limit, not proof of CPU saturation. The 30/minute invite and pre-auth budgets are not changed; distinct accounts and sources model their normal independent scopes.

In the 100-pair load run, serial setup took 984 ms, or 102 pairs/s, including client key and token generation, proof, invite and all three sockets. Setup p50/p95/p99 were 8.03/18.35/42.50 ms. It does not isolate token verification or director assignment. The first pair includes cold startup and JWKS fetch.

## Forwarding, CPU and lag

| Binary frame | Frames/s | Send-to-receive p50 / p95 / p99 ms | Relay CPU ms / 1,000 frames | Relay CPU / sampled wall | Event-loop p99 / max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 64 B | 134,673 | 0.732 / 1.209 / 1.566 | 7.25 | 95.7% | 10.85 / 11.98 |
| 1 KiB | 135,499 | 0.708 / 1.078 / 1.566 | 7.30 | 89.4% | 10.53 / 11.55 |
| 16 KiB | 28,155 | 2.192 / 8.285 / 19.571 | 34.28 | 87.1% | 25.44 / 45.94 |

CPU per 1,000 is phase CPU milliseconds divided by received frames times 1,000. The sampled wall intervals include phase transitions and sorting latency samples in the client; they are slightly longer than the five-second traffic windows. At 100 pairs and 64 B, the relay used 4.882 CPU seconds over a 5.102-second interval: approximately one core at 135k frames/s on this machine. This is a near-saturation observation, not a determined first saturation threshold: the harness does not sweep offered load or separate client from relay on different machines. CPU and network limits at other payloads cannot be inferred from this observation. A separate three-second 64 B concurrency sweep gave 44,428 frames/s at 44.2% sampled CPU with one pair, 122,904 at 81.4% with ten, and 115,931 at 84.9% with 30. The non-monotonic throughput and different runs show substantial measurement variability; they do not identify a precise saturation threshold. The 900 capacity setting and 600 default hard cap are connection/admission limits, not message-rate limits; a default cell cannot necessarily admit 100 such pairs under every reservation configuration.

The relay's V8 CPU profile covers startup, setup, all three phases and shutdown. Categorizing **self samples** by frame name or source URL gives 11,925 total: idle 4,636 (38.9%), splice/socket/ws 5,402 (45.3%), crypto 126 (1.1%), database 130 (1.1%), JSON 2 (<0.1%), GC 75 (0.6%), other 1,554 (13.0%). Among 7,289 non-idle samples, the splice/socket/ws category is 74.1%. This broad category includes native `writev`, ws masking and transport code, not just the application's splice function. Native operations and unattributed samples can fall into `other`; sampling is not a complete accounting of crypto or database cost. It is not a production CPU share, and setup is a small part of this traffic-heavy profile. The companion script states the matching rules.

## Idle memory

RSS was recorded after 25 seconds idle and compared with each relay process immediately after startup. Each pair has three server-side sockets; numbers exclude client RSS. To exceed the contract's 3,000-socket cap, 5k and 10k use two and four independent local combined relays, each with 833 pairs (2,499 sockets), measured concurrently. The 5k result sums the first two relays from the four-cell run. These are process RSS differences, not retained heap allocations per socket: allocator behavior, startup activity, GC and per-cell overhead affect them.

| Server sockets | Cells | Idle relay RSS total | Difference from startup RSS | Difference/socket |
| --- | ---: | ---: | ---: | ---: |
| 999 | 1 | 110,867,224 B | 40,046,840 B | 40,087 B |
| 4,998 | 2 | 283,199,040 B | 137,544,576 B | 27,520 B |
| 9,996 | 4 | 574,230,760 B | 282,658,944 B | 28,277 B |

The idle 999-socket relay used 47.995 CPU ms during 25.104 seconds; its event-loop p99/max was 12.86/19.35 ms with the same 10 ms monitor resolution. These shard measurements demonstrate an aggregate, not a single cell holding 10,000 sockets.

## Slow consumer

One pair sent 64 KiB frames while the data client's underlying socket was paused. The producer sent 77 frames (5,046,272 bytes) before its phone socket closed with 4429 `wedged relay link` after 10.15 seconds. This exercises real TCP backpressure and the timeout, but the sent count includes client/kernel buffers and does not measure the relay queue's peak bytes or validate every limit. The receiver was resumed during cleanup.

## Rust and decision

`cargo` was not available on PATH and `~/.cargo/bin/cargo` was absent. Accordingly no Rust baseline was built or measured. The evidence shows nearly one core at 135k 64-byte frames/s in this one local closed-loop run and 74.1% of non-idle profile self samples in a broad splice/socket/ws category. It does not measure Rust performance or establish production CPU shares. Expected users, workload distribution, deployment prices and actual production utilization were not supplied, so cost per user cannot be calculated. A rewrite would need to preserve the shared TypeScript relay-contract used by desktop and mobile, Zod schemas and the relay test suite; neither porting cost nor compatibility risk was measured. **Is Rust worth it? Undetermined** until a comparable Rust baseline, representative production traffic and deployment costs are measured.

## Reproduce

From `cloud/`:

```sh
pnpm install --frozen-lockfile
pnpm --filter @orca-cloud/relay-contract build
pnpm --filter @orca-cloud/postgres-schema build
cd apps/relay
BENCH_PAIRS=100 BENCH_SECONDS=5 BENCH_PROFILE_DIR=/private/tmp/relay-profile BENCH_STATS=/private/tmp/load.stats node --import tsx --conditions=orca-source bench/run.mjs
node bench/profile-summary.mjs /private/tmp/relay-profile/*.cpuprofile
BENCH_PAIRS=333 BENCH_IDLE=1 BENCH_IDLE_SECONDS=25 BENCH_STATS=/private/tmp/one.stats node --import tsx --conditions=orca-source bench/run.mjs
BENCH_PAIRS=1 BENCH_SLOW=1 BENCH_STATS=/private/tmp/slow.stats node --import tsx --conditions=orca-source bench/run.mjs
for i in 1 10 30; do BENCH_PAIRS=$i BENCH_SECONDS=3 BENCH_STATS=/private/tmp/sweep-$i.stats node --import tsx --conditions=orca-source bench/run.mjs; done
BENCH_PAIRS=1000 BENCH_IDLE=1 BENCH_STATS=/private/tmp/cap.stats node --import tsx --conditions=orca-source bench/run.mjs
```

The final command intentionally exceeds admission and exits unsuccessfully. For the 4-cell run, from `apps/relay` (each process uses its own temporary SQLite database and loopback ports):

```sh
for i in 1 2 3 4; do
  BENCH_PAIRS=833 BENCH_IDLE=1 BENCH_IDLE_SECONDS=25 BENCH_STATS=/private/tmp/shard-$i.stats node --import tsx --conditions=orca-source bench/run.mjs > /private/tmp/shard-$i.log 2>&1 &
done
wait
```
