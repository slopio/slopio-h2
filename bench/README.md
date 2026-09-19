# popple-h2 vs tokio+h2

A connection-count sweep. The question it answers is what a connection costs —
in throughput, in latency, and in memory — not what a single request costs.

## Conformance

h2spec 2.0.0 against `examples/bench_server`, both suites clean:

```sh
PORT=8090 ./target/release/examples/bench_server &
h2spec -h 127.0.0.1 -p 8090 --timeout 5       # 145 tests, 145 passed
h2spec -h 127.0.0.1 -p 8090 --timeout 5 -S    # 146 tests, 146 passed (strict)
```

Worth knowing what it does not say: both runs finish in ~0.05s, so no read
deadline and no stream sweep ever comes near firing. h2spec covers frame
handling, HPACK and error codes against a conforming peer; whether the defences
misfire is `src/server/connection/tests/` and nothing else.

## Running it

```sh
cargo build --release --example bench_server
cargo build --release --manifest-path bench/tokio-h2/Cargo.toml
./bench/run.sh                      # 100, 1000, 5000, 10000 connections
CONNS="1000 20000" ./bench/run.sh
```

Needs `h2load` (`nghttp2-client`). `SERVER_CORES`, `LOAD_CORES`, `STREAMS`,
`DURATION` and `RING` are the knobs; results land in `bench/results/`.

Response size comes from the URL rather than from either server's environment:
`/1024` asks for a 1024-byte body, `/` for the echo. Both servers read it the
same way and slice a static buffer, so a payload sweep points them at the same
path and neither is restarted between sizes. Capped at 64 KiB — the default
stream window — because past it a response needs a WINDOW_UPDATE to finish,
which is a different thing to measure.

    h2load ... http://127.0.0.1:8080/10240          # 10 KiB responses
    h2load ... -d body.bin http://127.0.0.1:8080/5120   # POST, 5 KiB back

## What is held equal

Both servers answer the same bytes — `200`, `read 0 bytes\n`, no `Date`, no
`server`, no `content-length` — because a header one side sends and the other
does not is bytes on the wire that show up as a throughput difference.

Both get the same two cores, one worker per core (`PER_CORE=1` against
`THREADS`), and h2load drives from the other eight. The server gets the smaller
half deliberately: a run where h2load is the bottleneck measures h2load. Check
`cpu_s` in the summary — at ~2.0 cores per second of wall clock, both sides are
saturated and the comparison is real.

Both accept the same way, which is not a detail. popple-h2's `MultiAccept` sets
`SO_REUSEPORT` and binds a listener per worker, so a tokio with one listener is
being compared on accept capacity as much as on serving requests — and loses on
the wrong axis. `LISTENERS` defaults to the worker count for that reason. What
it was worth, at 20 000 connections: one listener gave 178 359 req/s with a
7.33 s worst case and 33 893 `ListenOverflows`, two gave 189 301 req/s with
804 ms and 8 513. The 7 s was dropped SYNs coming back as client retransmit
backoff, and had nothing to do with how fast a request is served.

Cleartext h2c, prior knowledge, no TLS on either side.

`bench/tokio-h2` can be built with `--features mimalloc-global` into a separate
target dir. `runtime` installs mimalloc as popple-h2's global allocator whether
it is asked to or not, so comparing memory against a glibc-malloc tokio
measures two allocators as much as two servers. It turned out not to matter
(19.6 KiB/conn against 21.5), but the control is there.

## Results

10 cores, kernel 7.0, 2 server cores, 1 stream per connection, 10 s per cell.
Zero failed, errored or timed-out requests anywhere.

**These rows predate `LISTENERS` and were run against a single-listener tokio.**
Their throughput column stands; their `tokio max` column does not — the
multi-second figures are the accept handicap described above, not tokio serving
a request slowly. Re-run to replace them.

| conns | popple req/s | tokio req/s | popple mean / max | tokio mean / max | popple RSS | tokio RSS |
|---|---|---|---|---|---|---|
| 100 | 321 337 | 179 304 | 293 µs / 9.8 ms | 546 µs / 31 ms | 9.9 MB | 5.5 MB |
| 1 000 | 271 822 | 176 459 | 3.7 ms / 27.8 ms | 5.7 ms / 54.9 ms | 28.6 MB | 28.3 MB |
| 5 000 | 229 392 | 160 308 | 22.0 ms / 170 ms | 31.1 ms / *6.82 s* | 108.5 MB | 127.3 MB |
| 10 000 | 242 417 | 169 698 | 39.6 ms / 62.6 ms | 52.2 ms / *6.85 s* | 226.5 MB | 241.1 MB |

At 20 000 connections, with accept parity and popple on `RING=16x4096` so
nothing is dropped:

| | req/s | mean | max |
|---|---|---|---|
| popple-h2 | 261 861 | 76.4 ms | **142 ms** |
| tokio+h2 | 189 301 | 104.0 ms | **804 ms** |

1.38× the throughput at equal CPU, and ~5.7× on the tail. The distributions are
the better reading of it: popple ran min 65 ms / max 118 ms / sd 4.6 ms, tokio
min 7 µs / max 804 ms / sd 231 ms. One serves everything uniformly, the other
serves some requests at once and makes others wait.

These are single runs. The spread between adjacent connection counts (229k at
5 000 against 242k at 10 000) is noise, not a trend — take the ratio between
the two servers at one connection count, not the shape of one column.

## Scaling, and where the advantage comes from

`bench/scaling.sh`, 1000 connections, one worker and one listener per core on
both sides:

| cores | popple req/s | /core | tokio req/s | /core | ratio |
|---|---|---|---|---|---|
| 1 | 141 326 | 141 326 | 74 742 | 74 742 | 1.89× |
| 2 | 312 218 | 156 109 | 173 779 | 86 889 | 1.80× |
| 4 | 952 862 | 238 216 | 448 561 | 112 140 | 2.12× |

It is not a scaling advantage. tokio scales marginally better from one core to
two (2.33× against 2.21×) and popple better from one to four (6.74× against
6.00×); what holds at every width is a roughly constant ~1.8-2.1× per core.
popple wins because each core does about twice the work, not because it adds
cores better.

Both are superlinear, which cannot be real scaling — at one core a single worker
holds all 1000 connections and at four it holds 250, so per-core cache locality
improves as cores are added. Read the per-core column; the speedup multiples are
contaminated by that.

## Memory

Two costs, and only one of them is per-connection.

Per-connection state, read as the marginal cost of an added connection over a
sweep at fixed cores, is close and in popple's favour: **20-24 KiB** against
tokio's **23-25 KiB**. (It was 225 KiB before the HPACK encoder was sized in
entries rather than bytes.)

The fixed cost is what differs, and it scales with cores rather than
connections: the buffer ring is per worker. At 1000 connections on the shipped
`64x512` ring, peak RSS is 22.2 / 29.0 / 34.5 MB at 1 / 2 / 4 cores against
tokio's flat 25.5 / 27.1 / 27.2 — lighter on one core, level at two, ~7 MB
heavier at four while serving twice the requests. `16x4096` adds 18-58 MB on top
and buys nothing at this connection count; it earns its keep at 20 000, where it
is the difference between ~2 500 dropped connections and none.

So: a fixed, tunable, per-core allocation traded for a lower per-connection one.
Which way that trade falls depends entirely on how many connections there are.

## Where it tops out

`bench/heavy.sh` is the ceiling sweep. It runs every cell against two binaries
— the tree, and the commit before the read deadline — because the deadline arms
and cancels a timer on every chunk, and a cost invisible at 300k req/s need not
stay invisible at the top. `cpu/core` is the row to check first: below ~0.95 the
server was not the bottleneck and the row measures h2load.

| | req/s | req/s/core |
|---|---|---|
| 1 core, 1000 conns, 1 stream | 143 637 | 143 637 |
| 2 cores, 1000 conns, 1 stream | 299 167 | 149 583 |
| 4 cores, 1000 conns, 1 stream | 905 527 | 226 382 |
| 2 cores, 500 conns, 8 streams | 1 766 975 | 883 488 |
| **2 cores, 500 conns, 64 streams** | **3 838 970** | **1 919 485** |

Concurrency per connection is what the ceiling is made of, not cores: one stream
at a time leaves the loop waiting on a round trip per connection, and 64 of them
keeps it fed. 1.92M req/s per core matches the 1.80-1.83M recorded against
buffer size in `examples/server.rs`.

The read deadline costs nothing measurable anywhere in that table — it is ahead
at 1, 2 and 8, behind at 4 and 64, by less than the spread between runs.

## The buffer ring empties, and nothing is dropped for it

The ring is shared by every connection on a worker, so at high connection
counts it does run dry — more sockets with data in flight than there are slots,
no misbehaviour required. At 20 000 connections on the shipped `64x512` ring
that happens 1 652 and 1 996 times across two runs.

What it costs is nothing. Each of those is one `yield_now` and a retry, because
an empty ring means another connection is holding buffers and not that this peer
is gone — the runtime classifies it `ContinueLater` and `MAX_DRY_READS` bounds
how long the loop will wait. Not one connection was dropped, and the bound was
never approached:

| | dry reads | dropped | deepest retry (of 16) |
|---|---|---|---|
| 2 cores, 20 000 conns | 1 652 / 1 996 | **0** | — |
| 1 core, 10 000 conns | 14 442 | **0** | 6 |
| 1 core, 20 000 conns | 2 986 | **0** | 1 |

Single core is the harder case: 20 000 connections share *one* ring rather than
one per worker. It holds.

Before that, ENOBUFS was fatal and the same load dropped ~2 500 connections a
run — and `RING=16x4096` was the answer, at 79 MB for the bigger slot count. It
is no longer needed for that. What a larger ring still buys is fewer dry reads,
which is a latency argument rather than a correctness one, and this benchmark
has not measured it.

None of that was visible from the client: h2load reported `0 failed, 0 errored`
through every run that was dropping thousands of connections, because it
re-established them silently. It was only visible in the server log, and only
until that log line was removed. Nothing counts these now — if the ring starts
running tight in a real deployment, there is no way to find out.

One crash was seen, once, in a 20 000-connection run, before `Ring::add` learned
to submit on a full queue. Understood and fixed since: the submission queue is
4 096 entries and a scheduler pass polls every runnable task before flushing, so
enough connections waking at once overflowed it and the `unwrap` took the
process down.

## The memory column

It read 2 262 MB at 10 000 connections before the HPACK encoder was sized
correctly — 225 KiB per connection against tokio's 23 KiB. The cost was paid at
connection birth, not by request handling: 2 000 connections that sent a
preface and never a request cost 211 KiB each.

`examples/accept_only.rs` is what localized it. Accepting and parking a socket
costs 0.16 KiB, arming the multishot recv costs 3.11 KiB, so the runtime was
not where the memory went. It was `SharedConnection::new` passing the HPACK
dynamic table's size *in bytes* as the encoder index's capacity *in entries* —
`vec![None; 8192]`, memset at construction, 192 KiB resident per connection
before it served anything.
