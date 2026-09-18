# popple-h2 vs tokio+h2

A connection-count sweep. The question it answers is what a connection costs —
in throughput, in latency, and in memory — not what a single request costs.

## Running it

```sh
cargo build --release --example bench_server
cargo build --release --manifest-path bench/tokio-h2/Cargo.toml
./bench/run.sh                      # 100, 1000, 5000, 10000 connections
CONNS="1000 20000" ./bench/run.sh
```

Needs `h2load` (`nghttp2-client`). `SERVER_CORES`, `LOAD_CORES`, `STREAMS`,
`DURATION` and `RING` are the knobs; results land in `bench/results/`.

## What is held equal

Both servers answer the same bytes — `200`, `read 0 bytes\n`, no `Date`, no
`server`, no `content-length` — because a header one side sends and the other
does not is bytes on the wire that show up as a throughput difference.

Both get the same two cores, one worker per core (`PER_CORE=1` against
`THREADS`), and h2load drives from the other eight. The server gets the smaller
half deliberately: a run where h2load is the bottleneck measures h2load. Check
`cpu_s` in the summary — at ~2.0 cores per second of wall clock, both sides are
saturated and the comparison is real.

Cleartext h2c, prior knowledge, no TLS on either side.

`bench/tokio-h2` can be built with `--features mimalloc-global` into a separate
target dir. `runtime` installs mimalloc as popple-h2's global allocator whether
it is asked to or not, so comparing memory against a glibc-malloc tokio
measures two allocators as much as two servers. It turned out not to matter
(19.6 KiB/conn against 21.5), but the control is there.

## Results

10 cores, kernel 7.0, 2 server cores, 1 stream per connection, 10 s per cell.
Zero failed, errored or timed-out requests anywhere, including 10 000
connections against the shipped 512-slot buffer ring.

| conns | popple req/s | tokio req/s | popple mean / max | tokio mean / max | popple RSS | tokio RSS |
|---|---|---|---|---|---|---|
| 100 | 321 337 | 179 304 | 293 µs / 9.8 ms | 546 µs / 31 ms | 9.9 MB | 5.5 MB |
| 1 000 | 271 822 | 176 459 | 3.7 ms / 27.8 ms | 5.7 ms / 54.9 ms | 28.6 MB | 28.3 MB |
| 5 000 | 229 392 | 160 308 | 22.0 ms / 170 ms | 31.1 ms / 6.82 s | 108.5 MB | 127.3 MB |
| 10 000 | 242 417 | 169 698 | 39.6 ms / 62.6 ms | 52.2 ms / 6.85 s | 226.5 MB | 241.1 MB |

1.4–1.8× the throughput at equal CPU. The tail is the wider gap: the worst
request at 10 000 connections is 62 ms here against 6.85 s there.

These are single runs. The spread between adjacent connection counts (229k at
5 000 against 242k at 10 000) is noise, not a trend — take the ratio between
the two servers at one connection count, not the shape of one column.

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

## The buffer ring runs out before the server does

At 20 000 connections on the shipped `64x512` ring, the server drops ~2 500
connections per run with `transport error: No buffer space available`. It is not
the deadline: the commit before it drops 2 057, 4 028 and 2 055 across three
runs. It is the ring being shared by every connection on a worker, exactly as
`FLUSH_TIMEOUT`'s comment describes — a connection whose loop is not popping its
completions pins a buffer until the driver pauses its recv, and a recv that
finds the ring empty fails ENOBUFS, which the runtime does not resubmit.

`RING=` is the knob, and the whole effect is the slot count:

| ring | req/s | ENOBUFS | peak RSS |
|------|-------|---------|----------|
| 64x512 (32 MiB/worker) | 260 016 | 2 495 | 366 MB |
| 16x4096 (64 MiB/worker) | 261 220 | **0** | 445 MB |
| 16x16384 (256 MiB/worker) | 262 093 | **0** | 544 MB |

79 MB buys every connection at 20 000, for no throughput at all. The default is
sized for the connection counts in the sweep above and not for these.

One crash was seen, once, in a 20 000-connection run: a worker thread panicked
and `thread_per_core_with` unwrapped the join. It did not reproduce in six
further runs across both binaries and its cause is not established — recorded
here because a panic takes the process down, not because it is understood.

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
