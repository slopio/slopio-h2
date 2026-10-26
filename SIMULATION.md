# Simulated scenarios

What the deterministic simulation should explore next. The scripted tests
already take each attack alone (floods, rapid reset, slowloris, HPACK bomb,
CONTINUATION); these are the cases only a seed-drawn world reaches: many
connections at once, timing, faults, and invariants held over thousands of
runs.

The shared harness is `src/dst/`: drawing a world from a seed, the hostility
profile, and a failing seed replayed with the ring's journal kept in
`target/tmp/`. `DST_SEED=<n>` replays one seed, `DST_SEEDS=<n>` or
`DST_SEEDS=<a>..<b>` runs more than the default, `DST_TRACE=1` keeps the
journal of a passing seed. `src/dst/peer.rs` is the wire of a frame-aware
peer: it checks and credits both windows, applies and acknowledges SETTINGS,
answers PINGs and decodes the program's header blocks.

What runs today:

| DST | Peers | Explores |
| --- | --- | --- |
| `server::…::dst` | 1-4 `Dialogue` clients | small GETs and POSTs under drawn faults: cut sends, vanishing, failed sends, short and slow writes, EINTR, multishot ended |
| `client::…::dst` | a `Dialogue` server | the same, from the client's side |
| `server::…::dst_peer` | 1-4 frame-aware clients | scenarios 2, 3 and 4 below, and a client metering an answer a byte at a time |
| `client::…::dst_peer` | a frame-aware server | scenarios 2, 3 and 4 below |
| `server::…::dst_crowd` | 16-48 calm `Dialogue` clients and 1-4 ailing ones | scenario 1 below |

The defaults keep the suite to a few seconds. Run deeper before trusting a
change to these paths, for example `DST_SEEDS=1024` for the `dst_peer` ones
and `DST_SEEDS=128` for `dst_crowd`.

## Critical

1. **A crowd with a few ailing peers** (server). Done: `dst_crowd`. Dozens of
   healthy clients share a worker with a few that stop reading, dribble a byte
   at a time, or flood. One bad peer must not hurt the others: `FLUSH_TIMEOUT`
   and the empty-ring backoff exist for this, and the backoff's fairness is
   unproven. Holds: every healthy client is answered in full within a bound,
   whatever the ailing ones do.

2. **Flow control under pressure** (both). Done: both `dst_peer`. Bodies and
   answers of hundreds of KiB, past the client's 1 MiB stream window on its
   side, a peer that credits late, unevenly or a byte at a time, and
   `SETTINGS_INITIAL_WINDOW_SIZE` changed mid-stream so that windows go
   negative (§6.9.2). Holds: bytes arrive whole and in order, nothing is sent
   past a window, a stalled peer ends on a deadline.

3. **Cancellation mid-flight** (both). Done: both `dst_peer`.
   RST_STREAM(CANCEL) at a drawn point: during the head, the body, the
   response; on the client, the application dropping a stream it is reading.
   Holds: the handler ends, the other streams on the connection are served,
   and the client writes nothing on a stream after resetting it. The server's
   side of that is held only by its windows: no check yet that it stops
   writing once it has read the reset.

4. **GOAWAY and graceful shutdown under load** (both). Done: both `dst_peer`.
   The server's `run_until` stops at a drawn moment, with clients
   mid-dialogue. Holds: the GOAWAY's `last_stream_id` is right, every stream
   up to it is answered and none past it is processed, the drain deadline
   holds, every connection ends. On the client, a server GOAWAY at a drawn
   moment: requests past `last_stream_id` fail and are never answered, those
   before it complete.

## What they found

- **Fixed**: the client's send had no deadline, so a server that stopped
  reading held the connection's loop for ever (`client::…::dst`, seed 62).
  `FLUSH_TIMEOUT` now bounds it, and the farewell with it.
- **Fixed**: on an empty buffer ring, a connection re-armed its recv at once
  and spun at full CPU until another connection gave its buffers back
  (`server::…::dst`, seeds 130, 397, 456). It now yields a few times, then
  sleeps until the timewheel's next tick.
- **Fixed** (runtime d8b636f): a connection whose task stops
  polling its `MultiRecv` kept its multishot recv armed, so the kernel went
  on filling buffers of the ring every connection on the worker shares, up
  to the runtime's default of 32 queued completions, each a whole buffer
  however few bytes it carried. A connection stalled in a send held about 33
  buffers until `FLUSH_TIMEOUT` cut it; two stuck readers emptied
  `dst_crowd`'s ring and held six healthy clients 4.9 s (`DST_SEED=88`).
  `MultiRecv::with_queue_limit`, new in the runtime, takes the bound at run
  time, and `PlainMessages` now pauses past 4 (`RECV_QUEUE_LIMIT`): seed 88
  answers its slowest healthy client in 54 ms, and `DST_SEEDS=128` passes. An
  interleaved A/B on `bench_server` (4 rounds, 2 server cores) found GET, POST
  1M and 1000 connections within noise, and POST 16K up 34 %, likely warmer
  buffers. Still to do: the same bound in `slopio-tls`, whose `MultiRecv`s
  keep the default; and in the runtime, incremental provided buffers
  (`IOU_PBUF_RING_INC`) so that small reads stop costing a buffer each.
- **Open, in the runtime**: a `Sleep` ends early, not late. The wheel rounds
  down to its 10 ms tick, so 15 ms sleeps 10 ms and 25 ms sleeps 20 ms,
  where `Sleep::during` says up to 10 ms late. Durations here are 5 s,
  served exactly, or multiples of the tick, so it bites little.
- **Noted**: a connection accepted as the server stops is closed unread,
  as one still in the listener's backlog would be; a client sees it closed
  and may retry.
- **Noted**: a client request past a GOAWAY's last stream fails with an
  `io::Error` of kind `Other`, the same as any other failure, so an
  application cannot tell it is safe to retry without reading the message.

## Important

5. **Legal but unusual wire traffic** (server). CONTINUATION, padding,
   PRIORITY, unknown frame types, the peer's own PING (which needs an ACK),
   SETTINGS mid-connection, the HPACK dynamic table. Today's peers speak the
   barest HTTP/2. Holds: served exactly as without them.

6. **Malformed frames inside valid dialogues** (server). A healthy dialogue
   with mutations: wrong lengths, frames on stream 0 or on idle streams,
   END_STREAM twice. Holds: no panic, the right scope of error (stream or
   connection, §5.4), the other connections untouched.

7. **Handlers that misbehave** (server). Draw the handler too: slow,
   panicking, answering before the body, never reading it, streaming a long
   response; with peer faults on top. Today it is always `echo`.

8. **The pool under faults** (client). Connects refused or timing out,
   servers that GOAWAY or vanish, `max_connections`, idle extra connections,
   many origins. Holds: no request lost without an error, the origin map
   shrinks back, idle extras close.

## Worthwhile

9. **gRPC with faults.** Streaming both ways, `grpc-timeout` on virtual
   time, messages split across frames and buffers, faults mid-message.
   Holds: the right status, never a wrong or partial message.

10. **An early half-close.** FIN right after the requests rather than at the
    end. Holds: still answered (`HalfClosed`), or the cut bodies reset.

11. **Errors outside reads.** Accept errors (`EMFILE`, the `ACCEPT_BACKOFF`
    path), send errors on a live connection, runs of hours of virtual time
    for the long timers (`MAX_SLEEP` slices, the fixed 5 s store).

## Out of reach

TLS: kTLS lives in the kernel, which the simulator does not model.

## What the rest takes

Scenario 5 extends the frame-aware peers in `src/dst/peer.rs` (CONTINUATION,
padding, unknown frames, its own PING, the HPACK dynamic table). Scenario 6
is a mutation layer over a healthy `Dialogue`. Scenario 7 draws the handler
in `dst_peer` the way the peers are drawn. Scenario 8 needs connects to
script (`ConnectEvent`) and the pool's opener on simulated sockets.
