# What is left

## Receiving request bodies: the runtime's buffer ring

POST is about half of h2o's rate at 4-16 KiB bodies (`bench/vs-h2o.sh`: 256k
against 506k req/s at 16 KiB), while GET is within 15-20 % and many
connections are ahead. The HTTP/2 code is not the cause: the frames on the
wire are the same as h2o's, and neither the whole-body path, the flush order
nor the window size moves the number.

The cause is how `runtime` hands out receive buffers. The kernel takes them in
ring order and each one comes back at the tail, so every recv lands in a
different 64 KiB buffer out of `64x128+512`, about 40 MB per core. The copy
goes to cold memory: 6.8 µs of kernel time per request, against h2o's 2.4 µs.
A 64-buffer ring brings POST 4 KiB level with h2o (949k against 941k), and
then falls over at 1000 connections (119k against 297k), because the ring
runs dry.

- Incremental provided buffers (`IOU_PBUF_RING_INC`, kernel 6.12+): recvs
  packed one after another into the same buffer, which keeps it warm and not
  half empty, with a ring still large enough for many connections.
- Or recycle the most recently freed buffer first, with few buffers exposed.
- Confirm with `perf` as root first: the lead comes from ring-size sweeps, not
  from a profile.
- What stays after that at 16 KiB (about 330k against 500k) includes the copy
  into `InputData`; h2o parses the body in its read buffer.

## Client

- The in-place gRPC send only uses the room left in the open segment. A
  message that would fit a fresh one falls back to framing it apart, copying
  it and cutting it at the segment boundary.
- A gRPC call whose input failed (message too large, bad compressed flag, too
  many messages) is not reset. The client keeps crediting and discarding DATA
  until the application drops the call.
- Attaching slices leaves header-only segments behind them: in flight, up to
  about 1 MB of 16 KiB segments per connection, which carry 9 bytes each.
- Nothing waits at the limit: past `max_connections` a request is refused with
  `AtLimit` rather than queued for a stream to free up.
- The peer's settings are no longer visible through `Client`, so
  `grpc_load` cannot cap its concurrency at the server's
  `max_concurrent_streams` any more. Calls past it now count as failures.
- DNS: A records first, AAAA only when there are none. No Happy Eyeballs, and
  no `/etc/resolv.conf`, since slopio-dns reads no system configuration.
- `ATTACH_MIN` (4 KiB) is provisional. Measure it with large uploads, which
  `grpc_load` does not do.
- `send_zc` is off on the client (`PlainMessages<U, false>`). With slices
  attached, it could pay for large uploads if they are held until the
  kernel's notification.
- A streamed body's buffer grows by doubling, recopying what it holds, when
  several frames land before a read. Reserving capacity after each read
  would avoid most of it.

## Server

- `write_owned` is not exposed on the server's `Stream`, though
  `SharedConnection::write_data_owned` is there for it.

## Benchmarks

- `bench/vs-h2o.sh` measures the server only, with `h2load` as the client.
  There is no benchmark of our client yet, for example `grpc_load` before and
  after, or a load generator built on `Client` against h2o.
