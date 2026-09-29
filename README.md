# slopio-h2

An HTTP/2 server and client, with gRPC on top, for Linux. Built on
[`runtime`](https://github.com/saucisoupe/slopio), on io_uring.

## HTTP/2 only

There is no HTTP/1.1, and no upgrade from it. Cleartext is prior knowledge
(RFC 9113 §3.4); TLS negotiates `h2` with ALPN (§3.3). h2spec passes clean,
strict suite included.

## Server

- A **handler** is an async function called once per stream. It reads the
  request and writes the response on a `Stream`, and is told who connected.
  A handler that panics fails its own stream, not the connection.
- **`Limits`** say what one connection may hold and for how long: concurrent
  streams, flow-control window, header list size, idle and handshake
  timeouts. A set that does not add up is refused before the server listens.
- **Graceful shutdown**: SIGTERM or SIGINT sends every connection a GOAWAY,
  lets the streams in flight finish up to `drain_timeout`, then cuts the rest.
- **Defences** against the published HTTP/2 denial-of-service attacks (rapid
  reset, CONTINUATION flood, HPACK bombs, slowloris, ...): budgets stop the
  floods, size caps stop the bombs, deadlines stop the slow peers. Each has a
  test, and each deadline test has an honest peer beside it that must not be
  cut.

## Client

- A **`Client`** holds a pool of connections by origin and opens them as
  requests need them. An application never handles a connection itself.
- Cleartext or TLS is in the type: `PlainTextClient` or `TlsClient`.
- **Keepalive**: a silent server is pinged, with a stream open or not, and
  given up on if it does not answer.
- **Backpressure**: window credit goes back only for bytes the application
  has read. No deadline is imposed on a request; that is the caller's choice.
- Names are resolved with `slopio-dns`, which reads no system configuration.

## gRPC

Behind the `grpc` feature, on by default. Unary and streaming calls on both
sides, with messages decoded by `prost` into the caller's own types,
`grpc-timeout`, cancellation, gzip and deflate, and status codes as the spec
has them. The same rules serve the client and the server.

## TLS

Behind the `tls` feature, off by default. The handshake is `rustls`; the
record layer is the kernel's (kTLS), so reads and writes stay plain io_uring
operations. A server or client asked for TLS on a kernel without kTLS refuses
to start rather than fall back.

## OTLP

Behind the `otlp` feature, off by default. `OtlpCollector` exports the
runtime's spans over OTLP/gRPC to Jaeger, Tempo or an OpenTelemetry
collector; `examples/telemetry_server.rs` shows it end to end.

The encoder is written by hand rather than with `prost`, and will stay so
until Rust's allocator API (`allocator_api`) is stable. A span's strings live
in its own arena, while a `prost` message owns its fields as `String`s and
`Vec`s on the global allocator: building one copies every name, key, value
and id of every span. Written by hand, a batch goes straight from the spans
into one buffer the collector keeps, with nothing allocated per span. The
`prost` structs in `src/otlp/proto.rs` remain, to read the encoding back in
the tests.

## Layout

- `src/server`, `src/client`: the two ends.
- `src/shared`: framing, HPACK, flow control and the connection state both
  ends run.
- `src/grpc`: gRPC over either end.
- `src/otlp`: span export over OTLP/gRPC.
- `tests` modules under `src`: deterministic, frame by frame on the
  runtime's simulated I/O. `tests`: both ends against each other over a
  real socket.
- `examples`: servers, clients and load generators.
- `TODO.md`: what is left.
