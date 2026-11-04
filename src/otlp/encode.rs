//! The runtime's spans written straight to the OTLP wire format, into one
//! buffer the collector keeps: nothing is built per span, no name, key or
//! value copied into a `String`, no id into a `Vec`. [`super::proto`] reads
//! it back, in the tests.
//!
//! Field numbers are opentelemetry-proto v1's; a field at its default is left
//! out, as protobuf's own encoders do.

use std::time::{SystemTime, UNIX_EPOCH};

use slopio::tracing::SpanWrapper;
use slopio::tracing::types::{self, SpanData, SpanId};

use super::proto::{SpanFlags, SpanKind, StatusCode};
use crate::grpc::PREFIX_LEN;

const SCOPE_NAME: &str = "slopio";

const VARINT: u32 = 0;
const FIXED64: u32 = 1;
const LEN: u32 = 2;
const FIXED32: u32 = 5;

/// `out` is cleared, then holds one gRPC message: its 5-byte prefix, then an
/// `ExportTraceServiceRequest`. `resource` is a `Resource`'s encoded body,
/// from [`resource`].
pub(super) fn export_request(out: &mut Vec<u8>, resource: &[u8], batch: &[SpanWrapper]) {
    out.clear();
    out.extend_from_slice(&[0; PREFIX_LEN]);
    // ExportTraceServiceRequest.resource_spans
    message(out, 1, |out| {
        // ResourceSpans.resource
        bytes(out, 1, resource);
        // ResourceSpans.scope_spans
        message(out, 2, |out| {
            // ScopeSpans.scope, InstrumentationScope.name
            message(out, 1, |out| string(out, 1, SCOPE_NAME));
            for span in batch {
                // ScopeSpans.spans
                message(out, 2, |out| self::span(out, &span.data));
            }
        });
    });
    // No compression: the flag stays 0.
    let len = (out.len() - PREFIX_LEN) as u32;
    out[1..PREFIX_LEN].copy_from_slice(&len.to_be_bytes());
}

/// A string attribute of the resource, appended to `out`: a `Resource`'s
/// body is its attributes and nothing else.
pub(super) fn resource_attribute(out: &mut Vec<u8>, key: &str, value: &str) {
    // Resource.attributes
    message(out, 1, |out| {
        string(out, 1, key);
        message(out, 2, |out| string(out, 1, value));
    });
}

fn span(out: &mut Vec<u8>, s: &SpanData) {
    bytes(out, 1, &s.trace_id.to_bytes());
    bytes(out, 2, &s.span_id.to_bytes());
    if s.parent_span_id != SpanId::INVALID {
        bytes(out, 4, &s.parent_span_id.to_bytes());
    }
    string(out, 5, s.name);
    varint_field(out, 6, kind(s.span_kind) as u64);
    fixed64(out, 7, nanos(s.start_time));
    fixed64(out, 8, nanos(s.end_time));
    for kv in &s.attributes {
        message(out, 9, |out| attribute(out, kv));
    }
    varint_field(out, 10, s.dropped_attributes_count.into());
    for e in &s.events.events {
        message(out, 11, |out| event(out, e));
    }
    varint_field(out, 12, s.events.dropped_count.into());
    for l in &s.links {
        message(out, 13, |out| link(out, l));
    }
    varint_field(out, 14, s.dropped_links_count.into());
    message(out, 15, |out| status(out, &s.status));

    let mut flags = SpanFlags::SAMPLED | SpanFlags::CONTEXT_HAS_IS_REMOTE;
    if s.parent_span_is_remote {
        flags |= SpanFlags::CONTEXT_IS_REMOTE;
    }
    fixed32(out, 16, flags);
}

fn kind(k: types::SpanKind) -> SpanKind {
    match k {
        types::SpanKind::Internal => SpanKind::Internal,
        types::SpanKind::Server => SpanKind::Server,
        types::SpanKind::Client => SpanKind::Client,
        types::SpanKind::Producer => SpanKind::Producer,
        types::SpanKind::Consumer => SpanKind::Consumer,
    }
}

fn status(out: &mut Vec<u8>, s: &types::Status) {
    let (code, message) = match s {
        types::Status::Unset => (StatusCode::Unset, ""),
        types::Status::Ok => (StatusCode::Ok, ""),
        types::Status::Error(message) => (StatusCode::Error, *message),
    };
    string(out, 2, message);
    varint_field(out, 3, code as u64);
}

fn event(out: &mut Vec<u8>, e: &types::SpanEvent) {
    fixed64(out, 1, nanos(e.timestamp));
    string(out, 2, e.name);
    for kv in &e.attributes {
        message(out, 3, |out| attribute(out, kv));
    }
}

fn link(out: &mut Vec<u8>, l: &types::SpanLink) {
    bytes(out, 1, &l.trace_id.to_bytes());
    bytes(out, 2, &l.span_id.to_bytes());
    fixed32(out, 6, SpanFlags::SAMPLED);
}

/// A `KeyValue`, its value an `AnyValue`. A value at its default is still
/// written: the oneof says which it is.
fn attribute(out: &mut Vec<u8>, kv: &types::KeyValue) {
    string(out, 1, kv.key);
    message(out, 2, |out| match kv.value {
        types::Value::Str(s) => {
            tag(out, 1, LEN);
            varint(out, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        types::Value::Bool(b) => {
            tag(out, 2, VARINT);
            varint(out, b.into());
        }
        // int64: a negative one takes all ten bytes.
        types::Value::I64(i) => {
            tag(out, 3, VARINT);
            varint(out, i as u64);
        }
        types::Value::F64(f) => {
            tag(out, 4, FIXED64);
            out.extend_from_slice(&f.to_le_bytes());
        }
    });
}

/// A time before the epoch is 0, which OTLP reads as unknown.
fn nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

// ---- Wire format -----------------------------------------------------------

/// A nested message, its length unknown until `body` has written it: one
/// byte is kept for the length, and the body moved up in the rare case it
/// needs more, rather than every message measured before it is written.
fn message(out: &mut Vec<u8>, field: u32, body: impl FnOnce(&mut Vec<u8>)) {
    tag(out, field, LEN);
    let at = out.len();
    out.push(0);
    body(out);

    let len = out.len() - at - 1;
    let mut prefix = [0; 10];
    let n = varint_into(&mut prefix, len as u64);
    if n > 1 {
        out.resize(out.len() + n - 1, 0);
        out.copy_within(at + 1..at + 1 + len, at + n);
    }
    out[at..at + n].copy_from_slice(&prefix[..n]);
}

fn bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    if value.is_empty() {
        return;
    }
    tag(out, field, LEN);
    varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn string(out: &mut Vec<u8>, field: u32, value: &str) {
    bytes(out, field, value.as_bytes());
}

fn varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    if value == 0 {
        return;
    }
    tag(out, field, VARINT);
    varint(out, value);
}

fn fixed64(out: &mut Vec<u8>, field: u32, value: u64) {
    if value == 0 {
        return;
    }
    tag(out, field, FIXED64);
    out.extend_from_slice(&value.to_le_bytes());
}

fn fixed32(out: &mut Vec<u8>, field: u32, value: u32) {
    if value == 0 {
        return;
    }
    tag(out, field, FIXED32);
    out.extend_from_slice(&value.to_le_bytes());
}

fn tag(out: &mut Vec<u8>, field: u32, wire_type: u32) {
    varint(out, u64::from((field << 3) | wire_type));
}

fn varint(out: &mut Vec<u8>, value: u64) {
    let mut encoded = [0; 10];
    let n = varint_into(&mut encoded, value);
    out.extend_from_slice(&encoded[..n]);
}

fn varint_into(out: &mut [u8; 10], mut value: u64) -> usize {
    let mut n = 0;
    while value >= 0x80 {
        out[n] = value as u8 | 0x80;
        value >>= 7;
        n += 1;
    }
    out[n] = value as u8;
    n + 1
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prost::Message;
    use slopio::tracing::types::{KeyValue, SpanEvent, SpanLink, TraceId};

    use super::super::proto::{ExportTraceServiceRequest, any_value::Value};
    use super::*;

    fn at(nanos: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    fn span(name: &'static str, parent: Option<u64>) -> SpanWrapper {
        SpanWrapper::new(SpanData {
            trace_id: TraceId::from(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128),
            span_id: SpanId::from(0x1112_1314_1516_1718u64),
            parent_span_id: parent.map_or(SpanId::INVALID, SpanId::from),
            parent_span_is_remote: parent.is_some(),
            name,
            span_kind: types::SpanKind::Server,
            start_time: at(1_000),
            end_time: at(2_000),
            attributes: Default::default(),
            dropped_attributes_count: 3,
            events: Default::default(),
            links: Default::default(),
            dropped_links_count: 0,
            status: types::Status::Unset,
        })
    }

    fn decode(framed: &[u8]) -> ExportTraceServiceRequest {
        assert_eq!(framed[0], 0, "not compressed");
        let len = u32::from_be_bytes(framed[1..PREFIX_LEN].try_into().unwrap()) as usize;
        assert_eq!(len, framed.len() - PREFIX_LEN, "the prefix says the length");
        ExportTraceServiceRequest::decode(&framed[PREFIX_LEN..]).expect("valid protobuf")
    }

    /// Every field the exporter writes, as prost reads it back.
    #[test]
    fn a_span_reads_back_whole() {
        let mut s = span("GET", Some(0x2122_2324_2526_2728));
        s.data.attributes.push(KeyValue::new("url.path", "/hello"));
        s.data.attributes.push(KeyValue::new("ok", true));
        s.data.attributes.push(KeyValue::new("delta", -5i64));
        s.data.attributes.push(KeyValue::new("ratio", 0.5f64));
        s.data.attributes.push(KeyValue::new("empty", ""));
        let mut event = SpanEvent::new("failing");
        event.timestamp = at(1_500);
        event.attributes.push(KeyValue::new("level", "ERROR"));
        s.data.events.events.push(event);
        s.data.events.dropped_count = 1;
        s.data.links.push(SpanLink {
            trace_id: TraceId::from(7u128),
            span_id: SpanId::from(8u64),
        });
        s.data.status = types::Status::Error("broken");

        let mut resource = Vec::new();
        resource_attribute(&mut resource, "service.name", "api");
        let mut out = Vec::new();
        export_request(&mut out, &resource, &[s]);
        let request = decode(&out);

        let rs = &request.resource_spans[0];
        let service = &rs.resource.as_ref().unwrap().attributes[0];
        assert_eq!(service.key, "service.name");
        assert_eq!(
            service.value.as_ref().unwrap().value,
            Some(Value::StringValue("api".into()))
        );
        let ss = &rs.scope_spans[0];
        assert_eq!(ss.scope.as_ref().unwrap().name, SCOPE_NAME);

        let span = &ss.spans[0];
        assert_eq!(span.trace_id, (1..=16).collect::<Vec<u8>>());
        assert_eq!(span.span_id, (0x11..=0x18).collect::<Vec<u8>>());
        assert_eq!(span.parent_span_id, (0x21..=0x28).collect::<Vec<u8>>());
        assert_eq!(span.name, "GET");
        assert_eq!(span.kind, SpanKind::Server as i32);
        assert_eq!(
            (span.start_time_unix_nano, span.end_time_unix_nano),
            (1_000, 2_000)
        );
        let values: Vec<_> = span
            .attributes
            .iter()
            .map(|kv| (kv.key.as_str(), kv.value.as_ref().unwrap().value.clone()))
            .collect();
        assert_eq!(
            values,
            [
                ("url.path", Some(Value::StringValue("/hello".into()))),
                ("ok", Some(Value::BoolValue(true))),
                ("delta", Some(Value::IntValue(-5))),
                ("ratio", Some(Value::DoubleValue(0.5))),
                ("empty", Some(Value::StringValue(String::new()))),
            ]
        );
        assert_eq!(span.dropped_attributes_count, 3);
        assert_eq!(span.events[0].name, "failing");
        assert_eq!(span.events[0].time_unix_nano, 1_500);
        assert_eq!(span.events[0].attributes[0].key, "level");
        assert_eq!(span.dropped_events_count, 1);
        assert_eq!(span.links[0].span_id, 8u64.to_be_bytes());
        assert_eq!(span.links[0].flags, SpanFlags::SAMPLED);
        let status = span.status.as_ref().unwrap();
        assert_eq!(
            (status.code, status.message.as_str()),
            (StatusCode::Error as i32, "broken")
        );
        assert_eq!(
            span.flags,
            SpanFlags::SAMPLED | SpanFlags::CONTEXT_HAS_IS_REMOTE | SpanFlags::CONTEXT_IS_REMOTE
        );
    }

    /// Lengths of one, two and three bytes, the ones past the first moving
    /// the message up: a span of 100 attributes, and a batch of 400 spans.
    #[test]
    fn long_messages_take_longer_lengths() {
        let mut big = span("big", None);
        for _ in 0..100 {
            big.data.attributes.push(KeyValue::new("key", "value"));
        }
        let mut batch = vec![big];
        batch.extend((0..400).map(|_| span("small", None)));

        let mut out = Vec::new();
        export_request(&mut out, &[], &batch);
        let spans = &decode(&out).resource_spans[0].scope_spans[0].spans;

        assert_eq!(spans.len(), 401);
        assert_eq!(spans[0].attributes.len(), 100);
        assert!(spans[0].parent_span_id.is_empty(), "a root has no parent");
        assert_eq!(
            spans[0].flags,
            SpanFlags::SAMPLED | SpanFlags::CONTEXT_HAS_IS_REMOTE
        );
        assert!(spans[1..].iter().all(|s| s.name == "small"));
        assert!(out.len() > 16_384, "a three-byte length was needed");
    }

    /// The buffer is the collector's for good: a batch starts it afresh.
    #[test]
    fn a_second_batch_replaces_the_first() {
        let mut out = Vec::new();
        export_request(&mut out, &[], &[span("first", None), span("first", None)]);
        export_request(&mut out, &[], &[span("second", None)]);

        let spans = &decode(&out).resource_spans[0].scope_spans[0].spans;
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name, "second");
    }
}
