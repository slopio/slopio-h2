//! The runtime's spans as OTLP messages.

use std::time::{SystemTime, UNIX_EPOCH};

use runtime::tracing::SpanWrapper;
use runtime::tracing::types::{self, SpanData, SpanId};

use super::proto::{
    AnyValue, Event, ExportTraceServiceRequest, InstrumentationScope, KeyValue, Link, Resource,
    ResourceSpans, ScopeSpans, Span, SpanFlags, SpanKind, Status, StatusCode, any_value,
};

const SCOPE_NAME: &str = "slopio";

pub(super) fn export_request(
    resource: &Resource,
    batch: &[SpanWrapper],
) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource.clone()),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: SCOPE_NAME.to_owned(),
                    version: String::new(),
                }),
                spans: batch.iter().map(|span| self::span(&span.data)).collect(),
            }],
        }],
    }
}

pub(super) fn key_value(key: &str, value: any_value::Value) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue { value: Some(value) }),
    }
}

fn span(s: &SpanData) -> Span {
    let mut flags = SpanFlags::SAMPLED | SpanFlags::CONTEXT_HAS_IS_REMOTE;
    if s.parent_span_is_remote {
        flags |= SpanFlags::CONTEXT_IS_REMOTE;
    }
    Span {
        trace_id: s.trace_id.to_bytes().to_vec(),
        span_id: s.span_id.to_bytes().to_vec(),
        parent_span_id: match s.parent_span_id {
            SpanId::INVALID => Vec::new(),
            parent => parent.to_bytes().to_vec(),
        },
        name: s.name.to_owned(),
        kind: kind(s.span_kind) as i32,
        start_time_unix_nano: nanos(s.start_time),
        end_time_unix_nano: nanos(s.end_time),
        attributes: s.attributes.iter().map(attribute).collect(),
        dropped_attributes_count: s.dropped_attributes_count,
        events: s.events.events.iter().map(event).collect(),
        dropped_events_count: s.events.dropped_count,
        links: s.links.iter().map(link).collect(),
        dropped_links_count: s.dropped_links_count,
        status: Some(status(&s.status)),
        flags,
    }
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

fn status(s: &types::Status) -> Status {
    let (code, message) = match s {
        types::Status::Unset => (StatusCode::Unset, ""),
        types::Status::Ok => (StatusCode::Ok, ""),
        types::Status::Error(message) => (StatusCode::Error, *message),
    };
    Status {
        message: message.to_owned(),
        code: code as i32,
    }
}

fn event(e: &types::SpanEvent) -> Event {
    Event {
        time_unix_nano: nanos(e.timestamp),
        name: e.name.to_owned(),
        attributes: e.attributes.iter().map(attribute).collect(),
    }
}

fn link(l: &types::SpanLink) -> Link {
    Link {
        trace_id: l.trace_id.to_bytes().to_vec(),
        span_id: l.span_id.to_bytes().to_vec(),
        flags: SpanFlags::SAMPLED,
    }
}

fn attribute(kv: &types::KeyValue) -> KeyValue {
    let value = match kv.value {
        types::Value::Str(s) => any_value::Value::StringValue(s.to_owned()),
        types::Value::Bool(b) => any_value::Value::BoolValue(b),
        types::Value::I64(i) => any_value::Value::IntValue(i),
        types::Value::F64(f) => any_value::Value::DoubleValue(f),
    };
    key_value(kv.key, value)
}

/// A time before the epoch is 0, which OTLP reads as unknown.
fn nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}
