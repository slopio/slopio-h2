//! A peer's SETTINGS (§6.5), as received and as assumed before it speaks.
//!
//! # What is not done yet
//!
//! `Settings::apply` parses and validates a peer's SETTINGS frame. Everything
//! downstream of that is missing, so the list below is deliberately long.
//!
//! ## Applied
//!
//! - **`INITIAL_WINDOW_SIZE` (0x04)** — stored here, and §6.9.2's retroactive
//!   shift of every live stream's send window by `new - old` is done by
//!   `Protocol::on_settings`, which has the stream map. A window may go
//!   negative that way; overflowing 2^31-1 is a connection
//!   `FLOW_CONTROL_ERROR`.
//!
//! - **`HEADER_TABLE_SIZE` (0x01)** — clamped here, then handed to the HPACK
//!   encoder by `on_settings`, which shrinks its table and emits the dynamic
//!   table size update at the head of the next block (RFC 7541 §4.2).
//! - **`MAX_FRAME_SIZE` (0x05)** — handed to `SharedConnection`, where it
//!   bounds the DATA and HEADERS frames we emit.
//!
//! ## Stored but not honoured
//!
//! Applying a value to this struct is not the same as obeying it. None of
//! these currently reach the code they are supposed to constrain:
//!
//! - `MAX_CONCURRENT_STREAMS` — bounds streams *we* initiate, so inert
//!   without push; must never be confused with our own limit in `admits`.
//! - `ENABLE_PUSH`, `ENABLE_CONNECT_PROTOCOL`, `MAX_HEADER_LIST_SIZE`,
//!   `NO_RFC7540_PRIORITIES` — recorded, read by nobody.
//!
//! ## Not sent
//!
//! - **The SETTINGS ACK (§6.5.3)**, in `Connection::on_settings`. Waiting on
//!   the writer; `encode_settings_ack` is already there.
//! - **Our own SETTINGS**, in `Connection::on_preface`. We advertise nothing,
//!   so the peer assumes the RFC defaults for us — in particular it never
//!   learns of `MAX_CONCURRENT_STREAMS` (64), which `admits` enforces
//!   silently, nor of `CONNECTION_RECV_WINDOW`.
//! - No queue of unacked local settings, so we cannot *reduce* anything we
//!   announce: that needs knowing when the peer stopped using the old value.
//!
//! ## Not checked
//!
//! - §3.4: the first frame after the preface MUST be a SETTINGS. The decoder
//!   validates the 24 magic bytes only.
//! - RFC 9218 §2.1: `NO_RFC7540_PRIORITIES` MUST NOT change after the first
//!   SETTINGS; a change is a `PROTOCOL_ERROR`. Detecting it needs one more
//!   bit of state.
//! - No budget on unacked SETTINGS: a peer flooding empty frames forces one
//!   ACK each (CVE-2019-9515).
//!
//! ## Shape
//!
//! - 0x08 and 0x09 arrive as `Setting::Unknown` because `SettingsIter` only
//!   names the six ids of §6.5.2, and `setting_id_value` cannot encode them
//!   at all — so advertising extended CONNECT is impossible today. Two more
//!   variants on `Setting` would fix both ends.

use crate::shared::codec::{
    frames::DEFAULT_MAX_FRAME_SIZE,
    types::{FLOW_CONTROL_ERROR, PROTOCOL_ERROR, Setting},
};

/// The largest HPACK dynamic table we will keep for encoding, whatever the
/// peer offers.
///
/// §6.5.2 lets a peer name any `u32` here, and it is an *allowance* rather
/// than an instruction: §4.2 says an encoder may use less, and this one does.
/// Taking the number at face value means a peer sends `0xFFFFFFFF` and the
/// table it caps never evicts — growing by an entry for every distinct header
/// this server emits, for the life of the connection, times the number of
/// connections. One `Date` per second is enough to make that unbounded.
///
/// 4096 is the §6.5.2 default, and the reason for not going higher is that the
/// cost is per connection and the benefit is not. An entry costs its name, its
/// value and 32 bytes, so this bounds the table at ~128 entries and its index
/// at a few KiB — against 20 000 connections, which is the scale this server is
/// measured at. Raising it is a memory decision to make against a measured
/// compression gain on real response headers, not something to concede to
/// whatever a peer asks for.
pub const MAX_ENCODER_TABLE_SIZE: u32 = 4_096;

#[derive(Clone, Debug)]
pub struct Settings {
    /// 0x01 — max size of the HPACK dynamic table. Default 4096.
    pub header_table_size: u32,
    /// 0x02 — server push. Default true, but a server advertises false.
    pub enable_push: bool,
    /// 0x03 — `None` = unlimited (default). `Some(0)` forbids any new stream.
    pub max_concurrent_streams: Option<u32>,
    /// 0x04 — initial window of every stream. Default 65535, max 2^31-1.
    pub initial_window_size: u32,
    /// 0x05 — max frame payload size. Default 16384, within [2^14, 2^24-1].
    pub max_frame_size: u32,
    /// 0x06 — `None` = unlimited (default). Advisory, not binding.
    pub max_header_list_size: Option<u32>,
    /// 0x08 — RFC 8441, extended CONNECT (WebSocket over h2). Default false.
    pub enable_connect_protocol: bool,
    /// 0x09 — RFC 9218, dropping the RFC 7540 priority scheme. Default false.
    pub no_rfc7540_priorities: bool,
}

/// §6.5.2: a SETTINGS value outside its legal range. Always fatal to the
/// connection, but not always with the same code.
pub struct InvalidSetting {
    pub code: u32,
    pub message: &'static str,
}

impl Settings {
    /// Takes one entry of a peer's SETTINGS frame. Entries apply in the order
    /// they appear, and a repeated id legally overwrites the earlier one, so
    /// this is meant to be called in a loop with no deduplication.
    pub fn apply(&mut self, setting: Setting) -> Result<(), InvalidSetting> {
        match setting {
            // Any u32 is legal, and using less than allowed is permitted —
            // which is the whole point, since the allowance is what a peer
            // controls and the memory is what we pay.
            Setting::HeaderTableSize(value) => {
                self.header_table_size = value.min(MAX_ENCODER_TABLE_SIZE)
            }

            Setting::EnablePush(value) => {
                self.enable_push = as_bool(value, "ENABLE_PUSH must be 0 or 1")?;
            }

            // Any u32 is legal, `Some(0)` included — that one is the peer
            // telling us to open nothing more.
            Setting::MaxConcurrentStreams(value) => self.max_concurrent_streams = Some(value),

            // §6.5.2: capped at 2^31-1, and the code for going past it is
            // FLOW_CONTROL_ERROR, not PROTOCOL_ERROR. Only the new value is
            // stored here; §6.9.2 makes it retroactive on every live stream,
            // and that walk is the connection's, from the change in this
            // field before and after the frame.
            Setting::InitialWindowSize(value) => {
                if value > i32::MAX as u32 {
                    return Err(InvalidSetting {
                        code: FLOW_CONTROL_ERROR,
                        message: "INITIAL_WINDOW_SIZE above 2^31-1",
                    });
                }
                self.initial_window_size = value;
            }

            Setting::MaxFrameSize(value) => {
                // §6.5.2: confined to [2^14, 2^24-1].
                if !(16_384..=16_777_215).contains(&value) {
                    return Err(InvalidSetting {
                        code: PROTOCOL_ERROR,
                        message: "MAX_FRAME_SIZE outside [2^14, 2^24-1]",
                    });
                }
                self.max_frame_size = value;
            }

            // Advisory (§6.5.2): the peer may exceed it, so no bound to check.
            Setting::MaxHeaderListSize(value) => self.max_header_list_size = Some(value),

            // 0x08 and 0x09 reach us as `Unknown`: `SettingsIter` only names
            // the six ids of §6.5.2, these two come from later RFCs.
            Setting::Unknown { id: 0x8, value } => {
                self.enable_connect_protocol =
                    as_bool(value, "ENABLE_CONNECT_PROTOCOL must be 0 or 1")?;
            }
            Setting::Unknown { id: 0x9, value } => {
                self.no_rfc7540_priorities =
                    as_bool(value, "NO_RFC7540_PRIORITIES must be 0 or 1")?;
            }

            // §6.5.2: an unrecognized id MUST be ignored, not rejected. That
            // is the whole extension mechanism of the protocol.
            Setting::Unknown { .. } => {}
        }
        Ok(())
    }
}

/// The flag-shaped settings share one rule: anything but 0 or 1 is a
/// PROTOCOL_ERROR on the connection.
fn as_bool(value: u32, message: &'static str) -> Result<bool, InvalidSetting> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(InvalidSetting {
            code: PROTOCOL_ERROR,
            message,
        }),
    }
}

impl Default for Settings {
    /// §6.5.2: what a peer is assumed to use until it says otherwise. The
    /// SETTINGS frame of the preface is mandatory but may carry nothing, and
    /// any id it omits keeps the value below — so these are what a connection
    /// actually runs on, not a placeholder.
    fn default() -> Self {
        Self {
            header_table_size: 4_096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65_535,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: false,
            no_rfc7540_priorities: false,
        }
    }
}
