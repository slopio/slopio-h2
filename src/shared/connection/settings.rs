//! TODO: gaps in SETTINGS handling.
//!
//! - `MAX_CONCURRENT_STREAMS`, `ENABLE_PUSH`, `ENABLE_CONNECT_PROTOCOL`,
//!   `MAX_HEADER_LIST_SIZE`, `NO_RFC7540_PRIORITIES` are stored but not
//!   honoured. The peer's `MAX_CONCURRENT_STREAMS` bounds streams *we*
//!   initiate; must never be confused with our own limit in `admits`.
//! - No SETTINGS ACK (§6.5.3) and none of our own SETTINGS are sent, so the
//!   peer never learns our `MAX_CONCURRENT_STREAMS` (64) or
//!   `CONNECTION_RECV_WINDOW`. No queue of unacked local settings, so we
//!   cannot *reduce* anything we announce.
//! - §3.4: the first frame after the preface MUST be a SETTINGS — not checked.
//! - RFC 9218 §2.1: `NO_RFC7540_PRIORITIES` MUST NOT change after the first
//!   SETTINGS — not checked.
//! - No budget on unacked SETTINGS: a peer flooding empty frames forces one
//!   ACK each (CVE-2019-9515).
//! - `setting_id_value` cannot encode 0x08/0x09, so extended CONNECT cannot
//!   be advertised.

use crate::shared::codec::{
    frames::DEFAULT_MAX_FRAME_SIZE,
    types::{FLOW_CONTROL_ERROR, PROTOCOL_ERROR, Setting},
};

/// Cap on the HPACK encoder table whatever the peer offers (RFC 7541 §4.2
/// allows using less). Taken at face value, a peer's `0xFFFFFFFF` makes a table
/// that never evicts and grows per distinct header for the life of the
/// connection. The cost is per connection; don't raise it without measuring.
pub const MAX_ENCODER_TABLE_SIZE: u32 = 4_096;

#[derive(Clone, Debug)]
pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    /// `None` = unlimited (default). `Some(0)` forbids any new stream.
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    /// Advisory, not binding.
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: bool,
    pub no_rfc7540_priorities: bool,
}

/// §6.5.2: always fatal to the connection.
pub struct InvalidSetting {
    pub code: u32,
    pub message: &'static str,
}

impl Settings {
    /// Entries apply in order; a repeated id legally overwrites the earlier one.
    pub fn apply(&mut self, setting: Setting) -> Result<(), InvalidSetting> {
        match setting {
            // Any u32 is legal; clamped, see `MAX_ENCODER_TABLE_SIZE`.
            Setting::HeaderTableSize(value) => {
                self.header_table_size = value.min(MAX_ENCODER_TABLE_SIZE)
            }

            Setting::EnablePush(value) => {
                self.enable_push = as_bool(value, "ENABLE_PUSH must be 0 or 1")?;
            }

            Setting::MaxConcurrentStreams(value) => self.max_concurrent_streams = Some(value),

            // §6.5.2: past 2^31-1 is FLOW_CONTROL_ERROR, not PROTOCOL_ERROR.
            // §6.9.2's retroactive shift of live streams is the connection's job.
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

            Setting::Unknown { id: 0x8, value } => {
                self.enable_connect_protocol =
                    as_bool(value, "ENABLE_CONNECT_PROTOCOL must be 0 or 1")?;
            }
            Setting::Unknown { id: 0x9, value } => {
                self.no_rfc7540_priorities =
                    as_bool(value, "NO_RFC7540_PRIORITIES must be 0 or 1")?;
            }

            // §6.5.2: an unrecognized id MUST be ignored.
            Setting::Unknown { .. } => {}
        }
        Ok(())
    }
}

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
    /// §6.5.2: what a peer is assumed to use until it says otherwise.
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
