//! Frame parsing and serialization.
//!
//! Adapted from hyperium/h2 (MIT), see LICENSE-THIRD-PARTY. `Bytes` is gone
//! from the paths that read out of runtime-owned buffers, unused frame types
//! are dropped, and HEADERS handling is reworked.

pub mod ext;
pub mod frames;
pub mod types;
