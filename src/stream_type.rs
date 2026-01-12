// Copyright (c) 2026 Saorsa Labs Limited
//
// Licensed under the GPL-3.0 license

//! Stream type re-exports from ant-quic.
//!
//! This module re-exports the stream type types from ant-quic to provide
//! a consistent API for protocol multiplexing across the saorsa ecosystem.
//!
//! Each QUIC stream's first byte identifies the protocol type.
//!
//! ## Stream Type Registry
//!
//! | Range | Protocol | Types |
//! |-------|----------|-------|
//! | 0x00-0x0F | Gossip | Membership, PubSub, Bulk |
//! | 0x10-0x1F | DHT | Query, Store, Witness, Replication |
//! | 0x20-0x2F | WebRTC | Signal, Media, Data |
//! | 0xF0-0xFF | Reserved | Future use |

// Re-export everything from ant-quic's link_transport module
pub use ant_quic::link_transport::{StreamFilter, StreamType, StreamTypeFamily};

/// Alias for StreamTypeFamily for backward compatibility.
pub type StreamTypeRange = StreamTypeFamily;
