// Copyright (c) 2026 Saorsa Labs Limited
//
// Licensed under the GPL-3.0 license
//
// Shared transport abstraction for the Saorsa ecosystem.
// Unifies gossip, DHT, and WebRTC protocols over a single ant-quic connection per peer.

//\! # saorsa-transport
//\!
//\! Shared transport abstraction that multiplexes multiple protocols over a single
//\! QUIC connection per peer using ant-quic's typed stream API.
//\!
//\! ## Overview
//\!
//\! This crate provides:
//\! - [`StreamType`] - Protocol type registry (first byte of each stream)
//\! - [`StreamFilter`] - Filter for accepting specific stream types
//\! - [`ProtocolHandler`] - Trait for handling incoming streams by protocol type
//\! - [`SharedTransport`] - Multi-protocol transport over ant-quic
//\!
//\! ## Stream Type Registry
//\!
//\! Each stream's first byte identifies its protocol:
//\!
//\! | Range | Protocol | Types |
//\! |-------|----------|-------|
//\! | 0x00-0x0F | Gossip | Membership, PubSub, Bulk |
//\! | 0x10-0x1F | DHT | Query, Store, Witness, Replication |
//\! | 0x20-0x2F | WebRTC | Signal, Media, Data |
//\! | 0xF0-0xFF | Reserved | Future use |
//\!
//\! ## Example
//\!
//\! ```rust,ignore
//\! use saorsa_transport::{SharedTransport, StreamType, ProtocolHandler};
//\! use ant_quic::P2pLinkTransport;
//\!
//\! // Create transport with ant-quic backend
//\! let quic_transport = P2pLinkTransport::new(config).await?;
//\! let transport = SharedTransport::new_with_transport(quic_transport);
//\!
//\! // Register handlers
//\! transport.register_handler(my_gossip_handler).await;
//\! transport.register_handler(my_dht_handler).await;
//\!
//\! // Start accepting connections
//\! transport.run().await?;
//\! ```

mod error;
mod handler;
mod stream_type;
mod transport;

pub use error::{TransportError, TransportResult};
pub use handler::{BoxedHandler, ProtocolHandler, ProtocolHandlerExt};
pub use stream_type::{StreamFilter, StreamType, StreamTypeFamily, StreamTypeRange};
pub use transport::SharedTransport;

// Re-export commonly used types from ant-quic
pub use ant_quic::PeerId;
pub use ant_quic::link_transport::{
    Capabilities, ConnectionStats, LinkConn, LinkEvent, LinkRecvStream, LinkSendStream,
    LinkTransport, ProtocolId,
};
