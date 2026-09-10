// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! saorsa-transport: QUIC transport protocol with advanced NAT traversal for P2P networks
#![allow(elided_lifetimes_in_paths)]
#![allow(missing_debug_implementations)]
#![allow(clippy::manual_is_multiple_of)]
//!
//! This library provides a clean, modular implementation of QUIC-native NAT traversal
//! using raw public keys for authentication. It is designed to be minimal, focused,
//! and highly testable, with exceptional cross-platform support.
//!
//! The library is organized into the following main modules:
//! - `transport`: Core QUIC transport functionality
//! - `nat_traversal`: QUIC-native NAT traversal protocol
//! - `discovery`: Platform-specific network interface discovery
//! - `crypto`: Raw public key authentication
//! - `trust`: Trust management with TOFU pinning and channel binding

// Documentation warnings enabled - all public APIs must be documented
#![cfg_attr(not(fuzzing), warn(missing_docs))]
#![allow(unreachable_pub)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::use_self)]
// Dead code warnings enabled - remove unused code
#![warn(dead_code)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::module_inception)]
#![allow(clippy::useless_vec)]
#![allow(private_interfaces)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::manual_strip)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::incompatible_msrv)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::single_match)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::let_underscore_must_use)]
#![allow(clippy::let_underscore_untyped)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::result_large_err)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::new_without_default)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::needless_bool)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::match_ref_pats)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::wildcard_imports)]
#![warn(unused_must_use)]
#![allow(improper_ctypes)]
#![allow(improper_ctypes_definitions)]
#![allow(non_upper_case_globals)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::from_over_into)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::never_loop)]
#![allow(dropping_references)]
#![allow(non_snake_case)]
#![allow(clippy::unnecessary_literal_unwrap)]
#![allow(clippy::assertions_on_constants)]

#[cfg(feature = "native")]
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops,
};

// Core modules
#[cfg(feature = "native")]
mod cid_queue;
#[cfg(feature = "native")]
pub mod coding;
#[cfg(feature = "native")]
mod constant_time;
#[cfg(feature = "native")]
mod range_set;
#[cfg(feature = "native")]
pub mod transport_parameters;
#[cfg(feature = "native")]
mod varint;

#[cfg(feature = "native")]
pub use varint::{VarInt, VarIntBoundsExceeded};

// Removed optional bloom module

/// Bounded pending data buffer with TTL expiration
#[cfg(feature = "native")]
pub mod bounded_pending_buffer;

/// RTT-based path selection with hysteresis
#[cfg(feature = "native")]
pub mod path_selection;

/// Coordinated shutdown for endpoints
#[cfg(feature = "native")]
pub mod shutdown;

/// Watchable state pattern for reactive observation
#[cfg(feature = "native")]
pub mod watchable;

/// Fair polling for multiple transports
#[cfg(feature = "native")]
pub mod fair_polling;

/// Graceful transport degradation
#[cfg(feature = "native")]
pub mod transport_resilience;

/// Connection strategy state machine for progressive NAT traversal fallback
#[cfg(feature = "native")]
pub mod connection_strategy;

/// RFC 8305 Happy Eyeballs v2 for parallel IPv4/IPv6 connection racing
#[cfg(feature = "native")]
pub mod happy_eyeballs;

/// Discovery trait for stream composition
#[cfg(feature = "native")]
pub mod discovery_trait;

/// Structured event logging for observability
#[cfg(feature = "native")]
pub mod structured_events;

// ============================================================================
// SIMPLE API - Zero Configuration P2P
// ============================================================================

/// Zero-configuration P2P node - THE PRIMARY API
///
/// Use [`Node`] for the simplest possible P2P experience:
/// ```rust,ignore
/// let node = Node::new().await?;
/// ```
#[cfg(feature = "native")]
pub mod node;

/// Minimal configuration for zero-config P2P nodes
#[cfg(feature = "native")]
pub mod node_config;

/// Consolidated node status for observability
#[cfg(feature = "native")]
pub mod node_status;

/// Unified events for P2P nodes
#[cfg(feature = "native")]
pub mod node_event;

// Core implementation modules
/// Configuration structures and validation
#[cfg(feature = "native")]
pub mod config;
/// QUIC connection state machine and management
#[cfg(feature = "native")]
pub mod connection;
/// QUIC endpoint for accepting and initiating connections
#[cfg(feature = "native")]
pub mod endpoint;
/// QUIC frame types and encoding/decoding
#[cfg(feature = "native")]
pub mod frame;
/// QUIC packet structures and processing
#[cfg(feature = "native")]
pub mod packet;
/// Shared types and utilities
#[cfg(feature = "native")]
pub mod shared;
/// Transport error types and codes
#[cfg(feature = "native")]
pub mod transport_error;
// Simplified congestion control
/// Network candidate discovery and management
#[cfg(feature = "native")]
pub mod candidate_discovery;
/// Connection ID generation strategies
#[cfg(feature = "native")]
pub mod cid_generator;
#[cfg(feature = "native")]
mod congestion;

// Zero-cost tracing system
/// High-level NAT traversal API
#[cfg(feature = "native")]
pub mod nat_traversal_api;
#[cfg(feature = "native")]
mod token;
#[cfg(feature = "native")]
mod token_memory_cache;
/// Zero-cost tracing and event logging system
#[cfg(feature = "native")]
pub mod tracing;
/// Best-effort UPnP IGD port mapping for NAT traversal assistance.
///
/// This module is feature-gated behind `upnp` (enabled by default). When
/// disabled, [`UpnpMappingService`] is still present but is a no-op stub
/// that always reports [`UpnpState::Unavailable`].
#[cfg(feature = "native")]
pub mod upnp;

// Public modules with new structure
/// Constrained protocol engine for low-bandwidth transports (BLE, LoRa)
#[cfg(feature = "native")]
pub mod constrained;
/// Cryptographic operations and raw public key support
#[cfg(feature = "native")]
pub mod crypto;
/// Platform-specific network interface discovery
#[cfg(feature = "native")]
pub mod discovery;
/// NAT traversal protocol implementation
#[cfg(feature = "native")]
pub mod nat_traversal;
/// Transport-level protocol implementation
pub mod transport;

/// Signaling-free WebRTC DataChannel transport for direct browser clients.
#[cfg(feature = "webrtc-direct")]
#[cfg(feature = "native")]
pub use webrtc::direct as webrtc_direct;

/// Portable WebRTC profile, framing, and post-quantum sessions.
#[cfg(feature = "webrtc")]
pub mod webrtc;

/// Connection router for automatic protocol engine selection (QUIC vs Constrained)
#[cfg(feature = "native")]
pub mod connection_router;

// Additional modules
// v0.2: auth module removed - TLS handles peer authentication via ML-DSA-65
/// Secure chat protocol implementation
#[cfg(feature = "native")]
pub mod chat;

// ============================================================================
// P2P API
// ============================================================================

/// P2P endpoint - the primary API for saorsa-transport
///
/// This module provides the main API for P2P networking with NAT traversal,
/// connection management, and secure communication.
#[cfg(feature = "native")]
pub mod p2p_endpoint;

/// P2P configuration system
///
/// This module provides `P2pConfig` with builder pattern support for
/// configuring endpoints, NAT traversal, MTU, PQC, and other settings.
#[cfg(feature = "native")]
pub mod unified_config;

/// Real-time statistics dashboard
#[cfg(feature = "native")]
pub mod stats_dashboard;
/// Terminal user interface components
#[cfg(feature = "native")]
pub mod terminal_ui;

// Compliance validation framework
/// IETF compliance validation tools
#[cfg(feature = "native")]
pub mod compliance_validator;

// Comprehensive logging system
/// Structured logging and diagnostics
#[cfg(feature = "native")]
pub mod logging;

/// Metrics collection and export system (basic metrics always available)
#[cfg(feature = "native")]
pub mod metrics;

/// TURN-style relay protocol for NAT traversal fallback
#[cfg(feature = "native")]
pub mod relay;

/// MASQUE CONNECT-UDP Bind protocol for fully connectable P2P nodes
#[cfg(feature = "native")]
pub mod masque;

/// Transport trust module (TOFU, rotations, channel binding surfaces)
#[cfg(feature = "native")]
pub mod trust;

/// Address-validation tokens bound to (PeerId||CID||nonce)
#[cfg(feature = "native")]
pub mod token_v2;

// High-level async API modules (ported from quinn crate)
#[cfg(feature = "native")]
pub mod high_level;

// Re-export high-level API types for easier usage
#[cfg(feature = "native")]
pub use high_level::{
    Accept, Connecting, Connection as HighLevelConnection, Endpoint,
    RecvStream as HighLevelRecvStream, SendStream as HighLevelSendStream,
};

// Link transport abstraction layer for overlay networks
#[cfg(feature = "native")]
pub mod link_transport;
#[cfg(feature = "native")]
mod link_transport_impl;

// Re-export link transport types
#[cfg(feature = "native")]
pub use link_transport::{
    BoxFuture, BoxStream, BoxedHandler, Capabilities, ConnectionStats as LinkConnectionStats,
    DisconnectReason as LinkDisconnectReason, Incoming as LinkIncoming, LinkConn, LinkError,
    LinkEvent, LinkRecvStream, LinkResult, LinkSendStream, LinkTransport, NatHint, ProtocolHandler,
    ProtocolHandlerExt, ProtocolId, StreamFilter, StreamType, StreamTypeFamily,
};
#[cfg(feature = "native")]
pub use link_transport_impl::{
    P2pLinkConn, P2pLinkTransport, P2pRecvStream, P2pSendStream, SharedTransport,
};

// Host identity for local-only HostKey management (ADR-007)
#[cfg(feature = "native")]
pub mod host_identity;
#[cfg(feature = "native")]
pub use host_identity::{EndpointKeyPolicy, HostIdentity, HostKeyStorage, StorageError};

// Re-export crypto utilities (v0.2: Pure PQC with ML-DSA-65)
#[cfg(feature = "native")]
pub use crypto::raw_public_keys::key_utils::{
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SECRET_KEY_SIZE, MlDsaPublicKey, MlDsaSecretKey,
    fingerprint_public_key, fingerprint_public_key_bytes, generate_ml_dsa_keypair,
};

// Re-export key types for backward compatibility
#[cfg(feature = "native")]
pub use candidate_discovery::{
    CandidateDiscoveryManager, DiscoveryConfig, DiscoveryError, DiscoveryEvent, NetworkInterface,
    ValidatedCandidate,
};
// v0.13.0: NatTraversalRole removed - all nodes are symmetric P2P nodes
#[cfg(feature = "native")]
pub use connection::nat_traversal::{CandidateSource, CandidateState};
#[cfg(feature = "native")]
pub use connection::{
    Chunk, Chunks, ClosedStream, Connection, ConnectionError, ConnectionStats, DatagramDropStats,
    Datagrams, Event, FinishError, ReadError, ReadableError, RecvStream, SendDatagramError,
    SendStream, StreamEvent, Streams, WriteError, Written,
};
#[cfg(feature = "native")]
pub use endpoint::{
    AcceptError, ConnectError, ConnectionHandle, DatagramEvent, Endpoint as LowLevelEndpoint,
    Incoming,
};
#[cfg(feature = "native")]
pub use nat_traversal_api::{
    BootstrapNode, CandidateAddress, NatTraversalConfig, NatTraversalEndpoint, NatTraversalError,
    NatTraversalEvent, NatTraversalStatistics,
};

// ============================================================================
// SIMPLE API EXPORTS - Zero Configuration P2P (RECOMMENDED)
// ============================================================================

/// Zero-configuration P2P node - THE PRIMARY API
#[cfg(feature = "native")]
pub use node::{Node, NodeError};

/// Minimal configuration for zero-config P2P nodes
#[cfg(feature = "native")]
pub use node_config::{NodeConfig, NodeConfigBuilder};

/// Consolidated node status for observability
#[cfg(feature = "native")]
pub use node_status::{NatType, NodeStatus};

/// Unified events for P2P nodes
#[cfg(feature = "native")]
pub use node_event::{DisconnectReason as NodeDisconnectReason, NodeEvent, TraversalMethod};

// ============================================================================
// P2P API EXPORTS (for advanced use)
// ============================================================================

/// P2P endpoint - for advanced use, prefer Node for most applications
#[cfg(feature = "native")]
pub use p2p_endpoint::{
    ConnectionMetrics, DisconnectReason, EndpointError, EndpointStats, P2pEndpoint, P2pEvent,
    PeerConnection, SendFailureStage, TraversalPhase,
};

/// P2P configuration with builder pattern
#[cfg(feature = "native")]
pub use unified_config::{ConfigError, MtuConfig, NatConfig, P2pConfig, P2pConfigBuilder};

/// Connection strategy for progressive NAT traversal fallback
#[cfg(feature = "native")]
pub use connection_strategy::{
    AttemptedMethod, ConnectionAttemptError, ConnectionMethod, ConnectionStage, ConnectionStrategy,
    StrategyConfig,
};

#[cfg(feature = "native")]
pub use relay::{
    AuthToken,
    // MASQUE types re-exported from relay module
    MasqueRelayClient,
    MasqueRelayConfig,
    MasqueRelayServer,
    MasqueRelayStats,
    RelayAuthenticator,
    RelayError,
    RelayManager,
    RelayManagerConfig,
    RelayResult,
    RelaySession,
    RelaySessionConfig,
    RelaySessionState,
    RelayStatisticsCollector,
};
#[cfg(feature = "native")]
pub use shared::{ConnectionId, EcnCodepoint, EndpointEvent};
#[cfg(feature = "native")]
pub use transport_error::{Code as TransportErrorCode, Error as TransportError};

// Re-export transport abstraction types
#[cfg(feature = "native")]
pub use transport::{
    BandwidthClass, InboundDatagram, LinkQuality, LoRaParams, ProtocolEngine, ProviderError,
    TransportAddr, TransportCapabilities, TransportCapabilitiesBuilder, TransportDiagnostics,
    TransportProvider, TransportRegistry, TransportStats, TransportType, UdpTransport,
};

#[cfg(feature = "ble")]
#[cfg(feature = "native")]
pub use transport::BleTransport;

// Re-export connection router types for automatic protocol engine selection
#[cfg(feature = "native")]
pub use connection_router::{
    ConnectionRouter, RoutedConnection, RouterConfig, RouterError, RouterStats,
};

// #[cfg(fuzzing)]
// pub mod fuzzing; // Module not implemented yet

/// The QUIC protocol version implemented.
///
/// Simplified to include only the essential versions:
/// - 0x00000001: QUIC v1 (RFC 9000)
/// - 0xff00_001d: Draft 29
#[cfg(feature = "native")]
pub const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[
    0x00000001,  // QUIC v1 (RFC 9000)
    0xff00_001d, // Draft 29
];

/// Whether an endpoint was the initiator of a connection
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg(feature = "native")]
pub enum Side {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

#[cfg(feature = "native")]
impl Side {
    #[inline]
    /// Shorthand for `self == Side::Client`
    pub fn is_client(self) -> bool {
        self == Self::Client
    }

    #[inline]
    /// Shorthand for `self == Side::Server`
    pub fn is_server(self) -> bool {
        self == Self::Server
    }
}

#[cfg(feature = "native")]
impl ops::Not for Side {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Whether a stream communicates data in both directions or only from the initiator
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg(feature = "native")]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

#[cfg(feature = "native")]
impl Dir {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::Bi, Self::Uni].iter().cloned()
    }
}

#[cfg(feature = "native")]
impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Dir::*;
        f.pad(match *self {
            Bi => "bidirectional",
            Uni => "unidirectional",
        })
    }
}

/// Identifier for a stream within a particular connection
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg(feature = "native")]
pub struct StreamId(u64);

#[cfg(feature = "native")]
impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = match self.initiator() {
            Side::Client => "client",
            Side::Server => "server",
        };
        let dir = match self.dir() {
            Dir::Uni => "uni",
            Dir::Bi => "bi",
        };
        write!(
            f,
            "{} {}directional stream {}",
            initiator,
            dir,
            self.index()
        )
    }
}

#[cfg(feature = "native")]
impl StreamId {
    /// Create a new StreamId
    pub fn new(initiator: Side, dir: Dir, index: u64) -> Self {
        Self((index << 2) | ((dir as u64) << 1) | initiator as u64)
    }
    /// Which side of a connection initiated the stream
    pub fn initiator(self) -> Side {
        if self.0 & 0x1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }
    /// Which directions data flows in
    pub fn dir(self) -> Dir {
        if self.0 & 0x2 == 0 { Dir::Bi } else { Dir::Uni }
    }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

#[cfg(feature = "native")]
impl From<StreamId> for VarInt {
    fn from(x: StreamId) -> Self {
        unsafe { Self::from_u64_unchecked(x.0) }
    }
}

#[cfg(feature = "native")]
impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
    }
}

#[cfg(feature = "native")]
impl From<StreamId> for u64 {
    fn from(x: StreamId) -> Self {
        x.0
    }
}

#[cfg(feature = "native")]
impl coding::Codec for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<Self> {
        VarInt::decode(buf).map(|x| Self(x.into_inner()))
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        // StreamId values should always be valid VarInt values, but handle the error case
        match VarInt::from_u64(self.0) {
            Ok(varint) => varint.encode(buf),
            Err(_) => {
                // This should never happen for valid StreamIds, but use a safe fallback
                VarInt::MAX.encode(buf);
            }
        }
    }
}

/// An outgoing packet
#[derive(Debug)]
#[must_use]
#[cfg(feature = "native")]
pub struct Transmit {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Amount of data written to the caller-supplied buffer
    pub size: usize,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

// Deal with time
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[cfg(feature = "native")]
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[cfg(feature = "native")]
pub(crate) use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

//
// Useful internal constants
//

/// Maximum time to wait for QUIC connections and tasks to drain during shutdown.
///
/// Used by both `P2pEndpoint` and `NatTraversalEndpoint` to bound graceful-shutdown waits.
#[cfg(feature = "native")]
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum number of CIDs we bother to issue per connection
#[cfg(feature = "native")]
pub(crate) const LOC_CID_COUNT: u64 = 8;
#[cfg(feature = "native")]
pub(crate) const RESET_TOKEN_SIZE: usize = 16;
#[cfg(feature = "native")]
pub(crate) const MAX_CID_SIZE: usize = 20;
#[cfg(feature = "native")]
pub(crate) const MIN_INITIAL_SIZE: u16 = 1200;
/// <https://www.rfc-editor.org/rfc/rfc9000.html#name-datagram-size>
#[cfg(feature = "native")]
pub(crate) const INITIAL_MTU: u16 = 1200;
#[cfg(feature = "native")]
pub(crate) const MAX_UDP_PAYLOAD: u16 = 65527;
#[cfg(feature = "native")]
pub(crate) const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be tracked per connection
#[cfg(feature = "native")]
pub(crate) const MAX_STREAM_COUNT: u64 = 1 << 60;

// Internal type re-exports for crate modules
#[cfg(feature = "native")]
pub use cid_generator::RandomConnectionIdGenerator;
#[cfg(feature = "native")]
pub use config::{
    AckFrequencyConfig, ClientConfig, EndpointConfig, MtuDiscoveryConfig, ServerConfig,
    TransportConfig,
};

// Post-Quantum Cryptography (PQC) re-exports - always available
// v0.2: Pure PQC only - HybridKem and HybridSignature removed
#[cfg(feature = "native")]
pub use crypto::pqc::{MlDsa65, MlKem768, PqcConfig, PqcConfigBuilder, PqcError, PqcResult};
#[cfg(feature = "native")]
pub(crate) use frame::Frame;
#[cfg(feature = "native")]
pub use token::TokenStore;
#[cfg(feature = "native")]
pub(crate) use token::{NoneTokenLog, ResetToken, TokenLog};
#[cfg(feature = "native")]
pub(crate) use token_memory_cache::TokenMemoryCache;
