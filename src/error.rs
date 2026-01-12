// Copyright (c) 2026 Saorsa Labs Limited
//
// Licensed under the GPL-3.0 license

//! Error types for saorsa-transport.

use crate::StreamType;
use thiserror::Error;

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Errors that can occur in transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Invalid stream type byte received.
    #[error("invalid stream type byte: 0x{0:02x}")]
    InvalidStreamType(u8),

    /// Unknown stream type for this handler.
    #[error("unknown stream type: {0:?}")]
    UnknownStreamType(StreamType),

    /// No handler registered for stream type.
    #[error("no handler registered for stream type: {0:?}")]
    NoHandler(StreamType),

    /// Handler already registered for stream type.
    #[error("handler already registered for stream type: {0:?}")]
    HandlerExists(StreamType),

    /// Connection to peer failed.
    #[error("connection to peer {peer_id} failed: {reason}")]
    ConnectionFailed { peer_id: String, reason: String },

    /// Stream operation failed.
    #[error("stream operation failed: {0}")]
    StreamError(String),

    /// Transport not running.
    #[error("transport not running")]
    NotRunning,

    /// Transport already running.
    #[error("transport already running")]
    AlreadyRunning,

    /// Peer not connected.
    #[error("peer not connected: {0}")]
    PeerNotConnected(String),

    /// Send failed.
    #[error("send to peer {peer_id} failed: {reason}")]
    SendFailed { peer_id: String, reason: String },

    /// Receive failed.
    #[error("receive failed: {0}")]
    ReceiveFailed(String),

    /// Timeout waiting for operation.
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Transport shutdown.
    #[error("transport is shutting down")]
    Shutdown,

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying QUIC transport error.
    #[error("QUIC transport error: {0}")]
    QuicError(String),

    /// Link transport error from ant-quic.
    #[error("link transport error: {0}")]
    LinkError(String),

    /// Transport not initialized.
    #[error("transport not initialized - call new_with_transport()")]
    NotInitialized,

    /// Accept stream error.
    #[error("failed to accept stream: {0}")]
    AcceptError(String),
}

impl TransportError {
    /// Create a connection failed error.
    pub fn connection_failed(peer_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            peer_id: peer_id.into(),
            reason: reason.into(),
        }
    }

    /// Create a send failed error.
    pub fn send_failed(peer_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SendFailed {
            peer_id: peer_id.into(),
            reason: reason.into(),
        }
    }
}

impl From<ant_quic::link_transport::LinkError> for TransportError {
    fn from(err: ant_quic::link_transport::LinkError) -> Self {
        use ant_quic::link_transport::LinkError;
        match err {
            LinkError::Io(msg) => Self::Io(std::io::Error::other(msg)),
            LinkError::ConnectionFailed(msg) => Self::ConnectionFailed {
                peer_id: "unknown".to_string(),
                reason: msg,
            },
            LinkError::ConnectionClosed => Self::StreamError("connection closed".to_string()),
            LinkError::PeerNotFound(peer) => Self::PeerNotConnected(peer),
            LinkError::Timeout => Self::Timeout(std::time::Duration::from_secs(30)),
            LinkError::InvalidStreamType(byte) => Self::InvalidStreamType(byte),
            LinkError::StreamTypeFiltered(st) => Self::UnknownStreamType(st),
            LinkError::ProtocolNotSupported(proto) => {
                Self::StreamError(format!("protocol not supported: {}", proto))
            }
            LinkError::StreamReset(code) => Self::StreamError(format!("stream reset: {}", code)),
            LinkError::Shutdown => Self::Shutdown,
            LinkError::RateLimited => Self::StreamError("rate limited".to_string()),
            LinkError::Internal(msg) => Self::LinkError(msg),
        }
    }
}
