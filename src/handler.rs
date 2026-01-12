// Copyright (c) 2026 Saorsa Labs Limited
//
// Licensed under the GPL-3.0 license

//! Protocol handler trait for stream processing.

use crate::{StreamType, TransportResult};
use ant_quic::PeerId;
use async_trait::async_trait;
use bytes::Bytes;

/// Handler for a specific protocol stream type.
///
/// Implement this trait to handle incoming streams for your protocol.
/// Each handler is registered with the [`SharedTransport`] and will
/// receive streams matching its declared stream type.
///
/// # Example
///
/// ```rust,ignore
/// use saorsa_transport::{ProtocolHandler, StreamType, TransportResult};
/// use async_trait::async_trait;
///
/// struct GossipHandler;
///
/// #[async_trait]
/// impl ProtocolHandler for GossipHandler {
///     fn stream_types(&self) -> &[StreamType] {
///         &[StreamType::Membership, StreamType::PubSub, StreamType::GossipBulk]
///     }
///
///     async fn handle_stream(
///         &self,
///         peer: PeerId,
///         stream_type: StreamType,
///         data: Bytes,
///     ) -> TransportResult<Option<Bytes>> {
///         // Process the incoming data
///         match stream_type {
///             StreamType::Membership => self.handle_membership(peer, data).await,
///             StreamType::PubSub => self.handle_pubsub(peer, data).await,
///             _ => Ok(None),
///         }
///     }
/// }
/// ```
///
/// [`SharedTransport`]: crate::SharedTransport
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Get the stream types this handler processes.
    fn stream_types(&self) -> &[StreamType];

    /// Handle an incoming stream.
    async fn handle_stream(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> TransportResult<Option<Bytes>>;

    /// Handle an incoming datagram.
    async fn handle_datagram(
        &self,
        _peer: PeerId,
        _stream_type: StreamType,
        _data: Bytes,
    ) -> TransportResult<()> {
        Ok(())
    }

    /// Called when the handler is being shut down.
    async fn shutdown(&self) -> TransportResult<()> {
        Ok(())
    }

    /// Get a human-readable name for this handler.
    fn name(&self) -> &str {
        "ProtocolHandler"
    }
}

/// A boxed protocol handler for dynamic dispatch.
pub type BoxedHandler = Box<dyn ProtocolHandler>;

/// Extension trait for creating boxed handlers.
pub trait ProtocolHandlerExt: ProtocolHandler + Sized + 'static {
    /// Box this handler for use with SharedTransport.
    fn boxed(self) -> BoxedHandler {
        Box::new(self)
    }
}

impl<T: ProtocolHandler + 'static> ProtocolHandlerExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestHandler {
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProtocolHandler for TestHandler {
        fn stream_types(&self) -> &[StreamType] {
            &[StreamType::Membership]
        }

        async fn handle_stream(
            &self,
            _peer: PeerId,
            _stream_type: StreamType,
            _data: Bytes,
        ) -> TransportResult<Option<Bytes>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Bytes::from_static(b"response")))
        }

        fn name(&self) -> &str {
            "TestHandler"
        }
    }

    #[tokio::test]
    async fn test_handler_basic() {
        let count = Arc::new(AtomicUsize::new(0));
        let handler = TestHandler {
            call_count: count.clone(),
        };

        assert_eq!(handler.stream_types(), &[StreamType::Membership]);
        assert_eq!(handler.name(), "TestHandler");

        let peer = PeerId::from([0u8; 32]);
        let result = handler
            .handle_stream(peer, StreamType::Membership, Bytes::from_static(b"test"))
            .await;

        assert!(result.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
