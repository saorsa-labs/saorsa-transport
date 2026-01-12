// Copyright (c) 2026 Saorsa Labs Limited
//
// Licensed under the GPL-3.0 license

//! Shared transport implementation.
//!
//! Routes streams to registered protocol handlers based on the first byte.

use crate::handler::BoxedHandler;
use crate::{StreamFilter, StreamType, TransportError, TransportResult};
use ant_quic::PeerId;
use ant_quic::link_transport::{LinkConn, LinkRecvStream, LinkSendStream, LinkTransport};
use bytes::Bytes;
use futures::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, trace, warn};

/// Shared transport that multiplexes protocols over a single connection per peer.
pub struct SharedTransport<T: LinkTransport> {
    /// The underlying link transport.
    transport: Arc<T>,

    /// Registered protocol handlers, keyed by stream type.
    handlers: Arc<RwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,

    /// Connected peers with their connections.
    connections: Arc<RwLock<HashMap<PeerId, Arc<T::Conn>>>>,

    /// Peer state tracking.
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,

    /// Transport state.
    state: RwLock<TransportState>,

    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,
}

/// State of a connected peer.
#[derive(Debug)]
struct PeerState {
    /// Remote address.
    remote_addr: Option<SocketAddr>,

    /// When the peer connected.
    #[allow(dead_code)] // Will be used for connection age metrics
    connected_at: std::time::Instant,

    /// Messages sent to this peer.
    messages_sent: u64,

    /// Messages received from this peer.
    messages_received: u64,

    /// Last activity timestamp.
    last_activity: std::time::Instant,
}

impl PeerState {
    fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            remote_addr: None,
            connected_at: now,
            messages_sent: 0,
            messages_received: 0,
            last_activity: now,
        }
    }

    fn with_addr(addr: SocketAddr) -> Self {
        let mut state = Self::new();
        state.remote_addr = Some(addr);
        state
    }
}

/// Transport runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportState {
    Created,
    Running,
    ShuttingDown,
    Stopped,
}

impl<T: LinkTransport> SharedTransport<T>
where
    T::Conn: Send + Sync + 'static,
{
    /// Create a new shared transport with the given link transport.
    pub fn new_with_transport(transport: T) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            transport: Arc::new(transport),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            state: RwLock::new(TransportState::Created),
            shutdown_tx,
        }
    }

    /// Create a new shared transport from an existing Arc-wrapped transport.
    ///
    /// Use this when you already have an Arc<T> and want to avoid double-wrapping.
    pub fn from_arc_transport(transport: Arc<T>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            transport,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            state: RwLock::new(TransportState::Created),
            shutdown_tx,
        }
    }

    /// Get the local peer ID.
    pub fn local_peer(&self) -> PeerId {
        self.transport.local_peer()
    }

    /// Get the underlying transport.
    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    /// Register a protocol handler.
    pub async fn register_handler(&self, handler: BoxedHandler) -> TransportResult<()> {
        let mut handlers = self.handlers.write().await;
        let handler = Arc::new(handler);

        for &stream_type in handler.stream_types() {
            if handlers.contains_key(&stream_type) {
                return Err(TransportError::HandlerExists(stream_type));
            }
        }

        let name = handler.name();
        for &stream_type in handler.stream_types() {
            info!(
                handler = %name,
                stream_type = %stream_type,
                "Registered protocol handler"
            );
            handlers.insert(stream_type, Arc::clone(&handler));
        }

        Ok(())
    }
    #[allow(clippy::collapsible_if)]
    /// Unregister a handler by its stream types.
    pub async fn unregister_handler(&self, stream_types: &[StreamType]) -> TransportResult<()> {
        let mut handlers = self.handlers.write().await;

        for &stream_type in stream_types {
            if let Some(handler) = handlers.remove(&stream_type) {
                if Arc::strong_count(&handler) == 1 {
                    if let Err(e) = handler.shutdown().await {
                        warn!(stream_type = %stream_type, error = %e, "Handler shutdown error");
                    }
                }
                debug!(stream_type = %stream_type, "Unregistered handler");
            }
        }

        Ok(())
    }

    /// Get the handler for a stream type.
    pub async fn get_handler(&self, stream_type: StreamType) -> Option<Arc<BoxedHandler>> {
        self.handlers.read().await.get(&stream_type).cloned()
    }

    /// Check if a handler is registered for a stream type.
    pub async fn has_handler(&self, stream_type: StreamType) -> bool {
        self.handlers.read().await.contains_key(&stream_type)
    }

    /// Get all registered stream types.
    pub async fn registered_types(&self) -> Vec<StreamType> {
        self.handlers.read().await.keys().copied().collect()
    }

    /// Build a stream filter from registered handlers.
    async fn build_stream_filter(&self) -> StreamFilter {
        let handlers = self.handlers.read().await;
        let mut filter = StreamFilter::new();
        for stream_type in handlers.keys() {
            filter = filter.with_type(*stream_type);
        }
        filter
    }

    /// Connect to a peer by address.
    pub async fn connect(&self, addr: SocketAddr) -> TransportResult<PeerId> {
        let proto = ant_quic::link_transport::ProtocolId::DEFAULT;
        let conn = self.transport.dial_addr(addr, proto).await?;
        let peer_id = conn.peer();
        let remote_addr = conn.remote_addr();

        {
            let mut connections = self.connections.write().await;
            connections.insert(peer_id, Arc::new(conn));
        }

        {
            let mut peers = self.peers.write().await;
            peers.insert(peer_id, PeerState::with_addr(remote_addr));
        }

        info!(peer = ?peer_id, addr = %remote_addr, "Connected to peer");
        Ok(peer_id)
    }
    #[allow(clippy::collapsible_if)]
    /// Get connection to a peer, connecting if necessary.
    async fn get_or_connect(&self, peer: PeerId) -> TransportResult<Arc<T::Conn>> {
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_open() {
                    return Ok(Arc::clone(conn));
                }
            }
        }

        let proto = ant_quic::link_transport::ProtocolId::DEFAULT;
        let conn = self.transport.dial(peer, proto).await?;
        let remote_addr = conn.remote_addr();
        let conn = Arc::new(conn);

        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, Arc::clone(&conn));
        }

        {
            let mut peers = self.peers.write().await;
            peers
                .entry(peer)
                .or_insert_with(|| PeerState::with_addr(remote_addr));
        }

        Ok(conn)
    }

    /// Send data to a peer on a specific stream type.
    pub async fn send(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> TransportResult<Option<Bytes>> {
        let state = *self.state.read().await;
        if state != TransportState::Running {
            return Err(TransportError::NotRunning);
        }

        let conn = self.get_or_connect(peer).await?;

        {
            let mut peers = self.peers.write().await;
            if let Some(peer_state) = peers.get_mut(&peer) {
                peer_state.messages_sent += 1;
                peer_state.last_activity = std::time::Instant::now();
            }
        }

        trace!(
            peer = ?peer,
            stream_type = %stream_type,
            size = data.len(),
            "Sending message"
        );

        let (mut send, mut recv) = conn.open_bi_typed(stream_type).await?;
        send.write_all(&data).await?;
        let _ = send.finish();

        let response = recv.read_to_end(1024 * 1024).await?;

        if response.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::from(response)))
        }
    }

    /// Send data to a peer on a unidirectional stream.
    pub async fn send_uni(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> TransportResult<()> {
        let state = *self.state.read().await;
        if state != TransportState::Running {
            return Err(TransportError::NotRunning);
        }

        let conn = self.get_or_connect(peer).await?;

        {
            let mut peers = self.peers.write().await;
            if let Some(peer_state) = peers.get_mut(&peer) {
                peer_state.messages_sent += 1;
                peer_state.last_activity = std::time::Instant::now();
            }
        }

        trace!(
            peer = ?peer,
            stream_type = %stream_type,
            size = data.len(),
            "Sending unidirectional message"
        );

        let mut send = conn.open_uni_typed(stream_type).await?;
        send.write_all(&data).await?;
        let _ = send.finish();

        Ok(())
    }

    /// Process an incoming bidirectional stream.
    async fn handle_bi_stream(
        handlers: Arc<RwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,
        peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
        peer: PeerId,
        stream_type: StreamType,
        mut send: Box<dyn LinkSendStream>,
        mut recv: Box<dyn LinkRecvStream>,
    ) {
        {
            let mut peers_guard = peers.write().await;
            if let Some(state) = peers_guard.get_mut(&peer) {
                state.messages_received += 1;
                state.last_activity = std::time::Instant::now();
            }
        }

        let data = match recv.read_to_end(1024 * 1024).await {
            Ok(data) => Bytes::from(data),
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to read stream");
                return;
            }
        };

        let handler = {
            let handlers_guard = handlers.read().await;
            handlers_guard.get(&stream_type).cloned()
        };

        let handler = match handler {
            Some(h) => h,
            None => {
                warn!(peer = ?peer, stream_type = %stream_type, "No handler for stream type");
                return;
            }
        };

        trace!(
            peer = ?peer,
            stream_type = %stream_type,
            size = data.len(),
            handler = %handler.name(),
            "Dispatching to handler"
        );

        match handler.handle_stream(peer, stream_type, data).await {
            Ok(Some(response)) => {
                if let Err(e) = send.write_all(&response).await {
                    warn!(peer = ?peer, error = %e, "Failed to send response");
                }
                let _ = send.finish();
            }
            Ok(None) => {
                let _ = send.finish();
            }
            Err(e) => {
                error!(peer = ?peer, error = %e, "Handler error");
                let _ = send.finish();
            }
        }
    }

    /// Run the accept loop for a single connection.
    async fn run_connection_accept(
        conn: Arc<T::Conn>,
        handlers: Arc<RwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,
        peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
        filter: StreamFilter,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let peer = conn.peer();
        let mut stream = conn.accept_bi_typed(filter);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!(peer = ?peer, "Connection accept loop shutting down");
                    break;
                }
                result = stream.next() => {
                    match result {
                        Some(Ok((stream_type, send, recv))) => {
                            let handlers_clone = Arc::clone(&handlers);
                            let peers_clone = Arc::clone(&peers);
                            tokio::spawn(async move {
                                Self::handle_bi_stream(
                                    handlers_clone,
                                    peers_clone,
                                    peer,
                                    stream_type,
                                    send,
                                    recv,
                                ).await;
                            });
                        }
                        Some(Err(e)) => {
                            warn!(peer = ?peer, error = %e, "Error accepting stream");
                        }
                        None => {
                            debug!(peer = ?peer, "Connection closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Add a connected peer with its connection.
    pub async fn add_connection(&self, peer: PeerId, conn: T::Conn) {
        let remote_addr = conn.remote_addr();
        let conn = Arc::new(conn);

        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, Arc::clone(&conn));
        }

        {
            let mut peers = self.peers.write().await;
            peers
                .entry(peer)
                .or_insert_with(|| PeerState::with_addr(remote_addr));
        }

        let filter = self.build_stream_filter().await;
        let handlers = Arc::clone(&self.handlers);
        let peers_arc = Arc::clone(&self.peers);
        let shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            Self::run_connection_accept(conn, handlers, peers_arc, filter, shutdown_rx).await;
        });

        debug!(peer = ?peer, "Peer connected");
    }

    /// Remove a disconnected peer.
    pub async fn remove_peer(&self, peer: &PeerId) {
        {
            let mut connections = self.connections.write().await;
            connections.remove(peer);
        }

        {
            let mut peers = self.peers.write().await;
            if peers.remove(peer).is_some() {
                debug!(peer = ?peer, "Peer disconnected");
            }
        }
    }

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get all connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Check if a peer is connected.
    pub async fn is_peer_connected(&self, peer: &PeerId) -> bool {
        let connections = self.connections.read().await;
        connections
            .get(peer)
            .map(|conn| conn.is_open())
            .unwrap_or(false)
    }

    /// Start the transport.
    pub async fn start(&self) -> TransportResult<()> {
        let mut state = self.state.write().await;
        match *state {
            TransportState::Created => {
                *state = TransportState::Running;
                info!("SharedTransport started");
                Ok(())
            }
            TransportState::Running => Err(TransportError::AlreadyRunning),
            _ => Err(TransportError::NotRunning),
        }
    }

    /// Run the transport, accepting incoming connections.
    pub async fn run(&self) -> TransportResult<()> {
        self.start().await?;

        let proto = ant_quic::link_transport::ProtocolId::DEFAULT;
        let mut incoming = self.transport.accept(proto);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("SharedTransport received shutdown signal");
                    break;
                }
                result = incoming.next() => {
                    match result {
                        Some(Ok(conn)) => {
                            let peer = conn.peer();
                            let remote_addr = conn.remote_addr();

                            info!(peer = ?peer, addr = %remote_addr, "Accepted connection");

                            let conn_arc = Arc::new(conn);
                            {
                                let mut connections = self.connections.write().await;
                                connections.insert(peer, Arc::clone(&conn_arc));
                            }

                            {
                                let mut peers = self.peers.write().await;
                                peers.insert(peer, PeerState::with_addr(remote_addr));
                            }

                            let filter = self.build_stream_filter().await;
                            let handlers = Arc::clone(&self.handlers);
                            let peers_arc = Arc::clone(&self.peers);
                            let conn_shutdown_rx = self.shutdown_tx.subscribe();

                            tokio::spawn(async move {
                                Self::run_connection_accept(
                                    conn_arc,
                                    handlers,
                                    peers_arc,
                                    filter,
                                    conn_shutdown_rx,
                                ).await;
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "Error accepting connection");
                        }
                        None => {
                            debug!("Incoming connection stream ended");
                            break;
                        }
                    }
                }
            }
        }

        self.stop().await
    }

    #[allow(clippy::collapsible_if)]
    /// Stop the transport gracefully.
    pub async fn stop(&self) -> TransportResult<()> {
        let mut state = self.state.write().await;
        if *state == TransportState::Stopped {
            return Ok(());
        }

        *state = TransportState::ShuttingDown;
        info!("SharedTransport shutting down");

        let _ = self.shutdown_tx.send(());

        {
            let handlers = self.handlers.read().await;
            let mut seen = std::collections::HashSet::new();

            for (stream_type, handler) in handlers.iter() {
                let ptr = Arc::as_ptr(handler) as usize;
                if seen.insert(ptr) {
                    if let Err(e) = handler.shutdown().await {
                        error!(
                            handler = %handler.name(),
                            stream_type = %stream_type,
                            error = %e,
                            "Handler shutdown error"
                        );
                    }
                }
            }
        }

        {
            let connections = self.connections.read().await;
            for (peer, conn) in connections.iter() {
                conn.close(0, "transport shutdown");
                debug!(peer = ?peer, "Closed connection");
            }
        }

        self.connections.write().await.clear();
        self.peers.write().await.clear();

        self.transport.shutdown().await;

        *state = TransportState::Stopped;
        info!("SharedTransport stopped");

        Ok(())
    }

    /// Check if the transport is running.
    pub async fn is_running(&self) -> bool {
        *self.state.read().await == TransportState::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{ProtocolHandler, ProtocolHandlerExt};
    use ant_quic::link_transport::{
        BoxFuture, BoxStream, Capabilities, ConnectionStats, Incoming, LinkError, LinkResult,
        ProtocolId,
    };
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockHandler {
        types: Vec<StreamType>,
        call_count: Arc<AtomicUsize>,
    }

    impl MockHandler {
        fn new(types: Vec<StreamType>) -> Self {
            Self {
                types,
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl ProtocolHandler for MockHandler {
        fn stream_types(&self) -> &[StreamType] {
            &self.types
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
            "MockHandler"
        }
    }

    // Mock connection
    struct MockConn {
        peer: PeerId,
        addr: SocketAddr,
    }

    impl LinkConn for MockConn {
        fn peer(&self) -> PeerId {
            self.peer
        }
        fn remote_addr(&self) -> SocketAddr {
            self.addr
        }
        fn open_uni(&self) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
            Box::pin(async { Err(LinkError::ConnectionClosed) })
        }
        fn open_bi(
            &self,
        ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>> {
            Box::pin(async { Err(LinkError::ConnectionClosed) })
        }
        fn send_datagram(&self, _data: Bytes) -> LinkResult<()> {
            Ok(())
        }
        fn recv_datagrams(&self) -> BoxStream<'_, Bytes> {
            Box::pin(futures::stream::empty())
        }
        fn close(&self, _code: u64, _reason: &str) {}
        fn is_open(&self) -> bool {
            true
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
        fn open_uni_typed(
            &self,
            _st: StreamType,
        ) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
            Box::pin(async { Err(LinkError::ConnectionClosed) })
        }
        fn open_bi_typed(
            &self,
            _st: StreamType,
        ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>> {
            Box::pin(async { Err(LinkError::ConnectionClosed) })
        }
        fn accept_uni_typed(
            &self,
            _filter: StreamFilter,
        ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkRecvStream>)>> {
            Box::pin(futures::stream::empty())
        }
        fn accept_bi_typed(
            &self,
            _filter: StreamFilter,
        ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>
        {
            Box::pin(futures::stream::empty())
        }
    }

    // Mock transport
    struct MockTransport {
        local: PeerId,
    }

    impl LinkTransport for MockTransport {
        type Conn = MockConn;
        fn local_peer(&self) -> PeerId {
            self.local
        }
        fn external_address(&self) -> Option<SocketAddr> {
            None
        }
        fn peer_table(&self) -> Vec<(PeerId, Capabilities)> {
            vec![]
        }
        fn peer_capabilities(&self, _peer: &PeerId) -> Option<Capabilities> {
            None
        }
        fn subscribe(&self) -> broadcast::Receiver<ant_quic::link_transport::LinkEvent> {
            let (tx, rx) = broadcast::channel(1);
            drop(tx);
            rx
        }
        fn accept(&self, _proto: ProtocolId) -> Incoming<Self::Conn> {
            Box::pin(futures::stream::empty())
        }
        fn dial(&self, _peer: PeerId, _proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>> {
            Box::pin(async { Err(LinkError::PeerNotFound("mock".into())) })
        }
        fn dial_addr(
            &self,
            addr: SocketAddr,
            _proto: ProtocolId,
        ) -> BoxFuture<'_, LinkResult<Self::Conn>> {
            let local = self.local;
            Box::pin(async move { Ok(MockConn { peer: local, addr }) })
        }
        fn supported_protocols(&self) -> Vec<ProtocolId> {
            vec![ProtocolId::DEFAULT]
        }
        fn register_protocol(&self, _proto: ProtocolId) {}
        fn unregister_protocol(&self, _proto: ProtocolId) {}
        fn is_connected(&self, _peer: &PeerId) -> bool {
            false
        }
        fn active_connections(&self) -> usize {
            0
        }
        fn shutdown(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn test_register_handler() {
        let transport = SharedTransport::new_with_transport(MockTransport {
            local: PeerId::from([1u8; 32]),
        });

        let handler = MockHandler::new(vec![StreamType::Membership, StreamType::PubSub]);
        transport.register_handler(handler.boxed()).await.unwrap();

        assert!(transport.has_handler(StreamType::Membership).await);
        assert!(transport.has_handler(StreamType::PubSub).await);
        assert!(!transport.has_handler(StreamType::DhtQuery).await);
    }

    #[tokio::test]
    async fn test_duplicate_handler_error() {
        let transport = SharedTransport::new_with_transport(MockTransport {
            local: PeerId::from([1u8; 32]),
        });

        let handler1 = MockHandler::new(vec![StreamType::Membership]);
        let handler2 = MockHandler::new(vec![StreamType::Membership]);

        transport.register_handler(handler1.boxed()).await.unwrap();

        let result = transport.register_handler(handler2.boxed()).await;
        assert!(matches!(result, Err(TransportError::HandlerExists(_))));
    }

    #[tokio::test]
    async fn test_transport_lifecycle() {
        let transport = SharedTransport::new_with_transport(MockTransport {
            local: PeerId::from([1u8; 32]),
        });

        assert!(!transport.is_running().await);

        transport.start().await.unwrap();
        assert!(transport.is_running().await);

        assert!(transport.start().await.is_err());

        transport.stop().await.unwrap();
        assert!(!transport.is_running().await);
    }

    #[tokio::test]
    async fn test_build_stream_filter() {
        let transport = SharedTransport::new_with_transport(MockTransport {
            local: PeerId::from([1u8; 32]),
        });

        let handler1 = MockHandler::new(vec![StreamType::Membership, StreamType::PubSub]);
        let handler2 = MockHandler::new(vec![StreamType::DhtQuery]);

        transport.register_handler(handler1.boxed()).await.unwrap();
        transport.register_handler(handler2.boxed()).await.unwrap();

        let filter = transport.build_stream_filter().await;
        assert!(filter.accepts(StreamType::Membership));
        assert!(filter.accepts(StreamType::PubSub));
        assert!(filter.accepts(StreamType::DhtQuery));
        assert!(!filter.accepts(StreamType::WebRtcSignal));
    }

    #[tokio::test]
    async fn test_registered_types() {
        let transport = SharedTransport::new_with_transport(MockTransport {
            local: PeerId::from([1u8; 32]),
        });

        let handler = MockHandler::new(vec![StreamType::Membership, StreamType::DhtQuery]);
        transport.register_handler(handler.boxed()).await.unwrap();

        let types = transport.registered_types().await;
        assert_eq!(types.len(), 2);
        assert!(types.contains(&StreamType::Membership));
        assert!(types.contains(&StreamType::DhtQuery));
    }

    #[tokio::test]
    async fn test_local_peer() {
        let peer = PeerId::from([42u8; 32]);
        let transport = SharedTransport::new_with_transport(MockTransport { local: peer });
        assert_eq!(transport.local_peer(), peer);
    }
}
