// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Socket
//!
//! A virtual UDP socket backed entirely by a MASQUE relay tunnel.
//!
//! Implements [`AsyncUdpSocket`] so it can back a standalone Quinn
//! endpoint that accepts connections arriving through the relay.  The
//! node's **main** endpoint keeps its original UDP socket and is never
//! touched — this socket powers a **second** endpoint that provides an
//! additional inbound path.
//!
//! ## Routing
//!
//! - **Outgoing** → encoded as length-prefixed
//!   [`UncompressedDatagram`]s and written to the relay QUIC stream.
//! - **Incoming** → read from the relay QUIC stream, decoded, and
//!   queued for Quinn's `poll_recv`.
//!
//! ## Backpressure & buffering
//!
//! Both the send and receive paths use **bounded** `tokio::sync::mpsc`
//! channels rather than unbounded ones.  The receiver path gets natural
//! backpressure from `Sender::send().await` in the reader task: if
//! Quinn stops consuming, the reader stalls on the channel and QUIC
//! flow control eventually pauses the peer.  The sender path propagates
//! backpressure up into Quinn: when the send channel is full,
//! `try_send` returns [`io::ErrorKind::WouldBlock`] and the
//! [`TunnelPoller`] blocks on a [`Notify`] until the stream writer
//! task drains an item and frees a slot.  This preserves the
//! reliable-stream invariant of the MASQUE tunnel — packets are never
//! silently dropped — at the cost of pausing the inner Quinn endpoint
//! when the tunnel cannot keep up.

use bytes::Bytes;
use parking_lot::Mutex as PlMutex;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};

use quinn_udp::{RecvMeta, Transmit};

use crate::VarInt;
use crate::high_level::{AsyncUdpSocket, UdpPoller};
use crate::masque::UncompressedDatagram;

/// Interval at which the relay client sends a zero-length keepalive
/// frame through the relay stream.  Must be shorter than the NAT
/// conntrack UDP stream timeout (typically 120 s on Linux) to prevent
/// the mapping from expiring while the relay is idle.
const RELAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Upper bound on pending outbound packets queued for the stream writer.
/// A full channel causes `try_send` to drop packets (see module-level
/// docs), which matches UDP's lossy semantics.  8192 × ~1200 B ≈ 10 MB
/// of worst-case buffering before drops begin.
const SEND_QUEUE_CAPACITY: usize = 8192;

/// Upper bound on decoded inbound packets queued for `poll_recv`.
/// The reader task awaits on `Sender::send`, so when this fills up the
/// reader naturally backpressures the relay stream.
const RECV_QUEUE_CAPACITY: usize = 8192;

/// Safety cap on individual frame length read from the relay stream.
/// Legitimate QUIC packets are ≤65535 bytes; anything above this is a
/// framing error or corruption and closes the session.
const MAX_RELAY_FRAME: usize = 512 * 1024;

/// Raw QUIC streams from a relay session, before socket construction.
///
/// Returned by `establish_relay_session` so the caller can construct a
/// [`MasqueRelaySocket`] with the additional context it needs.
pub struct RawRelayStreams {
    /// Send half of the relay QUIC stream (length-prefixed datagrams).
    pub send_stream: crate::high_level::SendStream,
    /// Receive half of the relay QUIC stream.
    pub recv_stream: crate::high_level::RecvStream,
}

/// A virtual UDP socket backed entirely by a MASQUE relay tunnel.
///
/// All traffic — both outgoing and incoming — flows through the relay
/// QUIC stream.  This socket is intended for a **second** Quinn endpoint
/// dedicated to relay traffic, leaving the main endpoint and its
/// original UDP socket completely untouched.
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address).
    relay_public_addr: SocketAddr,
    /// Bounded MPSC receiver of decoded inbound packets.
    ///
    /// Wrapped in a parking_lot mutex purely for interior mutability
    /// (`Receiver::poll_recv` needs `&mut`).  Only Quinn's single I/O
    /// driver task polls `poll_recv` on this socket, so the lock is
    /// effectively uncontested at runtime.
    recv_rx: PlMutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    /// Bounded channel for outbound packets (drained by the background
    /// writer task into the relay send stream).
    send_tx: mpsc::Sender<Bytes>,
    /// Notified once after every item the writer task drains from
    /// `send_tx`.  Pollers parked on a full queue re-check capacity
    /// after each notification.  `notify_one` is used (not
    /// `notify_waiters`) so a drain that races with a poller entering
    /// the wait state stores a permit, avoiding lost wakeups.
    send_capacity_freed: Arc<Notify>,
    /// The original socket is kept alive so the relay connection's own
    /// QUIC traffic (keepalives, ACKs, stream data) continues to flow
    /// directly.  Without this reference the OS may reclaim the socket.
    _original_socket: Arc<dyn AsyncUdpSocket>,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field("send_capacity", &self.send_tx.capacity())
            .finish()
    }
}

impl MasqueRelaySocket {
    /// Create a new tunnel-only relay socket.
    ///
    /// All I/O flows through the relay QUIC stream.  `original_socket`
    /// is held alive (but not used for I/O) to prevent the OS from
    /// reclaiming the underlying file descriptor while the relay
    /// connection's own QUIC traffic still needs it.
    ///
    /// Spawns three background tasks:
    /// - A reader that decodes length-prefixed frames from
    ///   `recv_stream` and pushes `(Bytes, SocketAddr)` to the bounded
    ///   recv channel for [`poll_recv`] to drain.
    /// - A writer that drains the send channel and writes
    ///   length-prefixed frames to `send_stream`.
    /// - A keepalive ticker that injects zero-length frames so the
    ///   NAT conntrack entry stays alive on idle connections.
    ///
    /// Returns the socket alongside a [`Notify`] that fires exactly once
    /// when the reader task exits (tunnel failure).  Callers that own the
    /// backing endpoint should use this to trigger a **graceful** close
    /// — `Endpoint::close(code, reason)` sends CONNECTION_CLOSE frames
    /// to every connection before the endpoint driver future is dropped.
    /// Without this, the driver's `Drop` impl fires last and cascades
    /// a cryptic `"endpoint driver future was dropped"` into every
    /// connection accepted through this tunnel.
    pub fn new(
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
        _relay_server_addr: SocketAddr,
        original_socket: Arc<dyn AsyncUdpSocket>,
    ) -> (Arc<Self>, Arc<Notify>) {
        let (send_tx, mut send_rx) = mpsc::channel::<Bytes>(SEND_QUEUE_CAPACITY);
        let (recv_tx, recv_rx) = mpsc::channel::<(Bytes, SocketAddr)>(RECV_QUEUE_CAPACITY);
        let closed = Arc::new(Notify::new());
        let send_capacity_freed = Arc::new(Notify::new());

        let socket = Arc::new(Self {
            relay_public_addr,
            recv_rx: PlMutex::new(recv_rx),
            send_tx: send_tx.clone(),
            send_capacity_freed: Arc::clone(&send_capacity_freed),
            _original_socket: original_socket,
        });

        // Background task: read length-prefixed frames from relay stream
        // and forward decoded (payload, source) pairs to `poll_recv`.
        // Holds the payload as `Bytes` throughout — no Vec round-trip.
        let closed_reader = Arc::clone(&closed);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (length)");
                    break;
                }
                let frame_len = u32::from_be_bytes(len_buf) as usize;
                // Zero-length frame = keepalive ping from the relay
                // server, skip without trying to decode a datagram.
                if frame_len == 0 {
                    continue;
                }
                if frame_len > MAX_RELAY_FRAME {
                    tracing::warn!(frame_len, "MasqueRelaySocket: corrupt frame length");
                    break;
                }

                let mut frame_buf = vec![0u8; frame_len];
                if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (data)");
                    break;
                }

                let mut cursor = Bytes::from(frame_buf);
                match UncompressedDatagram::decode(&mut cursor) {
                    Ok(datagram) => {
                        // `datagram.payload` is a zero-copy slice of
                        // the original frame buffer — no clone needed.
                        if recv_tx
                            .send((datagram.payload, datagram.target))
                            .await
                            .is_err()
                        {
                            // Receiver dropped — socket is gone.
                            break;
                        }
                    }
                    Err(_) => {
                        tracing::trace!("MasqueRelaySocket: failed to decode frame");
                    }
                }
            }
            // Dropping `recv_tx` here wakes any pending `poll_recv`
            // with Poll::Ready(None), signalling end-of-stream.
            //
            // Signal any watcher waiting on the close notification so it
            // can initiate a graceful endpoint close BEFORE the driver's
            // `Drop` fires.  `notify_waiters` wakes every current waiter
            // exactly once; subsequent waits see `Pending`, which is
            // fine — the shutdown only needs to run once.
            closed_reader.notify_waiters();
        });

        // Background task: write queued outbound packets to relay stream.
        let writer_capacity = Arc::clone(&send_capacity_freed);
        tokio::spawn(async move {
            while let Some(encoded) = send_rx.recv().await {
                // `recv` completing means the channel just freed a
                // slot.  Wake any poller parked on full-queue
                // backpressure before proceeding with the (potentially
                // slow) stream write — so the Quinn endpoint can start
                // assembling the next packet concurrently with this
                // frame going out on the wire.
                writer_capacity.notify_one();

                let frame_len = encoded.len() as u32;
                if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (length)");
                    break;
                }
                // Zero-length frames (keepalives) need only the length
                // prefix — skip the empty write_all.
                if !encoded.is_empty() {
                    if let Err(e) = send_stream.write_all(&encoded).await {
                        tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (data)");
                        break;
                    }
                }
            }
            // Writer exited (stream error or receiver dropped). Dropping
            // `send_rx` closes the channel so subsequent `try_send`
            // calls fail fast with `Closed` instead of filling a queue
            // that nobody will drain. Wake any poller currently parked
            // on `send_capacity_freed`: it will re-check, observe the closed
            // channel via `is_closed`, and surface the failure instead
            // of waiting forever.
            drop(send_rx);
            writer_capacity.notify_waiters();
        });

        // Background task: periodic keepalive pings.
        // Sends a zero-length frame through the writer channel to keep
        // the NAT conntrack entry alive for the underlying QUIC
        // connection.  The writer encodes it as a 4-byte `[0,0,0,0]`
        // length prefix with no payload; the relay server skips it.
        let keepalive_tx = send_tx;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(RELAY_KEEPALIVE_INTERVAL);
            tick.tick().await; // skip immediate first tick
            loop {
                tick.tick().await;
                // Use `send` (not `try_send`) — a momentarily-full queue
                // must not cause us to lose liveness of the keepalive.
                if keepalive_tx.send(Bytes::new()).await.is_err() {
                    break; // channel closed — relay dead
                }
            }
        });

        (socket, closed)
    }

    /// Remaining capacity in the outbound send channel.  Exposed for
    /// tests and metrics — a sustained value of 0 means the tunnel
    /// stream can't keep up with Quinn's offered load and the poller
    /// is serialising sends.
    pub fn send_capacity(&self) -> usize {
        self.send_tx.capacity()
    }

    /// Internal helper: enqueue an already-encoded outbound frame.
    ///
    /// Returns [`io::ErrorKind::WouldBlock`] when the send channel is
    /// full so the Quinn UDP driver re-polls
    /// [`UdpPoller::poll_writable`] instead of dropping the packet.
    /// This preserves the reliable-stream invariant of the MASQUE
    /// tunnel — packets never silently disappear — at the cost of
    /// pausing the inner Quinn endpoint until the stream writer
    /// drains a slot.
    fn enqueue_outbound(&self, encoded: Bytes) -> io::Result<()> {
        match self.send_tx.try_send(encoded) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "relay send queue full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "relay stream closed",
            )),
        }
    }
}

impl AsyncUdpSocket for MasqueRelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TunnelPoller {
            socket: self,
            wait: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // When Quinn uses GSO (Generic Segmentation Offload),
        // transmit.contents contains multiple concatenated QUIC packets
        // of `segment_size` bytes.  Each segment must be sent as its
        // own tunnel frame — the relay server has a per-frame size
        // limit and cannot handle the entire batch as one.
        if let Some(segment_size) = transmit.segment_size {
            for chunk in transmit.contents.chunks(segment_size) {
                let datagram = UncompressedDatagram::new(
                    VarInt::from_u32(0),
                    transmit.destination,
                    Bytes::copy_from_slice(chunk),
                );
                self.enqueue_outbound(datagram.encode())?;
            }
            return Ok(());
        }

        let datagram = UncompressedDatagram::new(
            VarInt::from_u32(0),
            transmit.destination,
            Bytes::copy_from_slice(transmit.contents),
        );
        self.enqueue_outbound(datagram.encode())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let capacity = bufs.len().min(meta.len());
        let mut filled = 0;

        // Single lock acquisition per Quinn poll — unlike the previous
        // design there is no separate waker mutex, and no risk of
        // losing a wakeup: `Receiver::poll_recv` registers `cx.waker()`
        // itself when it returns `Pending`.
        let mut rx = self.recv_rx.lock();
        while filled < capacity {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((payload, source))) => {
                    if payload.len() > bufs[filled].len() {
                        tracing::warn!(
                            payload_len = payload.len(),
                            buf_len = bufs[filled].len(),
                            "MasqueRelaySocket: payload exceeds receive buffer; dropping packet"
                        );
                        continue;
                    }
                    let len = payload.len();
                    // Single copy — Bytes → Quinn-owned slice.
                    bufs[filled][..len].copy_from_slice(&payload);

                    let mut recv_meta = RecvMeta::default();
                    recv_meta.len = len;
                    recv_meta.stride = len;
                    recv_meta.addr = source;
                    recv_meta.ecn = None;
                    recv_meta.dst_ip = None;
                    meta[filled] = recv_meta;

                    tracing::trace!(
                        source = %source,
                        len,
                        "RELAY_TUNNEL: recv from tunnel queue"
                    );

                    filled += 1;
                }
                Poll::Ready(None) => {
                    // Channel closed — reader task exited.  Surface as
                    // end-of-stream only if we haven't collected any
                    // packets in this poll; otherwise deliver what we
                    // have and let the next poll see the closed state.
                    if filled == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "relay recv stream closed",
                        )));
                    }
                    break;
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        if filled > 0 {
            Poll::Ready(Ok(filled))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.relay_public_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Poller for the tunnel socket.
///
/// Backpressure model: when the outbound send channel is full,
/// [`poll_writable`](UdpPoller::poll_writable) parks on the socket's
/// `send_capacity_freed` [`Notify`] and wakes when the stream writer drains
/// a slot.  Each wake re-checks remaining capacity because multiple
/// pollers may race against the same notification and because the
/// keepalive task can refill the slot before we observe it.
///
/// The inner `wait` future captures an `Arc<MasqueRelaySocket>` so it
/// owns its own keep-alive reference to the `Notify`; the boxed future
/// is kept alive across polls (following the same pattern as
/// `UdpPollHelper` in `high_level::runtime`) so the registered waker
/// is not lost between calls.
struct TunnelPoller {
    socket: Arc<MasqueRelaySocket>,
    wait: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
}

impl fmt::Debug for TunnelPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelPoller")
            .field("socket", &self.socket)
            .field("waiting", &self.wait.is_some())
            .finish()
    }
}

impl UdpPoller for TunnelPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // `TunnelPoller` is `Unpin` (all fields are `Unpin`), so we can
        // freely take `&mut self` out of the `Pin`.
        let this = self.get_mut();

        // Fast path: capacity is available right now, or the channel
        // is closed (writer task exited — return Ready so Quinn
        // attempts a `try_send`, which surfaces the failure as
        // `ConnectionAborted`).
        if this.socket.send_tx.capacity() > 0 || this.socket.send_tx.is_closed() {
            this.wait = None;
            return Poll::Ready(Ok(()));
        }

        // Slow path: park on the `send_capacity_freed` notify and re-check
        // capacity after each wake.  The future is created once and
        // kept alive until it resolves, so the waker registered via
        // `Notified::enable()` survives across polls — discarding the
        // future after each poll would deregister the waker and lead
        // to lost wakeups.
        let fut = this.wait.get_or_insert_with(|| {
            let socket = Arc::clone(&this.socket);
            Box::pin(async move {
                loop {
                    // Register interest BEFORE re-checking capacity.
                    // If the writer task calls `notify_one` between our
                    // last check and `enable`, `enable` stashes the
                    // permit and the subsequent `.await` returns
                    // immediately.
                    let notified = socket.send_capacity_freed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();

                    if socket.send_tx.capacity() > 0 || socket.send_tx.is_closed() {
                        return;
                    }
                    notified.await;
                    if socket.send_tx.capacity() > 0 || socket.send_tx.is_closed() {
                        return;
                    }
                    // Spurious wake (e.g., another poller consumed the
                    // freed slot before we saw it).  Loop and wait for
                    // the next drain.
                }
            })
        });

        match fut.as_mut().poll(cx) {
            Poll::Ready(()) => {
                this.wait = None;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
