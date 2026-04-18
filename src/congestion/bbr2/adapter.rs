// Copyright 2026 Saorsa Labs Ltd.
//
// Adapter that implements saorsa's streaming `Controller` trait on top of
// the vendored BBRv2 implementation, whose native API expects per-batch
// `on_congestion_event(&[Acked], &[Lost])` calls.
//
// Call flow (saorsa connection):
//
//   `on_sent(pn, bytes, is_retransmissible)`   → feed BBRv2 sampler + accumulate `bytes_in_flight`
//   per-ack: `on_ack(pn, sent, bytes, ...)`    → push `Acked { pn, sent }` to buffer
//   per-loss: `on_packet_lost(pn, bytes)`      → push `Lost { pn, bytes }` to buffer
//   `on_congestion_event(...)`                 → record `is_persistent_congestion` (optional)
//   `on_end_acks(...)`                         → flush the buffered batch into BBRv2
//
// For PTO (no `on_end_acks` follow-up) we flush inside
// `on_congestion_event` too. The adapter self-cleans: `flush_batch` is a
// no-op when both buffers are empty.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use crate::Instant;
use crate::congestion::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory, ControllerMetrics};
use crate::connection::RttEstimator;

use super::BBRv2;
use super::types::{Acked, BbrParams, CongestionControl, Lost, RecoveryStats, RttStats};

/// Default packet count for the initial congestion window — matches BBRv1
/// in this crate (200 × BASE_DATAGRAM_SIZE).
const K_INITIAL_WINDOW_PACKETS: u64 = 200;

/// Cap the max congestion window at something generous but not
/// unbounded. 20k packets × 1500 = 30 MB, enough for 10 Gbps×100ms BDP.
const K_MAX_CONGESTION_WINDOW_PACKETS: usize = 20_000;

/// Fallback smoothed-RTT assumption before the first RTT sample arrives.
/// BBRv2 uses this to seed its initial pacing rate. 100 ms is a
/// reasonable internet-wide guess — real connections override via
/// `Bbr2Config::initial_rtt`.
const K_DEFAULT_SMOOTHED_RTT: Duration = Duration::from_millis(100);

/// Configuration for [`Bbr2Adapter`].
#[derive(Debug, Clone)]
pub(crate) struct Bbr2Config {
    initial_window: u64,
    /// Seed RTT for initial pacing-rate calculation. Falls back to
    /// [`K_DEFAULT_SMOOTHED_RTT`] when unset.
    initial_rtt: Option<Duration>,
    /// Custom BBR tuning knobs. `None` uses `DEFAULT_PARAMS` from the
    /// vendored BBRv2 module.
    params: Option<BbrParams>,
}

impl Bbr2Config {
    #[allow(dead_code)]
    pub(crate) fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn initial_rtt(&mut self, value: Duration) -> &mut Self {
        self.initial_rtt = Some(value);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn params(&mut self, params: BbrParams) -> &mut Self {
        self.params = Some(params);
        self
    }
}

impl Default for Bbr2Config {
    fn default() -> Self {
        Self {
            initial_window: K_INITIAL_WINDOW_PACKETS * BASE_DATAGRAM_SIZE,
            initial_rtt: None,
            params: None,
        }
    }
}

impl ControllerFactory for Bbr2Config {
    fn new_controller(&self, current_mtu: u16, _now: Instant) -> Box<dyn Controller + Send + Sync> {
        Box::new(Bbr2Adapter::new(Arc::new(self.clone()), current_mtu))
    }
}

/// Streaming `Controller` wrapper around `BBRv2`.
pub(crate) struct Bbr2Adapter {
    inner: BBRv2,
    config: Arc<Bbr2Config>,
    mss: usize,
    /// Running byte count of unacked ack-eliciting data. BBRv2's API
    /// needs `bytes_in_flight` at send time; saorsa's trait doesn't
    /// pass it, so we mirror the connection's counter here and resync
    /// from the authoritative value at each `on_end_acks`.
    bytes_in_flight: u64,
    /// In-flight bytes at the start of the current ack-processing
    /// round. Captured on the first `on_ack`/`on_packet_lost` after a
    /// flush so we can report `prior_in_flight` to BBRv2's congestion
    /// event.
    prior_in_flight: u64,
    /// Packets acked during the current batch.
    pending_acked: Vec<Acked>,
    /// Packets lost during the current batch.
    pending_lost: Vec<Lost>,
    /// Smallest packet number still unacked, tracked for BBRv2's
    /// sampler-GC hint. Updated every time we see a pn we haven't
    /// before — either at send or at ack.
    least_unacked: u64,
    /// Unused `RttStats` placeholder — the vendored BBRv2 only takes it
    /// as a typed parameter and never reads it.
    rtt_stats: RttStats,
    /// Startup-exit bookkeeping, passed to BBRv2 by `&mut`.
    recovery_stats: RecoveryStats,
}

impl Bbr2Adapter {
    pub(crate) fn new(config: Arc<Bbr2Config>, current_mtu: u16) -> Self {
        let mss = current_mtu as usize;
        let initial_cwnd_pkts = ((config.initial_window as usize) / mss.max(1)).max(4);
        let smoothed_rtt = config.initial_rtt.unwrap_or(K_DEFAULT_SMOOTHED_RTT);
        let inner = BBRv2::new(
            initial_cwnd_pkts,
            K_MAX_CONGESTION_WINDOW_PACKETS,
            mss,
            smoothed_rtt,
            config.params.as_ref(),
        );
        Self {
            inner,
            config,
            mss,
            bytes_in_flight: 0,
            prior_in_flight: 0,
            pending_acked: Vec::new(),
            pending_lost: Vec::new(),
            least_unacked: 0,
            rtt_stats: RttStats,
            recovery_stats: RecoveryStats::default(),
        }
    }

    /// Flush the pending acks/losses into a single BBRv2 congestion
    /// event. No-op if both buffers are empty. `event_time` should be
    /// the most recent ack/loss-detection time; `bytes_in_flight` is
    /// the current authoritative count (post-ack, post-loss).
    fn flush_batch(&mut self, event_time: Instant, bytes_in_flight: u64) {
        if self.pending_acked.is_empty() && self.pending_lost.is_empty() {
            return;
        }
        // rtt_updated reflects the real BBRv2 semantic: did the largest
        // newly-acked packet update RTT? We approximate by checking the
        // batch has any ack-eliciting acks (which is what's buffered).
        let rtt_updated = !self.pending_acked.is_empty();
        let least_unacked = self.least_unacked;
        self.inner.on_congestion_event(
            rtt_updated,
            self.prior_in_flight as usize,
            bytes_in_flight as usize,
            event_time,
            &self.pending_acked,
            &self.pending_lost,
            least_unacked,
            &self.rtt_stats,
            &mut self.recovery_stats,
        );
        self.pending_acked.clear();
        self.pending_lost.clear();
        // Next round's `prior_in_flight` starts from the current
        // authoritative value; the first ack/loss in the new round will
        // overwrite it via the empty-buffer check.
        self.prior_in_flight = bytes_in_flight;
    }
}

impl Controller for Bbr2Adapter {
    fn on_sent(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        is_retransmissible: bool,
    ) {
        self.inner.on_packet_sent(
            now,
            self.bytes_in_flight as usize,
            last_packet_number,
            bytes as usize,
            is_retransmissible,
        );
        if is_retransmissible {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        }
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
        pn: u64,
    ) {
        // If this is the first event in a new batch, snapshot the
        // current in-flight as `prior_in_flight` before we decrement.
        if self.pending_acked.is_empty() && self.pending_lost.is_empty() {
            self.prior_in_flight = self.bytes_in_flight;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.pending_acked.push(Acked {
            pkt_num: pn,
            time_sent: sent,
        });
        // Advance least_unacked monotonically past the highest pn we've
        // seen acked. The sampler uses this as a GC hint; overestimating
        // would cause premature state deletion, so we bump only when the
        // ack is at or beyond the current mark.
        self.least_unacked = self.least_unacked.max(pn.saturating_add(1));
    }

    fn on_packet_lost(&mut self, _now: Instant, pn: u64, bytes: u64) {
        if self.pending_acked.is_empty() && self.pending_lost.is_empty() {
            self.prior_in_flight = self.bytes_in_flight;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.pending_lost.push(Lost {
            packet_number: pn,
            bytes_lost: bytes as usize,
        });
    }

    fn on_app_limited(&mut self, bytes_in_flight: u64) {
        self.inner.on_app_limited(bytes_in_flight as usize);
    }

    fn on_packet_neutered(&mut self, pn: u64) {
        self.inner.on_packet_neutered(pn);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        // Re-sync our shadow counter from the authoritative value.
        // Drift can accumulate from non-congestion-controlled packets
        // (pure ACKs, PING) that the adapter counts as retransmissible.
        self.bytes_in_flight = in_flight;
        self.flush_batch(now, in_flight);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // For PTO timer-driven losses there's no subsequent
        // `on_end_acks`; flush here so the sampler sees the losses
        // promptly. During ack-processing (`on_ack_received` in
        // `connection/mod.rs`) the call order is on_ack → on_packet_lost
        // → on_congestion_event → on_end_acks, so the flush here draws
        // a complete batch (acks + losses), and on_end_acks's own flush
        // becomes a no-op on empty buffers.
        self.flush_batch(now, self.bytes_in_flight);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let new_mss = new_mtu as usize;
        if new_mss != self.mss {
            self.inner.update_mss(new_mss);
            self.mss = new_mss;
        }
    }

    fn window(&self) -> u64 {
        self.inner.get_congestion_window() as u64
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.inner.pacing_rate_bytes_per_second()),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        // BBRv2 doesn't implement Clone; reconstruct from config. Path
        // migrations are rare enough that resetting BBR state is
        // acceptable — the alternative would be a deep-clone of the
        // entire network model, sampler, mode machine, etc.
        Box::new(Bbr2Adapter::new(self.config.clone(), self.mss as u16))
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl std::fmt::Debug for Bbr2Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bbr2Adapter")
            .field("mss", &self.mss)
            .field("bytes_in_flight", &self.bytes_in_flight)
            .field("least_unacked", &self.least_unacked)
            .field("cwnd", &self.inner.get_congestion_window())
            .finish()
    }
}
