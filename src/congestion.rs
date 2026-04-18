// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Congestion Control Algorithms
//!
//! This module provides congestion control algorithms for QUIC connections.

use crate::connection::RttEstimator;
use std::any::Any;
use std::time::Instant;

// Re-export the congestion control implementations
pub(crate) mod bbr;
pub(crate) mod bbr2;
pub(crate) mod cubic;
pub(crate) mod new_reno;

// Re-export commonly used types
pub(crate) use self::bbr::BbrConfig;
pub(crate) use self::bbr2::Bbr2Config;
pub(crate) use self::cubic::CubicConfig;
// pub use self::new_reno::{NewReno as NewRenoFull, NewRenoConfig};

/// Metrics exported by congestion controllers
#[derive(Debug, Default, Clone, Copy)]
pub struct ControllerMetrics {
    /// Current congestion window in bytes
    pub congestion_window: u64,
    /// Slow start threshold in bytes (optional)
    pub ssthresh: Option<u64>,
    /// Pacing rate in bytes per second (optional)
    pub pacing_rate: Option<u64>,
}

/// Congestion controller interface
pub trait Controller: Send + Sync {
    /// Called when a packet is sent. `is_retransmissible` is `true` iff the
    /// packet carries congestion-controlled data (ack-eliciting); BBRv2's
    /// sampler uses this flag to decide whether to track the packet for
    /// delivery-rate sampling.
    fn on_sent(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        is_retransmissible: bool,
    ) {
        let _ = (now, bytes, last_packet_number, is_retransmissible);
    }

    /// Called when a packet is acknowledged. `pn` is the real packet
    /// number — BBRv2's `BandwidthSampler` uses it to look up per-packet
    /// send-time state in its `ConnectionStateMap`.
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
        pn: u64,
    );

    /// Called once per lost packet, **before** the aggregate
    /// [`Controller::on_congestion_event`] call. BBRv2 needs per-packet
    /// `(pn, bytes)` to feed its sampler's loss path; BBRv1/CUBIC/NewReno
    /// ignore this signal (default no-op).
    fn on_packet_lost(&mut self, now: Instant, pn: u64, bytes: u64) {
        let _ = (now, pn, bytes);
    }

    /// Signal that the sender has run out of data to send (app-limited).
    /// BBRv2 uses this to tag in-flight packets so bandwidth samples
    /// don't mistake the throughput dip for a bandwidth ceiling.
    fn on_app_limited(&mut self, bytes_in_flight: u64) {
        let _ = bytes_in_flight;
    }

    /// A packet that was in flight has been "neutered" — its protection
    /// keys have been discarded, so it can neither be acked nor
    /// retransmitted. BBRv2 removes it from its sampler state map.
    fn on_packet_neutered(&mut self, pn: u64) {
        let _ = pn;
    }

    /// Called when the known in-flight packet count has decreased (should be called exactly once per on_ack_received)
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let _ = (now, in_flight, app_limited, largest_packet_num_acked);
    }

    /// Called when a congestion event occurs (packet loss)
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    );

    /// Called when the maximum transmission unit (MTU) changes
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Get the current congestion window size
    fn window(&self) -> u64;

    /// Get controller metrics
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
        }
    }

    /// Clone this controller into a new boxed instance
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Get the initial congestion window size
    fn initial_window(&self) -> u64;

    /// Convert this controller to Any for downcasting
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Base datagram size constant
pub(crate) const BASE_DATAGRAM_SIZE: u64 = 1200;

/// Simplified NewReno congestion control algorithm
///
/// This is a minimal implementation that provides basic congestion control.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct NewReno {
    /// Current congestion window size
    window: u64,

    /// Slow start threshold
    ssthresh: u64,

    /// Minimum congestion window size
    min_window: u64,

    /// Maximum congestion window size
    max_window: u64,

    /// Initial window size
    initial_window: u64,

    /// Current MTU
    current_mtu: u64,

    /// Recovery start time
    recovery_start_time: Instant,
}

impl NewReno {
    /// Create a new NewReno controller
    #[allow(dead_code)]
    pub(crate) fn new(min_window: u64, max_window: u64, now: Instant) -> Self {
        let initial_window = min_window.max(10 * BASE_DATAGRAM_SIZE);
        Self {
            window: initial_window,
            ssthresh: max_window,
            min_window,
            max_window,
            initial_window,
            current_mtu: BASE_DATAGRAM_SIZE,
            recovery_start_time: now,
        }
    }
}

impl Controller for NewReno {
    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
        _pn: u64,
    ) {
        if app_limited || sent <= self.recovery_start_time {
            return;
        }

        if self.window < self.ssthresh {
            // Slow start
            self.window = (self.window + bytes).min(self.max_window);
        } else {
            // Congestion avoidance - increase by MTU per RTT
            let increase = (bytes * self.current_mtu) / self.window;
            self.window = (self.window + increase).min(self.max_window);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        if sent <= self.recovery_start_time {
            return;
        }

        self.recovery_start_time = now;
        self.window = (self.window / 2).max(self.min_window);
        self.ssthresh = self.window;

        if is_persistent_congestion {
            self.window = self.min_window;
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.min_window = 2 * self.current_mtu;
        self.window = self.window.max(self.min_window);
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window,
            ssthresh: Some(self.ssthresh),
            pacing_rate: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory trait for creating congestion controllers
pub trait ControllerFactory: Send + Sync {
    /// Create a new controller instance for a path whose current MTU is
    /// `current_mtu` bytes.
    fn new_controller(&self, current_mtu: u16, now: Instant) -> Box<dyn Controller + Send + Sync>;
}
