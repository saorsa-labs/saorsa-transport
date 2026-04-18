// Copyright 2026 Saorsa Labs Ltd.
//
// Shim types for the BBRv2 port. These mirror the quiche types that the
// vendored files reference. We keep names and signatures identical so the
// vendored code can reference them unchanged.

use super::bandwidth::Bandwidth;
use std::fmt::Debug;
use std::time::Instant;

// ---------- packet metadata ----------

#[derive(Debug, Clone, Copy)]
pub(super) struct Acked {
    pub(super) pkt_num: u64,
    pub(super) time_sent: Instant,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Lost {
    pub(super) packet_number: u64,
    pub(super) bytes_lost: usize,
}

// ---------- RTT stats placeholder ----------
//
// quiche's `RttStats` is a substantial RFC6298 RTT tracker. The vendored
// BBRv2 code only references it as a typed parameter on the
// `CongestionControl` trait — it never reads fields. So a unit struct is
// enough to satisfy the type system.

#[derive(Debug, Default)]
pub(super) struct RttStats;

// ---------- startup-exit bookkeeping ----------

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct StartupExit {
    pub(super) cwnd: usize,
    pub(super) bandwidth: Option<u64>,
    pub(super) reason: StartupExitReason,
}

impl StartupExit {
    pub(super) fn new(
        cwnd: usize,
        bandwidth: Option<Bandwidth>,
        reason: StartupExitReason,
    ) -> Self {
        Self {
            cwnd,
            bandwidth: bandwidth.map(Bandwidth::to_bytes_per_second),
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum StartupExitReason {
    /// Exit due to excessive loss.
    Loss,
    /// Exit due to bandwidth plateau.
    BandwidthPlateau,
    /// Exit due to persistent queueing (`max_startup_queue_rounds`).
    PersistentQueue,
}

#[derive(Debug, Default)]
pub(super) struct RecoveryStats {
    #[allow(dead_code)]
    startup_exit: Option<StartupExit>,
}

impl RecoveryStats {
    pub(super) fn set_startup_exit(&mut self, startup_exit: StartupExit) {
        if self.startup_exit.is_none() {
            self.startup_exit = Some(startup_exit);
        }
    }
}

// ---------- BBR tuning knobs ----------

/// How bandwidth_lo is reduced on congestion events. Defaults to the
/// `BBRBeta` multiplicative factor.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
#[allow(dead_code)]
pub(super) enum BbrBwLoReductionStrategy {
    Default = 0,
    MinRttReduction = 1,
    InflightReduction = 2,
    CwndReduction = 3,
}

/// Full set of BBRv2 knobs. All fields are `Option` so we can override
/// piecewise; unset fields fall back to the defaults in `DEFAULT_PARAMS`.
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[repr(C)]
#[allow(dead_code)]
pub(super) struct BbrParams {
    pub(super) startup_cwnd_gain: Option<f32>,
    pub(super) startup_pacing_gain: Option<f32>,
    pub(super) full_bw_threshold: Option<f32>,
    pub(super) startup_full_bw_rounds: Option<usize>,
    pub(super) startup_full_loss_count: Option<usize>,
    pub(super) drain_cwnd_gain: Option<f32>,
    pub(super) drain_pacing_gain: Option<f32>,
    pub(super) enable_reno_coexistence: Option<bool>,
    pub(super) enable_overestimate_avoidance: Option<bool>,
    pub(super) choose_a0_point_fix: Option<bool>,
    pub(super) probe_bw_probe_up_pacing_gain: Option<f32>,
    pub(super) probe_bw_probe_down_pacing_gain: Option<f32>,
    pub(super) probe_bw_cwnd_gain: Option<f32>,
    pub(super) probe_bw_up_cwnd_gain: Option<f32>,
    pub(super) probe_rtt_pacing_gain: Option<f32>,
    pub(super) probe_rtt_cwnd_gain: Option<f32>,
    pub(super) max_probe_up_queue_rounds: Option<usize>,
    pub(super) loss_threshold: Option<f32>,
    pub(super) use_bytes_delivered_for_inflight_hi: Option<bool>,
    pub(super) decrease_startup_pacing_at_end_of_round: Option<bool>,
    pub(super) bw_lo_reduction_strategy: Option<BbrBwLoReductionStrategy>,
    pub(super) ignore_app_limited_for_no_bandwidth_growth: Option<bool>,
    pub(super) initial_pacing_rate_bytes_per_second: Option<u64>,
    pub(super) scale_pacing_rate_by_mss: Option<bool>,
    pub(super) disable_probe_down_early_exit: Option<bool>,
    pub(super) time_sent_set_to_now: Option<bool>,
}

// ---------- congestion-control trait ----------
//
// Mirrors the quiche interface so `impl CongestionControl for BBRv2` in
// `mod.rs` compiles unchanged. The outer adapter (`Bbr2Adapter`) is what
// implements saorsa's real `Controller` trait by forwarding here.

pub(super) trait CongestionControl: Debug {
    fn get_congestion_window(&self) -> usize;

    fn get_congestion_window_in_packets(&self) -> usize;

    fn can_send(&self, bytes_in_flight: usize) -> bool;

    fn on_packet_sent(
        &mut self,
        sent_time: Instant,
        bytes_in_flight: usize,
        packet_number: u64,
        bytes: usize,
        is_retransmissible: bool,
    );

    fn on_packet_neutered(&mut self, _packet_number: u64) {}

    #[allow(clippy::too_many_arguments)]
    fn on_congestion_event(
        &mut self,
        rtt_updated: bool,
        prior_in_flight: usize,
        bytes_in_flight: usize,
        event_time: Instant,
        acked_packets: &[Acked],
        lost_packets: &[Lost],
        least_unacked: u64,
        rtt_stats: &RttStats,
        recovery_stats: &mut RecoveryStats,
    );

    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool);

    #[allow(dead_code)]
    fn on_connection_migration(&mut self);

    fn limit_cwnd(&mut self, _max_cwnd: usize) {}

    fn is_in_recovery(&self) -> bool;

    #[allow(dead_code)]
    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool;

    fn pacing_rate(&self, bytes_in_flight: usize, rtt_stats: &RttStats) -> Bandwidth;

    fn bandwidth_estimate(&self, rtt_stats: &RttStats) -> Bandwidth;

    fn max_bandwidth(&self) -> Bandwidth;

    fn update_mss(&mut self, new_mss: usize);

    fn on_app_limited(&mut self, _bytes_in_flight: usize) {}
}
