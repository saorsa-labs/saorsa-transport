// Copyright 2026 Saorsa Labs Ltd.
//
// Smoke tests for the BBRv2 adapter. These are not a rigorous validation
// of BBRv2 behaviour — they exercise the plumbing between saorsa's
// `Controller` trait and the vendored quiche state machine, to make sure
// the adapter doesn't panic on common call sequences and reports sane
// metrics.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::Instant;
    use crate::congestion::{Controller, ControllerFactory};
    use crate::connection::RttEstimator;

    use super::super::Bbr2Config;
    use super::super::adapter::Bbr2Adapter;

    const TEST_MTU: u16 = 1200;

    fn make_adapter() -> Bbr2Adapter {
        Bbr2Adapter::new(Arc::new(Bbr2Config::default()), TEST_MTU)
    }

    fn rtt_of(d: Duration) -> RttEstimator {
        RttEstimator::new(d)
    }

    #[test]
    fn instantiates_with_sane_window() {
        let a = make_adapter();
        let w = a.window();
        assert!(w > 0, "initial window must be positive, got {w}");
        // Default initial_window is 200 packets × 1200 bytes. The cwnd is
        // derived as initial_cwnd_pkts × mss, so it should land in that
        // ballpark (allow slack for BBRv2's internal clamping).
        assert!(w >= 4 * TEST_MTU as u64, "got {w}");
    }

    #[test]
    fn factory_path_produces_controller() {
        let cfg = Bbr2Config::default();
        let ctl = cfg.new_controller(TEST_MTU, Instant::now());
        assert!(ctl.initial_window() > 0);
    }

    #[test]
    fn ack_batch_does_not_panic() {
        let mut a = make_adapter();
        let t0 = Instant::now();
        let rtt = rtt_of(Duration::from_millis(50));

        // Send 5 packets, ack all 5, end batch.
        for i in 1..=5_u64 {
            a.on_sent(t0 + Duration::from_micros(i * 100), 1200, i, true);
        }
        for i in 1..=5_u64 {
            a.on_ack(
                t0 + Duration::from_millis(50),
                t0 + Duration::from_micros(i * 100),
                1200,
                false,
                &rtt,
                i,
            );
        }
        a.on_end_acks(t0 + Duration::from_millis(50), 0, false, Some(5));

        // After acking everything, the adapter's internal bytes_in_flight
        // should be zero (resyncs with `in_flight` argument in
        // on_end_acks).
        assert!(a.window() > 0);
    }

    #[test]
    fn loss_event_does_not_panic() {
        let mut a = make_adapter();
        let t0 = Instant::now();

        // Pretend we sent 3 packets, then all 3 are lost.
        for i in 1..=3_u64 {
            a.on_sent(t0, 1200, i, true);
        }
        for i in 1..=3_u64 {
            a.on_packet_lost(t0 + Duration::from_millis(100), i, 1200);
        }
        a.on_congestion_event(
            t0 + Duration::from_millis(100),
            t0,
            /* is_persistent_congestion = */ false,
            3 * 1200,
        );
        // cwnd shouldn't have collapsed to zero.
        assert!(a.window() > 0);
    }

    #[test]
    fn mtu_update_propagates() {
        let mut a = make_adapter();
        let old_w = a.window();
        a.on_mtu_update(1500);
        let new_w = a.window();
        // cwnd is in bytes so it shouldn't change drastically from an MTU
        // bump, but BBRv2 may rescale its pacing rate. Just check the
        // call doesn't panic and cwnd remains positive.
        assert!(new_w > 0, "cwnd {new_w} after MTU update (was {old_w})");
    }

    #[test]
    fn metrics_reports_pacing_rate() {
        let a = make_adapter();
        let m = a.metrics();
        // BBRv2 seeds an initial pacing rate from initial_cwnd / initial
        // smoothed_rtt — always non-None for the BBR family.
        assert!(m.pacing_rate.is_some());
        // cwnd matches window().
        assert_eq!(m.congestion_window, a.window());
    }

    #[test]
    fn clone_box_returns_fresh_adapter() {
        let a = make_adapter();
        let cloned = a.clone_box();
        assert_eq!(cloned.initial_window(), a.initial_window());
    }
}
