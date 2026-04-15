// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer.
///
/// Operates in one of two modes:
///
/// * **Rate-driven** — used when the congestion controller exports a
///   `pacing_rate` (bytes/sec) via its `metrics()`, e.g. BBR. The bucket
///   refills at exactly that rate and the burst capacity follows from
///   `rate * BURST_INTERVAL`.
/// * **Cwnd-driven** — fallback when the controller doesn't export a rate
///   (CUBIC, NewReno). The bucket refills at `1.25 * cwnd / RTT`, matching
///   the token-bucket shape recommended in
///   <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>.
///
/// BBR applies its own `pacing_gain` when it computes the rate, so the
/// rate-driven mode does not add a second overshoot factor.
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    /// The pacing rate (bytes/sec) used to size `capacity`. `None` means
    /// we're in cwnd-driven mode.
    last_rate: Option<u64>,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Create a new [`Pacer`].
    ///
    /// `pacing_rate` is the controller's advertised pacing rate in bytes
    /// per second. Pass `None` (or `Some(0)`) to use the cwnd-based
    /// fallback — this is the right choice for CUBIC and for BBR before
    /// the first bandwidth sample arrives.
    pub(super) fn new(
        smoothed_rtt: Duration,
        window: u64,
        mtu: u16,
        pacing_rate: Option<u64>,
        now: Instant,
    ) -> Self {
        let rate = pacing_rate.filter(|&r| r > 0);
        let capacity = compute_capacity(smoothed_rtt, window, mtu, rate);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            last_rate: rate,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`.
    ///
    /// If we can send right away, returns `None`. Otherwise returns
    /// `Some(t)` where `t` is the instant at which we should retry.
    ///
    /// `pacing_rate` tracks the controller's advertised rate and may
    /// change between calls (BBR updates it each ACK round); the pacer
    /// resizes the bucket accordingly.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        pacing_rate: Option<u64>,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        let rate = pacing_rate.filter(|&r| r > 0);

        if window != self.last_window || mtu != self.last_mtu || rate != self.last_rate {
            self.capacity = compute_capacity(smoothed_rtt, window, mtu, rate);
            // Clamp the tokens down to the new capacity. Leave them alone
            // when capacity grows.
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
            self.last_rate = rate;
        }

        // If we can already send a packet, there is no need for delay.
        if self.tokens >= bytes_to_send {
            return None;
        }

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp earlier than a previous recorded time, ignoring");
            Default::default()
        });

        let (new_tokens, delay): (u64, Duration) = match rate {
            Some(rate) => {
                // Rate-based refill: tokens = rate * elapsed.
                let refilled =
                    (rate as u128).saturating_mul(time_elapsed.as_nanos()) / NANOS_PER_SECOND;
                let delay = {
                    // After refilling, we still need more tokens. Compute
                    // how long until `bytes_to_send` is available. We
                    // intentionally refill up to `capacity` (matches the
                    // cwnd-driven branch's semantics and keeps the
                    // time-to-capacity bounded).
                    let projected = u64::try_from(self.tokens as u128 + refilled)
                        .unwrap_or(u64::MAX)
                        .min(self.capacity);
                    let deficit = bytes_to_send.max(self.capacity).saturating_sub(projected);
                    Duration::from_nanos(
                        u64::try_from((deficit as u128 * NANOS_PER_SECOND) / rate as u128)
                            .unwrap_or(u64::MAX),
                    )
                };
                (u64::try_from(refilled).unwrap_or(u64::MAX), delay)
            }
            None => {
                // Pacing is effectively disabled for extremely large
                // windows in cwnd-driven mode (the integer math below
                // would overflow or produce nonsense).
                if window > u64::from(u32::MAX) {
                    return None;
                }
                if smoothed_rtt.as_nanos() == 0 {
                    return None;
                }
                let window_u32 = window as u32;
                let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
                let refilled = window as f64 * CWND_OVERSHOOT * elapsed_rtts;
                let refilled = refilled.max(0.0) as u64;
                let projected = self.tokens.saturating_add(refilled).min(self.capacity);
                let deficit = bytes_to_send.max(self.capacity).saturating_sub(projected);
                // divisions come before multiplications to prevent overflow
                let unscaled_delay = smoothed_rtt
                    .checked_mul(u32::try_from(deficit).unwrap_or(u32::MAX))
                    .unwrap_or(Duration::MAX)
                    / window_u32;
                // The bucket empties in 4/5 of BURST_INTERVAL under the
                // 1.25× overshoot; scaling the delay by the same factor
                // keeps the pacer on that target.
                let delay = (unscaled_delay / CWND_OVERSHOOT_DENOM) * CWND_OVERSHOOT_NUM;
                (refilled, delay)
            }
        };

        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
        self.prev = now;

        if self.tokens >= bytes_to_send {
            return None;
        }

        Some(self.prev + delay)
    }
}

/// Pacer burst capacity in bytes: the size of one burst that we allow to
/// go out before throttling kicks in.
///
/// For a rate `r` (bytes/sec), one `BURST_INTERVAL` worth of bytes is
/// `r * BURST_INTERVAL`. For cwnd-driven pacing the same target is
/// `window * BURST_INTERVAL / RTT`. Both are clamped into the
/// `[MIN_BURST_SIZE, MAX_BURST_SIZE]` range (measured in MTUs) so that
/// very low rates still emit at least one useful burst and very high
/// rates don't outrun the send path.
fn compute_capacity(smoothed_rtt: Duration, window: u64, mtu: u16, rate: Option<u64>) -> u64 {
    let unclamped = match rate {
        Some(rate) => ((rate as u128).saturating_mul(BURST_INTERVAL_NANOS) / NANOS_PER_SECOND)
            .try_into()
            .unwrap_or(u64::MAX),
        None => {
            let rtt = smoothed_rtt.as_nanos().max(1);
            ((window as u128 * BURST_INTERVAL_NANOS) / rtt)
                .try_into()
                .unwrap_or(u64::MAX)
        }
    };
    unclamped.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval.
///
/// The capacity will be refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000;

/// Overshoot factor applied in cwnd-driven mode to match the
/// `N = 1.25` recommendation in the QUIC recovery draft.
const CWND_OVERSHOOT: f64 = 1.25;
const CWND_OVERSHOOT_NUM: u32 = 4;
const CWND_OVERSHOOT_DENOM: u32 = 5;

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't
/// make sense.
const MAX_BURST_SIZE: u64 = 256;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WINDOW: u64 = 30_000;
    const TEST_MTU: u16 = 1500;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, TEST_WINDOW, TEST_MTU, None, new_instant)
                .delay(Duration::from_micros(0), 0, TEST_MTU, 1, None, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, TEST_WINDOW, TEST_MTU, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1600,
                    TEST_MTU,
                    1,
                    None,
                    old_instant
                )
                .is_none()
        );
        assert!(
            Pacer::new(rtt, TEST_WINDOW, TEST_MTU, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1500,
                    TEST_MTU,
                    3000,
                    None,
                    old_instant
                )
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity_cwnd_mode() {
        let window = 2_000_000;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, TEST_MTU, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, TEST_MTU, None, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * TEST_MTU as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, TEST_MTU, None, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * TEST_MTU as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn derives_initial_capacity_rate_mode() {
        // 100 MB/s rate → capacity = rate * 2ms = 200_000 bytes.
        const RATE: u64 = 100 * 1024 * 1024;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, TEST_WINDOW, TEST_MTU, Some(RATE), now);
        let expected = (RATE as u128 * BURST_INTERVAL_NANOS / NANOS_PER_SECOND) as u64;
        assert_eq!(pacer.capacity, expected);
        assert_eq!(pacer.tokens, pacer.capacity);

        // Capacity is mtu-clamped from below — a very low rate gets
        // floored at MIN_BURST_SIZE * mtu.
        let pacer = Pacer::new(rtt, TEST_WINDOW, TEST_MTU, Some(1024), now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * TEST_MTU as u64);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, TEST_MTU, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, TEST_MTU as u64, TEST_MTU, window * 2, None, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, TEST_MTU as u64, TEST_MTU, window / 2, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, TEST_MTU as u64, TEST_MTU * 2, window, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, TEST_MTU as u64, 20_000, window, None, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu: u16 = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, None, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn rate_mode_delays_by_bytes_over_rate() {
        // At 10 MB/s the pacer should take ~1ms to refill enough tokens
        // to send 10 000 bytes after the bucket is drained.
        const RATE: u64 = 10 * 1024 * 1024; // 10 MiB/s
        const MTU: u16 = 1200;
        let rtt = Duration::from_millis(20);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, TEST_WINDOW, MTU, Some(RATE), now);
        // Drain the bucket.
        pacer.tokens = 0;
        let capacity_bytes = pacer.capacity;

        // Ask for more than we have; the returned delay should be
        // roughly capacity_bytes / rate.
        let earliest = pacer
            .delay(rtt, capacity_bytes, MTU, TEST_WINDOW, Some(RATE), now)
            .expect("must delay when bucket is drained");
        let delay_ns = earliest.duration_since(now).as_nanos();
        let expected_ns = (capacity_bytes as u128 * NANOS_PER_SECOND) / RATE as u128;
        // Allow 5% slack for integer-math rounding.
        let slack = expected_ns / 20;
        assert!(
            delay_ns >= expected_ns.saturating_sub(slack)
                && delay_ns <= expected_ns.saturating_add(slack),
            "expected ~{expected_ns} ns, got {delay_ns} ns"
        );
    }

    #[test]
    fn rate_mode_switches_to_cwnd_when_rate_drops_to_zero() {
        // BBR reports pacing_rate = 0 before the first bandwidth sample.
        // The pacer should silently fall back to cwnd-based refill.
        let window = 2_000_000;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, TEST_MTU, Some(0), now);
        let cwnd_capacity = (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64;
        assert_eq!(pacer.capacity, cwnd_capacity);

        // Switching on a real rate should resize the bucket.
        const RATE: u64 = 50 * 1024 * 1024;
        pacer.delay(rtt, TEST_MTU as u64, TEST_MTU, window, Some(RATE), now);
        let rate_capacity = (RATE as u128 * BURST_INTERVAL_NANOS / NANOS_PER_SECOND) as u64;
        assert_eq!(pacer.capacity, rate_capacity);
    }
}
