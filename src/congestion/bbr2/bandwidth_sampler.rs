// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright (C) 2023, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use super::bandwidth::Bandwidth;
use super::types::Acked;
use super::types::Lost;

use super::windowed_filter::WindowedFilter;

#[derive(Debug)]
struct ConnectionStateMap<T> {
    packet_map: VecDeque<(u64, Option<T>)>,
}

impl<T> Default for ConnectionStateMap<T> {
    fn default() -> Self {
        ConnectionStateMap {
            packet_map: VecDeque::new(),
        }
    }
}

impl<T> ConnectionStateMap<T> {
    fn insert(&mut self, pkt_num: u64, val: T) {
        if let Some((last_pkt, _)) = self.packet_map.back() {
            assert!(pkt_num > *last_pkt, "{} > {}", pkt_num, *last_pkt);
        }

        self.packet_map.push_back((pkt_num, Some(val)));
    }

    fn take(&mut self, pkt_num: u64) -> Option<T> {
        // First we check if the next packet is the one we are looking for
        let first = self.packet_map.front()?;
        if first.0 == pkt_num {
            return self.packet_map.pop_front().and_then(|(_, v)| v);
        }
        // Use binary search
        let ret = match self.packet_map.binary_search_by_key(&pkt_num, |&(n, _)| n) {
            Ok(found) => self.packet_map.get_mut(found).and_then(|(_, v)| v.take()),
            Err(_) => None,
        };

        while let Some((_, None)) = self.packet_map.front() {
            self.packet_map.pop_front();
        }

        ret
    }

    #[cfg(test)]
    fn peek(&self, pkt_num: u64) -> Option<&T> {
        // Use binary search
        match self.packet_map.binary_search_by_key(&pkt_num, |&(n, _)| n) {
            Ok(found) => self.packet_map.get(found).and_then(|(_, v)| v.as_ref()),
            Err(_) => None,
        }
    }

    fn remove_obsolete(&mut self, least_acked: u64) {
        while match self.packet_map.front() {
            Some(&(p, _)) if p < least_acked => {
                self.packet_map.pop_front();
                true
            }
            _ => false,
        } {}
    }
}

#[derive(Debug)]
pub struct BandwidthSampler {
    /// The total number of congestion controlled bytes sent during the
    /// connection.
    total_bytes_sent: usize,
    total_bytes_acked: usize,
    total_bytes_lost: usize,
    total_bytes_neutered: usize,
    last_sent_packet: u64,
    last_acked_packet: u64,
    is_app_limited: bool,
    last_acked_packet_ack_time: Instant,
    total_bytes_sent_at_last_acked_packet: usize,
    last_acked_packet_sent_time: Instant,
    recent_ack_points: RecentAckPoints,
    a0_candidates: VecDeque<AckPoint>,
    connection_state_map: ConnectionStateMap<ConnectionStateOnSentPacket>,
    max_ack_height_tracker: MaxAckHeightTracker,
    /// The packet that will be acknowledged after this one will cause the
    /// sampler to exit the app-limited phase.
    end_of_app_limited_phase: Option<u64>,
    overestimate_avoidance: bool,
    // If true, apply the fix to A0 point selection logic so the
    // implementation is consistent with the behavior of the
    // google/quiche implementation.
    choose_a0_point_fix: bool,
    limit_max_ack_height_tracker_by_send_rate: bool,

    total_bytes_acked_after_last_ack_event: usize,
}

/// A subset of [`ConnectionStateOnSentPacket`] which is returned
/// to the caller when the packet is acked or lost.
#[derive(Debug, Default, Clone, Copy)]
pub struct SendTimeState {
    /// Whether other states in this object is valid.
    pub is_valid: bool,
    /// Whether the sender is app limited at the time the packet was sent.
    /// App limited bandwidth sample might be artificially low because the
    /// sender did not have enough data to send in order to saturate the
    /// link.
    pub is_app_limited: bool,
    /// Total number of sent bytes at the time the packet was sent.
    /// Includes the packet itself.
    pub total_bytes_sent: usize,
    /// Total number of acked bytes at the time the packet was sent.
    pub total_bytes_acked: usize,
    /// Total number of lost bytes at the time the packet was sent.
    #[allow(dead_code)]
    pub total_bytes_lost: usize,
    /// Total number of inflight bytes at the time the packet was sent.
    /// Includes the packet itself.
    /// It should be equal to `total_bytes_sent` minus the sum of
    /// `total_bytes_acked`, `total_bytes_lost` and total neutered bytes.
    pub bytes_in_flight: usize,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
struct ExtraAckedEvent {
    /// The excess bytes acknowlwedged in the time delta for this event.
    extra_acked: usize,
    /// The bytes acknowledged and time delta from the event.
    bytes_acked: usize,
    time_delta: Duration,
    /// The round trip of the event.
    round: usize,
}

// BandwidthSample holds per-packet rate measurements
// This is the internal struct used by BandwidthSampler to track rates
struct BandwidthSample {
    /// The bandwidth at that particular sample.
    bandwidth: Bandwidth,
    /// The RTT measurement at this particular sample.  Does not correct for
    /// delayed ack time.
    rtt: Duration,
    /// `send_rate` is computed from the current packet being acked('P') and
    /// an earlier packet that is acked before P was sent.
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#name-send-rate>
    send_rate: Option<Bandwidth>,
    // ack_rate tracks the acknowledgment rate for this sample
    /// `ack_rate` is computed as bytes_acked_delta / time_delta between ack
    /// points. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#name-ack-rate>
    ack_rate: Bandwidth,
    /// States captured when the packet was sent.
    state_at_send: SendTimeState,
}

/// [`AckPoint`] represents a point on the ack line.
#[derive(Debug, Clone, Copy)]
struct AckPoint {
    ack_time: Instant,
    total_bytes_acked: usize,
}

/// [`RecentAckPoints`] maintains the most recent 2 ack points at distinct
/// times.
#[derive(Debug, Default)]
struct RecentAckPoints {
    ack_points: [Option<AckPoint>; 2],
}

// [`ConnectionStateOnSentPacket`] represents the information about a sent
// packet and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
#[derive(Debug)]
struct ConnectionStateOnSentPacket {
    /// Time at which the packet is sent.
    sent_time: Instant,
    /// Size of the packet.
    size: usize,
    /// The value of [`BandwidthSampler::total_bytes_sent_at_last_acked_packet`]
    /// at the time the packet was sent.
    total_bytes_sent_at_last_acked_packet: usize,
    /// The value of [`BandwidthSampler::last_acked_packet_sent_time`] at the
    /// time the packet was sent.
    last_acked_packet_sent_time: Instant,
    /// The value of [`BandwidthSampler::last_acked_packet_ack_time`] at the
    /// time the packet was sent.
    last_acked_packet_ack_time: Instant,
    /// Send time states that are returned to the congestion controller when the
    /// packet is acked or lost.
    send_time_state: SendTimeState,
}

/// [`MaxAckHeightTracker`] is part of the [`BandwidthSampler`]. It is called
/// after every ack event to keep track the degree of ack
/// aggregation(a.k.a "ack height").
#[derive(Debug)]
struct MaxAckHeightTracker {
    /// Tracks the maximum number of bytes acked faster than the estimated
    /// bandwidth.
    max_ack_height_filter: WindowedFilter<ExtraAckedEvent, usize, usize>,
    /// The time this aggregation started and the number of bytes acked during
    /// it.
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: usize,
    /// The last sent packet number before the current aggregation epoch
    /// started.
    last_sent_packet_number_before_epoch: u64,
    /// The number of ack aggregation epochs ever started, including the ongoing
    /// one. Stats only.
    num_ack_aggregation_epochs: u64,
    ack_aggregation_bandwidth_threshold: f64,
    start_new_aggregation_epoch_after_full_round: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

/// Measurements collected from a congestion event, used for bandwidth
/// estimation and congestion control in BBR.
#[derive(Default)]
pub(crate) struct CongestionEventSample {
    /// The maximum bandwidth sample from all acked packets.
    pub sample_max_bandwidth: Option<Bandwidth>,
    /// Whether [`Self::sample_max_bandwidth`] is from a app-limited sample.
    pub sample_is_app_limited: bool,
    /// The minimum rtt sample from all acked packets.
    pub sample_rtt: Option<Duration>,
    /// For each packet p in acked packets, this is the max value of
    /// INFLIGHT(p), where INFLIGHT(p) is the number of bytes acked while p
    /// is inflight.
    pub sample_max_inflight: usize,
    /// The send state of the largest packet in acked_packets, unless it is
    /// empty. If acked_packets is empty, it's the send state of the largest
    /// packet in lost_packets.
    pub last_packet_send_state: SendTimeState,
    /// The number of extra bytes acked from this ack event, compared to what is
    /// expected from the flow's bandwidth. Larger value means more ack
    /// aggregation.
    pub extra_acked: usize,

    /// The maximum send rate observed across all acked packets in this event.
    /// Computed as bytes_sent_delta / time_delta between packet send times.
    pub sample_max_send_rate: Option<Bandwidth>,
    /// The maximum ack rate observed across all acked packets in this event.
    /// Computed as bytes_acked_delta / time_delta between ack times.
    pub sample_max_ack_rate: Option<Bandwidth>,
}

impl MaxAckHeightTracker {
    pub(crate) fn new(window: usize, overestimate_avoidance: bool) -> Self {
        MaxAckHeightTracker {
            max_ack_height_filter: WindowedFilter::new(window),
            aggregation_epoch_start_time: None,
            aggregation_epoch_bytes: 0,
            last_sent_packet_number_before_epoch: 0,
            num_ack_aggregation_epochs: 0,
            ack_aggregation_bandwidth_threshold: if overestimate_avoidance { 2.0 } else { 1.0 },
            start_new_aggregation_epoch_after_full_round: true,
            reduce_extra_acked_on_bandwidth_increase: true,
        }
    }

    #[allow(dead_code)]
    fn reset(&mut self, new_height: usize, new_time: usize) {
        self.max_ack_height_filter.reset(
            ExtraAckedEvent {
                extra_acked: new_height,
                bytes_acked: 0,
                time_delta: Duration::ZERO,
                round: new_time,
            },
            new_time,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: usize,
        last_sent_packet_number: u64,
        last_acked_packet_number: u64,
        ack_time: Instant,
        bytes_acked: usize,
    ) -> usize {
        let mut force_new_epoch = false;

        if self.reduce_extra_acked_on_bandwidth_increase && is_new_max_bandwidth {
            // Save and clear existing entries.
            let mut best = self.max_ack_height_filter.get_best().unwrap_or_default();
            let mut second_best = self
                .max_ack_height_filter
                .get_second_best()
                .unwrap_or_default();
            let mut third_best = self
                .max_ack_height_filter
                .get_third_best()
                .unwrap_or_default();
            self.max_ack_height_filter.clear();

            // Reinsert the heights into the filter after recalculating.
            let expected_bytes_acked =
                bandwidth_estimate.to_bytes_per_period(best.time_delta) as usize;
            if expected_bytes_acked < best.bytes_acked {
                best.extra_acked = best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter.update(best, best.round);
            }

            let expected_bytes_acked =
                bandwidth_estimate.to_bytes_per_period(second_best.time_delta) as usize;
            if expected_bytes_acked < second_best.bytes_acked {
                second_best.extra_acked = second_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter
                    .update(second_best, second_best.round);
            }

            let expected_bytes_acked =
                bandwidth_estimate.to_bytes_per_period(third_best.time_delta) as usize;
            if expected_bytes_acked < third_best.bytes_acked {
                third_best.extra_acked = third_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter
                    .update(third_best, third_best.round);
            }
        }

        // If any packet sent after the start of the epoch has been acked, start a
        // new epoch.
        if self.start_new_aggregation_epoch_after_full_round
            && last_acked_packet_number > self.last_sent_packet_number_before_epoch
        {
            force_new_epoch = true;
        }

        let epoch_start_time = match self.aggregation_epoch_start_time {
            Some(time) if !force_new_epoch => time,
            _ => {
                self.aggregation_epoch_bytes = bytes_acked;
                self.aggregation_epoch_start_time = Some(ack_time);
                self.last_sent_packet_number_before_epoch = last_sent_packet_number;
                self.num_ack_aggregation_epochs += 1;
                return 0;
            }
        };

        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let aggregation_delta = ack_time.duration_since(epoch_start_time);
        let expected_bytes_acked =
            bandwidth_estimate.to_bytes_per_period(aggregation_delta) as usize;
        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes
            <= (self.ack_aggregation_bandwidth_threshold * expected_bytes_acked as f64) as usize
        {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = bytes_acked;
            self.aggregation_epoch_start_time = Some(ack_time);
            self.last_sent_packet_number_before_epoch = last_sent_packet_number;
            self.num_ack_aggregation_epochs += 1;
            return 0;
        }

        self.aggregation_epoch_bytes += bytes_acked;

        // Compute how many extra bytes were delivered vs max bandwidth.
        let extra_bytes_acked = self.aggregation_epoch_bytes - expected_bytes_acked;

        let new_event = ExtraAckedEvent {
            extra_acked: extra_bytes_acked,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: aggregation_delta,
            round: 0,
        };

        self.max_ack_height_filter
            .update(new_event, round_trip_count);
        extra_bytes_acked
    }
}

impl From<(Instant, usize, usize, &BandwidthSampler)> for ConnectionStateOnSentPacket {
    fn from(
        (sent_time, size, bytes_in_flight, sampler): (Instant, usize, usize, &BandwidthSampler),
    ) -> Self {
        ConnectionStateOnSentPacket {
            sent_time,
            size,
            total_bytes_sent_at_last_acked_packet: sampler.total_bytes_sent_at_last_acked_packet,
            last_acked_packet_sent_time: sampler.last_acked_packet_sent_time,
            last_acked_packet_ack_time: sampler.last_acked_packet_ack_time,
            send_time_state: SendTimeState {
                is_valid: true,
                is_app_limited: sampler.is_app_limited,
                total_bytes_sent: sampler.total_bytes_sent,
                total_bytes_acked: sampler.total_bytes_acked,
                total_bytes_lost: sampler.total_bytes_lost,
                bytes_in_flight,
            },
        }
    }
}

impl RecentAckPoints {
    fn update(&mut self, ack_time: Instant, total_bytes_acked: usize) {
        assert!(total_bytes_acked >= self.ack_points[1].map(|p| p.total_bytes_acked).unwrap_or(0));

        self.ack_points[0] = self.ack_points[1];
        self.ack_points[1] = Some(AckPoint {
            ack_time,
            total_bytes_acked,
        });
    }

    fn clear(&mut self) {
        self.ack_points = Default::default();
    }

    fn most_recent(&self) -> Option<AckPoint> {
        self.ack_points[1]
    }

    fn less_recent_point(&self, choose_a0_point_fix: bool) -> Option<AckPoint> {
        if choose_a0_point_fix {
            self.ack_points[0]
                .filter(|ack_point| ack_point.total_bytes_acked > 0)
                .or(self.ack_points[1])
        } else {
            self.ack_points[0].or(self.ack_points[1])
        }
    }
}

impl BandwidthSampler {
    pub(crate) fn new(
        max_height_tracker_window_length: usize,
        overestimate_avoidance: bool,
        choose_a0_point_fix: bool,
    ) -> Self {
        BandwidthSampler {
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            total_bytes_neutered: 0,
            total_bytes_sent_at_last_acked_packet: 0,
            last_acked_packet_sent_time: Instant::now(),
            last_acked_packet_ack_time: Instant::now(),
            is_app_limited: true,
            connection_state_map: ConnectionStateMap::default(),
            max_ack_height_tracker: MaxAckHeightTracker::new(
                max_height_tracker_window_length,
                overestimate_avoidance,
            ),
            total_bytes_acked_after_last_ack_event: 0,
            overestimate_avoidance,
            choose_a0_point_fix,
            limit_max_ack_height_tracker_by_send_rate: false,

            last_sent_packet: 0,
            last_acked_packet: 0,
            recent_ack_points: RecentAckPoints::default(),
            a0_candidates: VecDeque::new(),
            end_of_app_limited_phase: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_app_limited(&self) -> bool {
        self.is_app_limited
    }

    pub(crate) fn on_packet_sent(
        &mut self,
        sent_time: Instant,
        packet_number: u64,
        bytes: usize,
        bytes_in_flight: usize,
        has_retransmittable_data: bool,
    ) {
        self.last_sent_packet = packet_number;

        if !has_retransmittable_data {
            return;
        }

        self.total_bytes_sent += bytes;

        // If there are no packets in flight, the time at which the new
        // transmission opens can be treated as the A_0 point for the
        // purpose of bandwidth sampling. This underestimates bandwidth to
        // some extent, and produces some artificially low samples for
        // most packets in flight, but it provides with samples at
        // important points where we would not have them otherwise, most
        // importantly at the beginning of the connection.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = sent_time;
            if self.overestimate_avoidance {
                self.recent_ack_points.clear();
                self.recent_ack_points
                    .update(sent_time, self.total_bytes_acked);
                self.a0_candidates.clear();
                self.a0_candidates
                    .push_back(self.recent_ack_points.most_recent().unwrap());
            }

            self.total_bytes_sent_at_last_acked_packet = self.total_bytes_sent;

            // In this situation ack compression is not a concern, set send rate
            // to effectively infinite.
            self.last_acked_packet_sent_time = sent_time;
        }

        self.connection_state_map.insert(
            packet_number,
            (sent_time, bytes, bytes_in_flight + bytes, &*self).into(),
        );
    }

    pub(crate) fn on_packet_neutered(&mut self, packet_number: u64) {
        if let Some(pkt) = self.connection_state_map.take(packet_number) {
            self.total_bytes_neutered += pkt.size;
        }
    }

    pub(crate) fn on_congestion_event(
        &mut self,
        ack_time: Instant,
        acked_packets: &[Acked],
        lost_packets: &[Lost],
        mut max_bandwidth: Option<Bandwidth>,
        est_bandwidth_upper_bound: Bandwidth,
        round_trip_count: usize,
    ) -> CongestionEventSample {
        let mut last_lost_packet_send_state = SendTimeState::default();
        let mut last_acked_packet_send_state = SendTimeState::default();
        let mut last_lost_packet_num = 0u64;
        let mut last_acked_packet_num = 0u64;

        for packet in lost_packets {
            let send_state = self.on_packet_lost(packet.packet_number, packet.bytes_lost);
            if send_state.is_valid {
                last_lost_packet_send_state = send_state;
                last_lost_packet_num = packet.packet_number;
            }
        }

        if acked_packets.is_empty() {
            // Only populate send state for a loss-only event.
            return CongestionEventSample {
                last_packet_send_state: last_lost_packet_send_state,
                ..Default::default()
            };
        }

        let mut event_sample = CongestionEventSample::default();

        let mut max_send_rate = None;
        let mut max_ack_rate = None;
        for packet in acked_packets {
            let sample = match self.on_packet_acknowledged(ack_time, packet.pkt_num) {
                Some(sample) if sample.state_at_send.is_valid => sample,
                _ => continue,
            };

            last_acked_packet_send_state = sample.state_at_send;
            last_acked_packet_num = packet.pkt_num;

            event_sample.sample_rtt = Some(
                sample
                    .rtt
                    .min(*event_sample.sample_rtt.get_or_insert(sample.rtt)),
            );

            if Some(sample.bandwidth) > event_sample.sample_max_bandwidth {
                event_sample.sample_max_bandwidth = Some(sample.bandwidth);
                event_sample.sample_is_app_limited = sample.state_at_send.is_app_limited;
            }
            max_send_rate = max_send_rate.max(sample.send_rate);
            max_ack_rate = max_ack_rate.max(Some(sample.ack_rate));

            let inflight_sample =
                self.total_bytes_acked - last_acked_packet_send_state.total_bytes_acked;
            if inflight_sample > event_sample.sample_max_inflight {
                event_sample.sample_max_inflight = inflight_sample;
            }
        }

        if !last_lost_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_acked_packet_send_state;
        } else if !last_acked_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_lost_packet_send_state;
        } else {
            // If two packets are inflight and an alarm is armed to lose a packet
            // and it wakes up late, then the first of two in flight packets could
            // have been acknowledged before the wakeup, which re-evaluates loss
            // detection, and could declare the later of the two lost.
            event_sample.last_packet_send_state = if last_acked_packet_num > last_lost_packet_num {
                last_acked_packet_send_state
            } else {
                last_lost_packet_send_state
            };
        }

        let is_new_max_bandwidth = event_sample.sample_max_bandwidth > max_bandwidth;
        max_bandwidth = event_sample.sample_max_bandwidth.max(max_bandwidth);

        if self.limit_max_ack_height_tracker_by_send_rate {
            max_bandwidth = max_bandwidth.max(max_send_rate);
        }

        let bandwidth_estimate = if let Some(max_bandwidth) = max_bandwidth {
            max_bandwidth.min(est_bandwidth_upper_bound)
        } else {
            est_bandwidth_upper_bound
        };

        event_sample.extra_acked =
            self.on_ack_event_end(bandwidth_estimate, is_new_max_bandwidth, round_trip_count);

        event_sample.sample_max_send_rate = max_send_rate;
        event_sample.sample_max_ack_rate = max_ack_rate;

        event_sample
    }

    fn on_packet_lost(&mut self, packet_number: u64, bytes_lost: usize) -> SendTimeState {
        let mut send_time_state = SendTimeState::default();

        self.total_bytes_lost += bytes_lost;
        if let Some(state) = self.connection_state_map.take(packet_number) {
            send_time_state = state.send_time_state;
            send_time_state.is_valid = true;
        }

        send_time_state
    }

    fn on_ack_event_end(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: usize,
    ) -> usize {
        let newly_acked_bytes =
            self.total_bytes_acked - self.total_bytes_acked_after_last_ack_event;

        if newly_acked_bytes == 0 {
            return 0;
        }

        self.total_bytes_acked_after_last_ack_event = self.total_bytes_acked;
        let extra_acked = self.max_ack_height_tracker.update(
            bandwidth_estimate,
            is_new_max_bandwidth,
            round_trip_count,
            self.last_sent_packet,
            self.last_acked_packet,
            self.last_acked_packet_ack_time,
            newly_acked_bytes,
        );
        // If `extra_acked` is zero, i.e. this ack event marks the start of a new
        // ack aggregation epoch, save `less_recent_point`, which is the
        // last ack point of the previous epoch, as a A0 candidate.
        if self.overestimate_avoidance && extra_acked == 0 {
            self.a0_candidates.push_back(
                self.recent_ack_points
                    .less_recent_point(self.choose_a0_point_fix)
                    .unwrap(),
            );
        }

        extra_acked
    }

    fn on_packet_acknowledged(
        &mut self,
        ack_time: Instant,
        packet_number: u64,
    ) -> Option<BandwidthSample> {
        self.last_acked_packet = packet_number;
        let sent_packet = self.connection_state_map.take(packet_number)?;

        self.total_bytes_acked += sent_packet.size;
        self.total_bytes_sent_at_last_acked_packet = sent_packet.send_time_state.total_bytes_sent;
        self.last_acked_packet_sent_time = sent_packet.sent_time;
        self.last_acked_packet_ack_time = ack_time;
        if self.overestimate_avoidance {
            self.recent_ack_points
                .update(ack_time, self.total_bytes_acked);
        }

        if self.is_app_limited {
            // Exit app-limited phase in two cases:
            // (1) end_of_app_limited_phase is not initialized, i.e., so far all
            // packets are sent while there are buffered packets or pending data.
            // (2) The current acked packet is after the sent packet marked as the
            // end of the app limit phase.
            if self.end_of_app_limited_phase.is_none()
                || Some(packet_number) > self.end_of_app_limited_phase
            {
                self.is_app_limited = false;
            }
        }

        // No send rate indicates that the sampler is supposed to discard the
        // current send rate sample and use only the ack rate.
        let send_rate = if sent_packet.sent_time > sent_packet.last_acked_packet_sent_time {
            Some(Bandwidth::from_bytes_and_time_delta(
                sent_packet.send_time_state.total_bytes_sent
                    - sent_packet.total_bytes_sent_at_last_acked_packet,
                sent_packet.sent_time - sent_packet.last_acked_packet_sent_time,
            ))
        } else {
            None
        };

        let a0 = if self.overestimate_avoidance {
            Self::choose_a0_point(
                &mut self.a0_candidates,
                sent_packet.send_time_state.total_bytes_acked,
                self.choose_a0_point_fix,
            )
        } else {
            None
        };

        let a0 = a0.unwrap_or(AckPoint {
            ack_time: sent_packet.last_acked_packet_ack_time,
            total_bytes_acked: sent_packet.send_time_state.total_bytes_acked,
        });

        // During the slope calculation, ensure that ack time of the current
        // packet is always larger than the time of the previous packet,
        // otherwise division by zero or integer underflow can occur.
        if ack_time <= a0.ack_time {
            return None;
        }

        let ack_rate = Bandwidth::from_bytes_and_time_delta(
            self.total_bytes_acked - a0.total_bytes_acked,
            ack_time.duration_since(a0.ack_time),
        );

        let bandwidth = if let Some(send_rate) = send_rate {
            send_rate.min(ack_rate)
        } else {
            ack_rate
        };

        // Note: this sample does not account for delayed acknowledgement time.
        // This means that the RTT measurements here can be artificially
        // high, especially on low bandwidth connections.
        let rtt = ack_time.duration_since(sent_packet.sent_time);

        Some(BandwidthSample {
            bandwidth,
            rtt,
            send_rate,
            ack_rate,
            state_at_send: SendTimeState {
                is_valid: true,
                ..sent_packet.send_time_state
            },
        })
    }

    fn choose_a0_point(
        a0_candidates: &mut VecDeque<AckPoint>,
        total_bytes_acked: usize,
        choose_a0_point_fix: bool,
    ) -> Option<AckPoint> {
        if a0_candidates.is_empty() {
            return None;
        }

        while let Some(candidate) = a0_candidates.get(1) {
            if candidate.total_bytes_acked > total_bytes_acked {
                if choose_a0_point_fix {
                    break;
                } else {
                    return Some(*candidate);
                }
            }
            a0_candidates.pop_front();
        }

        Some(a0_candidates[0])
    }

    pub(crate) fn total_bytes_acked(&self) -> usize {
        self.total_bytes_acked
    }

    pub(crate) fn total_bytes_lost(&self) -> usize {
        self.total_bytes_lost
    }

    #[allow(dead_code)]
    pub(crate) fn reset_max_ack_height_tracker(&mut self, new_height: usize, new_time: usize) {
        self.max_ack_height_tracker.reset(new_height, new_time);
    }

    pub(crate) fn max_ack_height(&self) -> Option<usize> {
        self.max_ack_height_tracker
            .max_ack_height_filter
            .get_best()
            .map(|b| b.extra_acked)
    }

    pub(crate) fn on_app_limited(&mut self) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = Some(self.last_sent_packet);
    }

    pub(crate) fn remove_obsolete_packets(&mut self, least_acked: u64) {
        // A packet can become obsolete when it is removed from
        // QuicUnackedPacketMap's view of inflight before it is acked or
        // marked as lost. For example, when
        // QuicSentPacketManager::RetransmitCryptoPackets retransmits a crypto
        // packet, the packet is removed from QuicUnackedPacketMap's
        // inflight, but is not marked as acked or lost in the
        // BandwidthSampler.
        self.connection_state_map.remove_obsolete(least_acked);
    }
}

// vendored #[cfg(test)] mod blocks stripped — relied on rstest + quiche test infra
