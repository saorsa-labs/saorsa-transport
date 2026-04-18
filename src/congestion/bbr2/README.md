# BBRv2 — ported from cloudflare/quiche

Saorsa's BBRv2 congestion controller. The state machine (startup, drain,
probe_bw with UP/DOWN/CRUISE/REFILL phases, probe_rtt) and per-packet
bandwidth sampler are vendored verbatim from cloudflare/quiche; the only
net-new code here is the shim types and the `Bbr2Adapter` that implements
saorsa's streaming `Controller` trait on top of quiche's batched
`CongestionControl` interface.

## Usage

```rust
let config = P2pConfig {
    congestion_algorithm: CongestionAlgorithm::Bbr2,
    // ...
};
```

Or via the raw factory:

```rust
let mut cc = crate::congestion::Bbr2Config::default();
cc.initial_window(200 * 1200);
let factory: Arc<dyn ControllerFactory + Send + Sync> = Arc::new(cc);
```

## Licensing & attribution

All vendored files preserve their original **Chromium BSD-2-Clause** +
**Cloudflare BSD-2-Clause** copyright headers. Saorsa's modifications
(imports, shim types, adapter, test stripping) are marked in each file
and are dual-licensed under saorsa-transport's license.

## File inventory

| File | LoC | Origin | Role |
|---|---:|---|---|
| `mod.rs` | ~850 | `gcongestion/bbr2.rs` | Top-level `BBRv2` struct + `Params` + `DEFAULT_PARAMS` + `impl CongestionControl`. |
| `adapter.rs` | ~240 | saorsa original | `Bbr2Adapter` + `Bbr2Config` — implements saorsa's `Controller`. |
| `types.rs` | ~185 | saorsa original | Shim types (`Acked`, `Lost`, `BbrParams`, `RttStats`, `CongestionControl` trait, etc.). |
| `bandwidth.rs` | 355 | `recovery/bandwidth.rs` | `Bandwidth` newtype. |
| `bandwidth_sampler.rs` | ~860 | `gcongestion/bbr/bandwidth_sampler.rs` | Per-packet delivery rate sampler. Vendored tests stripped. |
| `network_model.rs` | 784 | `gcongestion/bbr2/network_model.rs` | `BBRv2NetworkModel` (bandwidth/rtt/inflight tracking). |
| `mode.rs` | ~300 | `gcongestion/bbr2/mode.rs` | Mode enum + `ModeImpl` trait (via `enum_dispatch`). |
| `startup.rs` | ~190 | `gcongestion/bbr2/startup.rs` | Startup mode with loss-aware exit. |
| `drain.rs` | ~120 | `gcongestion/bbr2/drain.rs` | Drain mode. |
| `probe_bw.rs` | ~610 | `gcongestion/bbr2/probe_bw.rs` | ProbeBW with UP/DOWN/CRUISE/REFILL cycle. |
| `probe_rtt.rs` | ~155 | `gcongestion/bbr2/probe_rtt.rs` | ProbeRTT mode. |
| `windowed_filter.rs` | 158 | `gcongestion/bbr/windowed_filter.rs` | Generic windowed max/min filter. |
| `smoke_tests.rs` | ~120 | saorsa original | Plumbing tests for the adapter. |

## Adapter semantics (saorsa's `Controller` → quiche's batched API)

saorsa calls into the controller per-packet:
- `on_sent(now, bytes, pn)` — for each sent packet
- `on_ack(now, sent, bytes, app_limited, rtt)` — for each acked packet
- `on_end_acks(now, in_flight, app_limited, largest_pn)` — at end of ack batch
- `on_congestion_event(now, sent, is_persistent, lost_bytes)` — for aggregated loss

The vendored BBRv2 wants a single batched call:
- `on_congestion_event(rtt_updated, prior_in_flight, bytes_in_flight, event_time, &[Acked], &[Lost], least_unacked, ...)`

The adapter buffers `Acked`/`Lost` entries and flushes at the two natural
batch boundaries in saorsa's flow:
1. `on_end_acks` → flush the ack batch (lost list is usually empty here;
   saorsa's `detect_lost_packets` runs afterwards).
2. `on_congestion_event` → append to the loss list, then flush.

Because saorsa's ack-then-loss split spans two flushes within the same
ack-processing round, the adapter issues up to two `BBRv2::on_congestion_event`
calls per RTT instead of one batched call. BBRv2 handles this — the minor
fidelity cost is that the sampler can't correlate same-round acks and
losses in a single event.

## Known fidelity gaps vs upstream quiche

These are the places where the adapter trades accuracy for interface
compatibility with saorsa's existing `Controller` trait. Fixing them
requires extending saorsa's trait (cross-cutting changes in
`src/congestion.rs` + `src/connection/mod.rs`):

1. **No packet number on ack.** saorsa's `Controller::on_ack` doesn't carry
   `pn: u64`. The adapter falls back to using `max_sent_packet_number`
   as a proxy key when pushing `Acked { pkt_num, time_sent }`. The
   sampler is robust to unknown pkt_nums (it just skips them) but loses
   per-packet delivery-rate precision as a result.

2. **No per-packet loss info.** saorsa's `on_congestion_event` gives a
   single aggregate `lost_bytes`. The adapter wraps this in a single
   synthetic `Lost` entry keyed on `max_sent_packet_number`. BBRv2's
   `inflight_hi_on_loss` reduction still fires correctly from the
   aggregate byte count; only the sampler's per-packet loss-rate
   tracking is degraded.

3. **No `bytes_in_flight` passed through.** saorsa's `on_sent` and
   `on_ack` don't include the connection's in-flight counter. The
   adapter tracks its own `bytes_in_flight` by summing sent/acked/lost
   bytes and resyncs to the authoritative value in `on_end_acks`.

Both (1) and (2) are blocked on a single trait change — add `pn: u64` to
`Controller::on_ack` and take `&[(u64, u64)]` (pn, bytes) in
`on_congestion_event` — which would be a small cross-cutting refactor in
`src/congestion.rs` and `src/connection/mod.rs`.

## What this gets you over saorsa's BBRv1

1. **Loss-aware startup exit.** BBRv1 exits startup only on 3 rounds of
   no bandwidth growth; BBRv2 also exits on cumulative loss count
   (`startup_full_loss_count = 8`), which prevents the "startup
   overshoots on real wireless links" failure mode.
2. **`inflight_hi`/`inflight_lo` short-term caps** cap bytes-in-flight on
   loss events, preventing BBRv1's infamous bufferbloat-plus-tail-drop
   behaviour on shared queues.
3. **Reno coexistence** (`enable_reno_coexistence = true` by default):
   probe-max-rounds scales with BDP, so BBRv2 shares bottlenecks fairly
   with Reno/CUBIC flows.
4. **Per-packet delivery rate sampler** handles stretch-ACKs and ack
   coalescing correctly (modulo the pkt_num proxy gap above).

## Default

BBRv2 is the default as of this port (`CongestionAlgorithm::Bbr2`). To
opt back into BBRv1, set `congestion_algorithm: CongestionAlgorithm::Bbr`
in the `P2pConfig`; CUBIC is available as
`CongestionAlgorithm::Cubic` for comparison or when probing an unknown
path.
