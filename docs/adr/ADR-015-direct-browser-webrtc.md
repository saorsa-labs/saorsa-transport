# ADR-015: Direct Browser Connections over WebRTC

## Status

Proposed, 2026-09-07. Implementation: [PR #160](https://github.com/WithAutonomi/saorsa-transport/pull/160).

## Context

Browsers cannot open the raw UDP sockets required by Saorsa's native QUIC
transport. Browser clients need a direct connection to a public node without
an HTTP data gateway, a signaling service, DNS, or public-CA certificates.
The node-to-node QUIC transport retains its native NAT traversal extensions
and post-quantum authentication.

## Decision

Offer an opt-in `webrtc-direct` listener on its own UDP socket. The browser
transport uses ICE-lite, DTLS, SCTP, and reliable ordered DataChannels. This
is a browser-specific exception to the native transport's exclusion of
STUN/ICE; it does not introduce STUN servers, TURN, or ICE into QUIC traversal.

Advertise a literal IPv4 or IPv6 address, nonzero UDP port, and stable SHA-256
DTLS certificate hash. Browser application endpoints additionally carry the
expected 32-byte ANT peer ID. The browser synthesizes an ICE-lite SDP answer
using that certificate pin. The v2 ICE username fragment carries the browser's
original ICE password, allowing the listener to recover the credentials from
the first STUN request without modifying the browser's local offer. The
listener also recognizes the existing v1 profile. These credentials are public
on the wire; ICE message integrity is not peer authentication in this profile.
The certificate pin and the independent PQ session supply authentication and
confidentiality. A fresh association must complete a signed STUN Binding round
trip to its observed source before RTC allocation. The listener validates method,
class, MESSAGE-INTEGRITY and FINGERPRINT. Challenge transactions carry a keyed, source-bound 96-bit cookie valid for the
current or previous two-second interval. Unanswered challenges retain no state.
A returned cookie is cached for at most two seconds; the next ordinary ICE
request supplies the credentials used to check the response MESSAGE-INTEGRITY
before admission. This cache is bounded globally and per canonical IP, evicts
the oldest returned proof when full, and contains no RTC state. ICE request
retransmission completes admission without browser-specific signalling.
Challenges never exceed the triggering packet size. This is reachability proof,
not protection against an on-path attacker or many genuinely reachable sources.
Existing associations are pinned to their validated source; moving to a new
source requires a new association rather than credential-based rebinding.

The P-256 DTLS certificate is a transport credential, not an ANT identity.
New certificates have five-year X.509 validity on every architecture. Runtime
expiry is derived from the signed X.509 notAfter value, not upstream's artificial
two-day ARM expiry. Loading old PEM files preserves their key and certificate pin
while ignoring that advisory EXPIRES header. Actually expired or not-yet-valid
certificates are rejected; operators must replace and re-advertise those pins.
Applications must establish the portable `saorsa_transport::webrtc` post-quantum session
before accepting application RPCs: ephemeral ML-KEM-768, an ML-DSA-65 signed
transcript bound to the expected peer ID, and ChaCha20-Poly1305 records with
independent direction keys and strict sequence validation. The native listener
API exposes raw binary channels; that API alone does not enforce the
application handshake. Browser protocol v5, framing, payment metadata, and
signature primitives live in the portable module so native and WASM adapters
share the same contract. Payment verification and RPC authorization remain
application responsibilities.

Extended address encoding reserves type 12 for WebRTC; type 11 remains
reserved for the earlier WebTransport experiment. Unknown layouts are rejected
before payload decoding. This is not forward-compatible with old decoders that
assume unknown types are QUIC: do not send extended frames to those peers.
`advertise_transport_address` currently only transmits socket advertisements and
returns an error for WebRTC and other unsupported transports. In this stack,
WebRTC descriptors travel through saorsa-core’s V2 peer-record address plane. Browser endpoints are advertised descriptors and do
not become native QUIC dial targets through `as_socket_addr()`.

### Admission and lifecycle

- Apply configurable global/per-IP association limits before RTC allocation;
  ant-node supplies its configured connection limits. Queued associations and
  incomplete RTC handshakes expire after ten seconds. Queue bounds do not replace
  application first-RPC deadlines. Dropped associations own asynchronous cleanup.
- Inbound construction remains owned by the listener across cancelled `accept`
  futures. Setup errors and dropped results close RTC and release mux state.
- Route STUN requests by ICE credential before consulting source-address
  mappings so a new browser association can reuse a UDP source port.
- Reject unordered channels and either partial-reliability mode. Reset rejected
  streams after SCTP attaches them; closing the channel before attachment does
  not reset the peer's stream in the current WebRTC dependency.
- Limit each binary DataChannel message to 16 KiB. Larger application frames
  use bounded framing and fragmentation in the portable protocol and adapters.
- Own each outbound receive task with a drop guard during setup and after
  connection establishment, so cancelling a dial releases its socket.
- Make listener shutdown wake acceptance and make closed channel acceptance
  terminal, including repeated calls and queued associations.

### Dependencies

Keep ICE, DTLS, and SCTP behind the optional `webrtc-direct` native feature.
The `webrtc` feature exposes `saorsa_transport::webrtc` and builds for
`wasm32-unknown-unknown` with default features disabled. Its cryptographic,
framing, and payment primitives are versioned together with the application
profile. The native listener lives in `webrtc::direct`; the existing
`webrtc_direct` path remains a compatibility re-export. The standalone
`saorsa-webrtc` package is removed now that transport has a portable feature
boundary.

The current optional DTLS dependency uses unmaintained `bincode 1.3.3` for
state export/import APIs that Saorsa does not invoke. The maintenance-only
advisory has a documented exception in `deny.toml`; vulnerability checks
remain enabled. [Issue #164](https://github.com/WithAutonomi/saorsa-transport/issues/164)
tracks removal of the dependency and exception.

## Consequences

Browsers can transfer application data directly to public nodes while pinning
the transport certificate and authenticating the ANT identity independently.
The additional native dependency graph is opt-in, but deployments enabling it
must manage certificate persistence, UDP reachability, application admission,
and coordinated browser-protocol upgrades. Nodes without a public UDP path
need a future relay design; this decision does not provide that path.

Tests cover certificate persistence, address rejection and round trips, v2
native interoperability, both partial-reliability modes, cancellation, stale
UDP mappings, pending bounds, shutdown, PQ authentication, replay rejection,
and portable framing. Downstream devnet and real-browser checks validate the
combined application stack before rollout.

## Alternatives Considered

- An HTTP data gateway would route all browser file traffic through a service.
- WebTransport would require a different browser trust and deployment model.
- General WebRTC signaling and TURN would add coordination and relay services
  outside the scope of direct connections to public nodes.

## Mitigation / Rollback

Leave `webrtc-direct` disabled or stop advertising and binding its listener.
Revert the coordinated browser profile pins when reverting its wire contract.
No stored record format or existing native QUIC wire behavior changes.
