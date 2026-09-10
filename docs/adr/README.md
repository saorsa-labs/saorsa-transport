# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the saorsa-transport project.

## What are ADRs?

ADRs document significant architectural decisions made in the project. Each record captures the context, decision, and consequences to help future maintainers understand why things are the way they are.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001-link-transport-abstraction.md) | LinkTransport Trait Abstraction | Accepted | 2025-12-21 |
| [ADR-002](ADR-002-epsilon-greedy-bootstrap-cache.md) | Epsilon-Greedy Bootstrap Cache | Superseded | 2026-05-28 |
| [ADR-003](ADR-003-pure-post-quantum-cryptography.md) | Pure Post-Quantum Cryptography | Accepted | 2025-12-21 |
| [ADR-004](ADR-004-symmetric-p2p-architecture.md) | Symmetric P2P Architecture | Accepted | 2025-12-21 |
| [ADR-005](ADR-005-native-quic-nat-traversal.md) | Native QUIC NAT Traversal | Accepted | 2025-12-21 |
| [ADR-006](ADR-006-masque-relay-fallback.md) | MASQUE CONNECT-UDP Bind Relay | Accepted | 2025-12-21 |
| [ADR-007](ADR-007-local-only-hostkey.md) | Local-only HostKey for Local State Encryption | Amended | 2026-05-28 |
| [ADR-008](ADR-008-universal-connectivity-architecture.md) | Universal Connectivity Architecture | Accepted | 2025-12-26 |
| [ADR-009](ADR-009-masque-relay-data-plane.md) | MASQUE Relay Data Plane Implementation | Accepted | 2026-03-29 |
| [ADR-010](ADR-010-repository-ownership.md) | Repository Ownership under WithAutonomi | Accepted | 2026-05-29 |
| [ADR-011](ADR-011-stable-relay-port-reservations.md) | Stable Relay Port Reservations (Authenticated, Leased) | Proposed | 2026-06-24 |
| [ADR-012](ADR-012-keep-alive-dial-accept-split.md) | Keep-Alive on the Dialling Side Only | Proposed | 2026-08-14 |
| [ADR-013](ADR-013-relay-tunnel-teardown-ordering.md) | Relay Tunnel Teardown Ordering and Failure Classification | Proposed | 2026-08-19 |
| [ADR-014](ADR-014-accept-side-keep-alive-backstop.md) | Accept-Side Keep-Alive Backstop | Proposed | 2026-08-20 |
| [ADR-015](ADR-015-direct-browser-webrtc.md) | Direct Browser Connections over WebRTC | Proposed | 2026-09-07 |

## ADR Template

New ADRs should follow this structure:

```markdown
# ADR-N: Title

## Status
Proposed | Accepted | Deprecated | Superseded

## Context
Why this decision was necessary.

## Decision
What was chosen and why.

## Consequences
Benefits and trade-offs.

## Alternatives Considered
Other options and why rejected.

## References
Relevant commits, RFCs, code paths.
```

## Related Documentation

- [Architecture Overview](../architecture/ARCHITECTURE.md)
- [Symmetric P2P Design](../SYMMETRIC_P2P.md)
- [NAT Traversal Guide](../NAT_TRAVERSAL_GUIDE.md)
- [PQC Authentication Spec](../rfcs/saorsa-transport-pqc-authentication.md)
