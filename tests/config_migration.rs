//! End-to-End Integration Test for Config Address Migration
//!
//! This test validates backward compatibility and correctness when migrating
//! from SocketAddr to TransportAddr in configuration types.
//!
//! # Test Scenarios
//!
//! 1. **P2pConfig with old SocketAddr approach** - Verify auto-conversion via Into trait
//! 2. **P2pConfig with new TransportAddr approach** - Verify explicit TransportAddr usage
//! 3. **NodeConfig with TransportAddr** - Verify TransportAddr support
//! 4. **Config interoperability** - Verify configs produce expected results when used together
//!
//! This ensures the migration maintains 100% backward compatibility while enabling
//! multi-transport functionality.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_transport::transport::{TransportAddr, TransportType};
use saorsa_transport::{NodeConfig, P2pConfig};
use std::net::SocketAddr;

// ============================================================================
// P2pConfig Migration Tests
// ============================================================================

#[test]
fn test_p2p_config_old_socket_addr_approach() {
    // Scenario 1: Old code using SocketAddr directly
    // The Into trait should auto-convert to TransportAddr::Quic

    let bind_socket: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");

    let config = P2pConfig::builder()
        .bind_addr(bind_socket) // Auto-converts via Into<TransportAddr>
        .build()
        .expect("Failed to build P2pConfig");

    // Verify bind_addr was auto-converted
    assert!(config.bind_addr.is_some());
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(bind_socket),
        "bind_addr should preserve SocketAddr via TransportAddr::Quic"
    );
    assert_eq!(
        config.bind_addr.as_ref().unwrap().transport_type(),
        TransportType::Quic
    );
}

#[test]
fn test_p2p_config_new_transport_addr_approach() {
    // Scenario 2: New code using TransportAddr explicitly
    // This enables multi-transport functionality

    let bind_addr = TransportAddr::Quic("0.0.0.0:9000".parse().expect("valid addr"));

    let config = P2pConfig::builder()
        .bind_addr(bind_addr.clone())
        .build()
        .expect("Failed to build P2pConfig");

    // Verify bind_addr preserved
    assert_eq!(config.bind_addr, Some(bind_addr));
}

#[test]
fn test_p2p_config_ipv6_addresses() {
    // Verify IPv6 addresses work correctly in both approaches

    let ipv6_bind: SocketAddr = "[::]:9000".parse().expect("valid IPv6 addr");

    // Old approach (auto-convert)
    let config_old = P2pConfig::builder()
        .bind_addr(ipv6_bind)
        .build()
        .expect("Failed to build config");

    // New approach (explicit)
    let config_new = P2pConfig::builder()
        .bind_addr(TransportAddr::Quic(ipv6_bind))
        .build()
        .expect("Failed to build config");

    // Both approaches should produce identical results
    assert_eq!(config_old.bind_addr, config_new.bind_addr);

    // Verify IPv6 addresses preserved
    assert_eq!(
        config_new.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv6_bind)
    );
}

// ============================================================================
// NodeConfig Migration Tests
// ============================================================================

#[test]
fn test_node_config_old_socket_addr_approach() {
    // Verify NodeConfig also supports SocketAddr via Into trait

    let bind_socket: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");

    let config = NodeConfig::builder().bind_addr(bind_socket).build();

    // Verify auto-conversion worked
    assert_eq!(
        config.bind_addr,
        Some(TransportAddr::from(bind_socket)),
        "bind_addr should auto-convert"
    );
}

#[test]
fn test_node_config_new_transport_addr_approach() {
    // Verify NodeConfig supports explicit TransportAddr

    let bind_addr = TransportAddr::Quic("0.0.0.0:0".parse().expect("valid addr"));

    let config = NodeConfig::builder().bind_addr(bind_addr.clone()).build();

    // Verify fields preserved
    assert_eq!(config.bind_addr, Some(bind_addr));
}

// ============================================================================
// Cross-Config Interoperability Tests
// ============================================================================

#[test]
fn test_p2p_and_node_config_equivalence() {
    // Verify P2pConfig and NodeConfig produce equivalent bind_addr for the same inputs

    let bind_socket: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(bind_socket)
        .build()
        .expect("Failed to build P2pConfig");

    let node_config = NodeConfig::builder().bind_addr(bind_socket).build();

    // Both configs should have equivalent bind addresses
    assert_eq!(p2p_config.bind_addr, node_config.bind_addr);
}

#[test]
fn test_to_nat_config_preserves_bind_addr() {
    // Verify P2pConfig::to_nat_config() correctly handles TransportAddr bind_addr

    let bind_addr: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(bind_addr)
        .build()
        .expect("Failed to build config");

    let nat_config = p2p_config.to_nat_config();

    // NatTraversalConfig should extract SocketAddr from TransportAddr::Quic
    assert_eq!(nat_config.bind_addr, Some(bind_addr));
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_ipv4_mapped_ipv6_address() {
    // Test IPv4-mapped IPv6 addresses (::ffff:192.0.2.1)
    // These should be handled correctly without confusion

    use std::net::{IpAddr, Ipv6Addr};

    // Create IPv4-mapped IPv6 address
    let ipv4_mapped = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)),
        8080,
    );

    let config = P2pConfig::builder()
        .bind_addr(ipv4_mapped)
        .build()
        .expect("Failed to build config");

    // Verify IPv4-mapped IPv6 addresses are preserved correctly
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv4_mapped),
        "IPv4-mapped IPv6 should be preserved"
    );
}

#[test]
fn test_port_zero_dynamic_allocation() {
    // Verify port 0 (dynamic allocation) works correctly

    let dynamic_port: SocketAddr = "0.0.0.0:0".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(dynamic_port)
        .build()
        .expect("Failed to build config");

    let node_config = NodeConfig::builder().bind_addr(dynamic_port).build();

    // Verify port 0 is preserved (OS will assign actual port at bind time)
    assert_eq!(
        p2p_config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(dynamic_port)
    );
    assert_eq!(
        node_config.bind_addr.unwrap().as_socket_addr(),
        Some(dynamic_port)
    );
}

#[test]
fn test_ipv6_with_scope_id() {
    // Test IPv6 addresses with scope IDs (zone indices)
    // e.g., fe80::1%eth0 or fe80::1%1

    use std::net::{Ipv6Addr, SocketAddrV6};

    // Link-local IPv6 with scope ID
    let ipv6_scoped = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        8080,
        0, // flowinfo
        1, // scope_id (interface index)
    ));

    let config = P2pConfig::builder()
        .bind_addr(ipv6_scoped)
        .build()
        .expect("Failed to build config");

    // Verify scope ID is preserved
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv6_scoped)
    );

    // Verify it's recognized as QUIC transport
    assert_eq!(
        config.bind_addr.as_ref().unwrap().transport_type(),
        TransportType::Quic
    );
}

// ============================================================================
// Backward Compatibility Regression Tests
// ============================================================================

#[test]
fn test_old_code_still_compiles() {
    // This test represents typical old user code to ensure zero breakage

    let addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid");

    // Old pattern 1: Direct SocketAddr to bind_addr
    let _config1 = P2pConfig::builder().bind_addr(addr).build().unwrap();

    // Old pattern 2: NodeConfig with SocketAddr
    let _node_config = NodeConfig::builder().bind_addr(addr).build();
}

#[test]
fn test_new_code_multi_transport() {
    // This test represents new user code using multi-transport features

    // Pattern 1: Explicit TransportAddr for clarity
    let _config1 = P2pConfig::builder()
        .bind_addr(TransportAddr::Quic(
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
        ))
        .build()
        .unwrap();

    // Pattern 2: NodeConfig with explicit TransportAddr
    let _config2 = NodeConfig::builder()
        .bind_addr(TransportAddr::Quic(
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
        ))
        .build();
}
