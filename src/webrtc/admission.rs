// Copyright 2026 Saorsa Labs Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Stateless STUN reachability challenges; these do not authenticate peer identity.
use super::{IncomingAssociation, parse_profile_credentials, stun_ice_credentials};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use stun::agent::TransactionId;
use stun::attributes::{ATTR_ICE_CONTROLLED, ATTR_PRIORITY, ATTR_USERNAME};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use stun::textattrs::Username;
use tokio::time::Instant;

const PROBE_LIFETIME: Duration = Duration::from_secs(2);
const MAX_PROBES: usize = 256;
const MAX_PROBES_PER_IP: usize = 4;

struct ReturnedProof {
    message: Message,
    expires: Instant,
}

pub(super) struct Admission {
    secret: [u8; 32],
    born: Instant,
    verified: HashMap<SocketAddr, ReturnedProof>,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            secret: rand::random(),
            born: Instant::now(),
            verified: HashMap::new(),
        }
    }
}

pub(super) enum Decision {
    Ignore,
    Challenge(Vec<u8>),
    Admit(IncomingAssociation),
}

impl Admission {
    fn bucket(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.born).as_secs() / PROBE_LIFETIME.as_secs()
    }

    fn cookie(&self, source: SocketAddr, bucket: u64) -> TransactionId {
        let mut hash = blake3::Hasher::new_keyed(&self.secret);
        hash.update(b"saorsa-webrtc-reachability-v1");
        hash.update(source.to_string().as_bytes());
        hash.update(&bucket.to_be_bytes());
        let mut bytes = [0; 12];
        bytes.copy_from_slice(&hash.finalize().as_bytes()[..12]);
        TransactionId(bytes)
    }

    fn valid_cookie(&self, message: &Message, source: SocketAddr, now: Instant) -> bool {
        let bucket = self.bucket(now);
        [Some(bucket), bucket.checked_sub(1)]
            .into_iter()
            .flatten()
            .any(|bucket| {
                // Hash equality uses constant-time comparison, including this padded cookie.
                let mut expected = [0; 32];
                let mut received = [0; 32];
                expected[..12].copy_from_slice(&self.cookie(source, bucket).0);
                received[..12].copy_from_slice(&message.transaction_id.0);
                blake3::Hash::from_bytes(expected) == blake3::Hash::from_bytes(received)
            })
    }

    pub(super) fn expects_response(&self, packet: &[u8], source: SocketAddr) -> bool {
        let mut message = Message::new();
        packet.len() <= 512
            && message.unmarshal_binary(packet).is_ok()
            && message.typ == BINDING_SUCCESS
            && self.valid_cookie(&message, source, Instant::now())
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.verified.retain(|_, proof| proof.expires > now);
    }

    pub(super) fn receive(&mut self, packet: &[u8], source: SocketAddr, now: Instant) -> Decision {
        self.expire(now);
        let mut message = Message::new();
        if message.unmarshal_binary(packet).is_err() || FINGERPRINT.check(&message).is_err() {
            return Decision::Ignore;
        }
        if message.typ == BINDING_SUCCESS {
            if packet.len() > 512 || !self.valid_cookie(&message, source, now) {
                return Decision::Ignore;
            }
            // Only a returned source-bound cookie consumes memory. Retain its
            // integrity tag until the next ICE request supplies the credentials.
            let ip = super::super::source_ip_bucket(source.ip());
            let same_ip = self
                .verified
                .keys()
                .filter(|addr| super::super::source_ip_bucket(addr.ip()) == ip)
                .count();
            if !self.verified.contains_key(&source)
                && (same_ip >= MAX_PROBES_PER_IP || self.verified.len() >= MAX_PROBES)
            {
                let victim = self
                    .verified
                    .iter()
                    .filter(|(addr, _)| {
                        same_ip < MAX_PROBES_PER_IP
                            || super::super::source_ip_bucket(addr.ip()) == ip
                    })
                    .min_by_key(|(_, proof)| proof.expires)
                    .map(|(addr, _)| *addr);
                if let Some(victim) = victim {
                    self.verified.remove(&victim);
                }
            }
            self.verified.insert(
                source,
                ReturnedProof {
                    message,
                    expires: now + PROBE_LIFETIME,
                },
            );
            return Decision::Ignore;
        }
        if message.typ != BINDING_REQUEST {
            return Decision::Ignore;
        }
        let Some((server, client)) = stun_ice_credentials(packet) else {
            return Decision::Ignore;
        };
        let Some(credentials) = parse_profile_credentials(&server, &client) else {
            return Decision::Ignore;
        };
        if MessageIntegrity::new_short_term_integrity(server.clone())
            .check(&mut message)
            .is_err()
        {
            return Decision::Ignore;
        }
        if let Some(mut proof) = self.verified.remove(&source) {
            if self.valid_cookie(&proof.message, source, now)
                && MessageIntegrity::new_short_term_integrity(credentials.client_pwd.clone())
                    .check(&mut proof.message)
                    .is_ok()
            {
                return Decision::Admit(IncomingAssociation {
                    remote_addr: source,
                    server_ufrag: server,
                    client_ufrag: client,
                    client_pwd: credentials.client_pwd,
                    generation: None,
                });
            }
        }
        let mut challenge = Message::new();
        if challenge
            .build(&[
                Box::new(self.cookie(source, self.bucket(now))),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(ATTR_USERNAME, format!("{client}:{server}"))),
            ])
            .is_err()
        {
            return Decision::Ignore;
        }
        challenge.add(ATTR_ICE_CONTROLLED, &0u64.to_be_bytes());
        challenge.add(ATTR_PRIORITY, &1u32.to_be_bytes());
        if MessageIntegrity::new_short_term_integrity(credentials.client_pwd)
            .add_to(&mut challenge)
            .is_err()
            || FINGERPRINT.add_to(&mut challenge).is_err()
            || challenge.raw.len() > packet.len()
        {
            return Decision::Ignore;
        }
        Decision::Challenge(challenge.raw)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use stun::attributes::ATTR_ICE_CONTROLLING;
    use stun::xoraddr::XorMappedAddress;

    pub(in crate::webrtc::direct) fn request(password: &str) -> Vec<u8> {
        let mut message = Message::new();
        let server = format!("{}{}", super::super::ICE_CREDENTIAL_PREFIX_V2, password);
        message
            .build(&[
                Box::new(TransactionId::new()),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(
                    ATTR_USERNAME,
                    format!("{server}:browserClientUfrag"),
                )),
            ])
            .unwrap();
        message.add(ATTR_ICE_CONTROLLING, &1u64.to_be_bytes());
        message.add(ATTR_PRIORITY, &1u32.to_be_bytes());
        MessageIntegrity::new_short_term_integrity(server)
            .add_to(&mut message)
            .unwrap();
        FINGERPRINT.add_to(&mut message).unwrap();
        message.raw
    }

    pub(in crate::webrtc::direct) fn response(
        challenge: &[u8],
        password: &str,
        source: SocketAddr,
    ) -> Vec<u8> {
        let mut incoming = Message::new();
        incoming.unmarshal_binary(challenge).unwrap();
        let mut response = Message::new();
        response
            .build(&[
                Box::new(incoming.transaction_id),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: source.ip(),
                    port: source.port(),
                }),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    password.to_string(),
                )),
                Box::new(FINGERPRINT),
            ])
            .unwrap();
        response.raw
    }

    #[test]
    fn returned_cookies_share_an_ipv6_prefix_budget() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let password = "browserPassword0123456789";
        let packet = request(password);
        for host in 1..=12 {
            let source = format!("[2001:db8:1:2::{host:x}]:5000").parse().unwrap();
            let Decision::Challenge(challenge) = admission.receive(&packet, source, now) else {
                panic!("expected challenge")
            };
            let proof = response(&challenge, password, source);
            admission.receive(&proof, source, now);
        }
        assert_eq!(admission.verified.len(), MAX_PROBES_PER_IP);
        let other = "[2001:db8:1:3::1]:5000".parse().unwrap();
        let Decision::Challenge(challenge) = admission.receive(&packet, other, now) else {
            panic!("expected challenge")
        };
        let proof = response(&challenge, password, other);
        admission.receive(&proof, other, now);
        assert_eq!(admission.verified.len(), MAX_PROBES_PER_IP + 1);
    }

    #[test]
    fn unanswered_sources_cannot_exhaust_admission() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let password = "browserPassword0123456789";
        let packet = request(password);
        let source = "127.0.0.1:5000".parse().unwrap();
        let Decision::Challenge(challenge) = admission.receive(&packet, source, now) else {
            panic!("challenge")
        };
        assert!(challenge.len() <= packet.len());
        for index in 0..1024u16 {
            let spoofed = SocketAddr::from(([10, 0, (index / 256) as u8, index as u8], 5000));
            assert!(matches!(
                admission.receive(&packet, spoofed, now),
                Decision::Challenge(_)
            ));
        }
        assert!(admission.verified.is_empty());
        let proof = response(&challenge, password, source);
        assert!(matches!(
            admission.receive(&proof, source, now),
            Decision::Ignore
        ));
        assert!(matches!(
            admission.receive(&packet, source, now),
            Decision::Admit(_)
        ));
        assert!(admission.verified.is_empty());
    }

    #[test]
    fn cookies_require_source_freshness_and_matching_ice_integrity() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let source = "127.0.0.1:5000".parse().unwrap();
        let password = "browserPassword0123456789";
        let packet = request(password);
        let Decision::Challenge(challenge) = admission.receive(&packet, source, now) else {
            panic!("challenge")
        };
        let proof = response(&challenge, password, source);
        for other in ["127.0.0.2:5000", "127.0.0.1:5001"] {
            admission.receive(&proof, other.parse().unwrap(), now);
            assert!(admission.verified.is_empty());
        }
        admission.receive(&response(&challenge, "wrong password", source), source, now);
        assert!(matches!(
            admission.receive(&packet, source, now),
            Decision::Challenge(_)
        ));
        admission.receive(&proof, source, now + Duration::from_secs(4));
        assert!(admission.verified.is_empty());
        let mut restarted = Admission::default();
        restarted.receive(&proof, source, now);
        assert!(restarted.verified.is_empty());
    }

    #[test]
    fn returned_proof_cache_is_bounded_and_expires() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let password = "browserPassword0123456789";
        let packet = request(password);
        for index in 0..1024u16 {
            let source = SocketAddr::from(([10, 0, (index / 256) as u8, index as u8], 5000));
            let Decision::Challenge(challenge) = admission.receive(&packet, source, now) else {
                panic!("challenge")
            };
            admission.receive(&response(&challenge, password, source), source, now);
        }
        assert_eq!(admission.verified.len(), MAX_PROBES);
        let now = now + Duration::from_millis(1);
        for port in 1..10 {
            let source = SocketAddr::from(([127, 0, 0, 1], port));
            let Decision::Challenge(challenge) = admission.receive(&packet, source, now) else {
                panic!("challenge")
            };
            admission.receive(&response(&challenge, password, source), source, now);
        }
        assert_eq!(
            admission
                .verified
                .keys()
                .filter(|addr| addr.ip().is_loopback())
                .count(),
            MAX_PROBES_PER_IP
        );
        assert_eq!(admission.verified.len(), MAX_PROBES);
        admission.expire(now + PROBE_LIFETIME);
        assert!(admission.verified.is_empty());
    }

    #[test]
    fn long_valid_ice_requests_are_not_limited_by_the_proof_cache_bound() {
        let mut admission = Admission::default();
        let source = "127.0.0.1:5000".parse().unwrap();
        let now = Instant::now();
        let password = "a".repeat(230);
        let mut message = Message::new();
        message.unmarshal_binary(&request(&password)).unwrap();
        let server = format!("{}{}", super::super::ICE_CREDENTIAL_PREFIX_V2, password);
        message
            .build(&[
                Box::new(TransactionId::new()),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(
                    ATTR_USERNAME,
                    format!("{server}:{}", "b".repeat(256)),
                )),
            ])
            .unwrap();
        message.add(ATTR_ICE_CONTROLLING, &1u64.to_be_bytes());
        message.add(ATTR_PRIORITY, &1u32.to_be_bytes());
        MessageIntegrity::new_short_term_integrity(server)
            .add_to(&mut message)
            .unwrap();
        FINGERPRINT.add_to(&mut message).unwrap();
        assert!(message.raw.len() > 512);
        let Decision::Challenge(challenge) = admission.receive(&message.raw, source, now) else {
            panic!("challenge")
        };
        admission.receive(&response(&challenge, &password, source), source, now);
        assert!(matches!(
            admission.receive(&message.raw, source, now),
            Decision::Admit(_)
        ));
    }

    #[test]
    fn malformed_or_unsigned_stun_allocates_nothing() {
        let mut admission = Admission::default();
        let source = "127.0.0.1:5000".parse().unwrap();
        let original = request("browserPassword0123456789");
        for end in 0..original.len() {
            assert!(matches!(
                admission.receive(&original[..end], source, Instant::now()),
                Decision::Ignore
            ));
        }
        let mut corrupt = original;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            admission.receive(&corrupt, source, Instant::now()),
            Decision::Ignore
        ));
        assert!(admission.verified.is_empty());
    }
}
