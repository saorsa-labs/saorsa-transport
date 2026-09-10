//! Shared post-quantum application session for browser WebRTC connections.
//!
//! WebRTC authenticates the certificate pinned in the direct multiaddress and
//! encrypts transport traffic with DTLS. This layer additionally authenticates
//! the ANT node identity with ML-DSA-65, establishes fresh ML-KEM-768 key
//! material, and protects every subsequent application frame with
//! ChaCha20-Poly1305.

use super::verify_ml_dsa_65;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use saorsa_pqc::{
    kem_traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _},
    ml_kem_768,
};
use std::fmt;
use zeroize::Zeroize;

const PQ_SESSION_VERSION: u16 = 1;
const CLIENT_HELLO_TAG: u8 = 1;
const SERVER_ACCEPT_TAG: u8 = 2;
const ENCRYPTED_RECORD_TAG: u8 = 3;
const HANDSHAKE_DOMAIN: &[u8] = b"autonomi-webrtc-pq-handshake-v1\0";
const CLIENT_TO_SERVER_KDF: &str = "autonomi webrtc pq session v1 client to server";
const SERVER_TO_CLIENT_KDF: &str = "autonomi webrtc pq session v1 server to client";
const RECORD_AAD_DOMAIN: &[u8] = b"autonomi-webrtc-pq-record-v1\0";

/// ML-DSA-65 public-key length from FIPS 204.
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
/// ML-DSA-65 signature length from FIPS 204.
const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
const PEER_ID_BYTES: usize = 32;
const TAG_AND_VERSION_BYTES: usize = 3;
const RECORD_HEADER_BYTES: usize = 1 + 8;
const AEAD_TAG_BYTES: usize = 16;

/// Bytes in a serialized ML-KEM-768 client hello.
pub const PQ_CLIENT_HELLO_BYTES: usize = TAG_AND_VERSION_BYTES + ml_kem_768::EK_LEN;
/// Bytes in a serialized node accept message.
pub const PQ_SERVER_ACCEPT_BYTES: usize = TAG_AND_VERSION_BYTES
    + ml_kem_768::CT_LEN
    + PEER_ID_BYTES
    + ML_DSA_65_PUBLIC_KEY_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;
/// Bytes added by the encrypted-record envelope.
pub const PQ_ENCRYPTED_OVERHEAD_BYTES: usize = RECORD_HEADER_BYTES + AEAD_TAG_BYTES;
/// Bytes in the outer length prefix used to delimit `DataChannel` streams.
pub const PQ_FRAME_PREFIX_BYTES: usize = 4;

/// Error returned by the WebRTC post-quantum handshake or record layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqSessionError {
    /// A frame or handshake message has an invalid shape or value.
    InvalidFrame(String),
    /// ML-KEM key generation, parsing, encapsulation, or decapsulation failed.
    KeyExchange(String),
    /// The node identity did not authenticate the KEM transcript.
    Authentication(String),
    /// AEAD encryption or authentication failed.
    Encryption(String),
    /// The ordered `DataChannel` delivered an unexpected record sequence.
    UnexpectedSequence {
        /// Sequence number required by the receiver.
        expected: u64,
        /// Sequence number carried by the rejected record.
        received: u64,
    },
    /// A per-direction record sequence was exhausted.
    SequenceExhausted,
}

impl fmt::Display for PqSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrame(message) => write!(formatter, "invalid PQ session frame: {message}"),
            Self::KeyExchange(message) => write!(formatter, "ML-KEM session failed: {message}"),
            Self::Authentication(message) => {
                write!(formatter, "PQ session authentication failed: {message}")
            }
            Self::Encryption(message) => {
                write!(formatter, "PQ session encryption failed: {message}")
            }
            Self::UnexpectedSequence { expected, received } => write!(
                formatter,
                "unexpected PQ record sequence {received}; expected {expected}"
            ),
            Self::SequenceExhausted => formatter.write_str("PQ record sequence exhausted"),
        }
    }
}

impl std::error::Error for PqSessionError {}

/// Client-side state retained between the ML-KEM hello and server accept.
pub struct PqClientHandshake {
    client_hello: Vec<u8>,
    decapsulation_key: ml_kem_768::DecapsKey,
}

impl PqClientHandshake {
    /// Generate an ephemeral ML-KEM-768 keypair and its wire hello.
    ///
    /// # Errors
    ///
    /// Returns an error if secure key generation fails.
    pub fn start() -> Result<(Self, Vec<u8>), PqSessionError> {
        let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::try_keygen()
            .map_err(|error| PqSessionError::KeyExchange(error.to_string()))?;
        let mut client_hello = Vec::with_capacity(PQ_CLIENT_HELLO_BYTES);
        client_hello.push(CLIENT_HELLO_TAG);
        client_hello.extend_from_slice(&PQ_SESSION_VERSION.to_be_bytes());
        client_hello.extend_from_slice(&encapsulation_key.into_bytes());
        Ok((
            Self {
                client_hello: client_hello.clone(),
                decapsulation_key,
            },
            client_hello,
        ))
    }

    /// Authenticate the server accept, decapsulate its ML-KEM ciphertext, and
    /// construct the client half of the encrypted session.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed accept, an unauthenticated node, or a
    /// failed ML-KEM decapsulation.
    pub fn finish(
        self,
        server_accept: &[u8],
        expected_peer_id: &[u8; PEER_ID_BYTES],
    ) -> Result<PqSession, PqSessionError> {
        let parsed = parse_server_accept(server_accept)?;
        if &parsed.peer_id != expected_peer_id {
            return Err(PqSessionError::Authentication(format!(
                "endpoint names peer {}, server authenticated as {}",
                hex::encode(expected_peer_id),
                hex::encode(parsed.peer_id)
            )));
        }
        if blake3::hash(parsed.public_key).as_bytes() != expected_peer_id {
            return Err(PqSessionError::Authentication(
                "ML-DSA public key does not match the endpoint peer ID".to_string(),
            ));
        }
        let transcript =
            handshake_transcript(&self.client_hello, parsed.ciphertext, &parsed.peer_id);
        if !verify_ml_dsa_65(parsed.public_key, parsed.signature, &transcript, b"") {
            return Err(PqSessionError::Authentication(
                "node returned an invalid ML-DSA-65 signature".to_string(),
            ));
        }
        let ciphertext =
            ml_kem_768::CipherText::try_from_bytes(parsed.ciphertext.try_into().map_err(|_| {
                PqSessionError::InvalidFrame("wrong ciphertext length".to_string())
            })?)
            .map_err(|error| PqSessionError::KeyExchange(error.to_string()))?;
        let shared_secret = self
            .decapsulation_key
            .try_decaps(&ciphertext)
            .map_err(|error| PqSessionError::KeyExchange(error.to_string()))?;
        Ok(PqSession::from_shared_secret(
            shared_secret.into_bytes(),
            &transcript,
            SessionRole::Client,
        ))
    }
}

/// Accept an ephemeral client hello and build the server half of the session.
///
/// `sign` must sign the supplied transcript with the node's persistent
/// ML-DSA-65 identity key and return the serialized signature.
///
/// # Errors
///
/// Returns an error for malformed key material, an identity mismatch, a
/// failed ML-KEM encapsulation, or a signing failure.
pub fn accept_pq_session<E, F>(
    client_hello: &[u8],
    peer_id: &[u8; PEER_ID_BYTES],
    public_key: &[u8],
    sign: F,
) -> Result<(Vec<u8>, PqSession), PqSessionError>
where
    E: fmt::Display,
    F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
{
    validate_client_hello(client_hello)?;
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(PqSessionError::Authentication(format!(
            "expected a {ML_DSA_65_PUBLIC_KEY_BYTES}-byte ML-DSA-65 public key"
        )));
    }
    if blake3::hash(public_key).as_bytes() != peer_id {
        return Err(PqSessionError::Authentication(
            "node public key does not match its peer ID".to_string(),
        ));
    }
    let encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(
        client_hello[TAG_AND_VERSION_BYTES..]
            .try_into()
            .map_err(|_| {
                PqSessionError::InvalidFrame("wrong encapsulation-key length".to_string())
            })?,
    )
    .map_err(|error| PqSessionError::KeyExchange(error.to_string()))?;
    let (shared_secret, ciphertext) = encapsulation_key
        .try_encaps()
        .map_err(|error| PqSessionError::KeyExchange(error.to_string()))?;
    let ciphertext = ciphertext.into_bytes();
    let transcript = handshake_transcript(client_hello, &ciphertext, peer_id);
    let signature =
        sign(&transcript).map_err(|error| PqSessionError::Authentication(error.to_string()))?;
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(PqSessionError::Authentication(format!(
            "signer returned {} bytes; expected {ML_DSA_65_SIGNATURE_BYTES}",
            signature.len()
        )));
    }

    let mut server_accept = Vec::with_capacity(PQ_SERVER_ACCEPT_BYTES);
    server_accept.push(SERVER_ACCEPT_TAG);
    server_accept.extend_from_slice(&PQ_SESSION_VERSION.to_be_bytes());
    server_accept.extend_from_slice(&ciphertext);
    server_accept.extend_from_slice(peer_id);
    server_accept.extend_from_slice(public_key);
    server_accept.extend_from_slice(&signature);
    let session =
        PqSession::from_shared_secret(shared_secret.into_bytes(), &transcript, SessionRole::Server);
    Ok((server_accept, session))
}

/// Ordered, authenticated application-record session.
///
/// The type is deliberately role-specific at construction time. Its outbound
/// and inbound keys are independently derived, so equal sequence numbers in
/// opposite directions never reuse an AEAD nonce/key pair.
pub struct PqSession {
    outbound_key: [u8; 32],
    inbound_key: [u8; 32],
    outbound_sequence: u64,
    inbound_sequence: u64,
}

impl PqSession {
    fn from_shared_secret(
        mut shared_secret: [u8; 32],
        transcript: &[u8],
        role: SessionRole,
    ) -> Self {
        let transcript_hash = blake3::hash(transcript);
        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(&shared_secret);
        key_material[32..].copy_from_slice(transcript_hash.as_bytes());
        let client_to_server = blake3::derive_key(CLIENT_TO_SERVER_KDF, &key_material);
        let server_to_client = blake3::derive_key(SERVER_TO_CLIENT_KDF, &key_material);
        shared_secret.zeroize();
        key_material.zeroize();
        let (outbound_key, inbound_key) = match role {
            SessionRole::Client => (client_to_server, server_to_client),
            SessionRole::Server => (server_to_client, client_to_server),
        };
        Self {
            outbound_key,
            inbound_key,
            outbound_sequence: 0,
            inbound_sequence: 0,
        }
    }

    /// Encrypt and authenticate the next outbound application frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the sequence is exhausted or encryption fails.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PqSessionError> {
        let sequence = self.outbound_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(PqSessionError::SequenceExhausted)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.outbound_key));
        let sequence_bytes = sequence.to_be_bytes();
        let nonce = record_nonce(sequence_bytes);
        let aad = record_aad(sequence_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PqSessionError::Encryption("could not seal record".to_string()))?;
        let mut record = Vec::with_capacity(RECORD_HEADER_BYTES + ciphertext.len());
        record.push(ENCRYPTED_RECORD_TAG);
        record.extend_from_slice(&sequence_bytes);
        record.extend_from_slice(&ciphertext);
        self.outbound_sequence = next;
        Ok(record)
    }

    /// Authenticate and decrypt the next inbound application frame.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, out-of-order, replayed, or
    /// unauthenticated records, or if the sequence is exhausted.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, PqSessionError> {
        if record.len() < PQ_ENCRYPTED_OVERHEAD_BYTES {
            return Err(PqSessionError::InvalidFrame(
                "encrypted record is truncated".to_string(),
            ));
        }
        if record[0] != ENCRYPTED_RECORD_TAG {
            return Err(PqSessionError::InvalidFrame(
                "expected an encrypted record".to_string(),
            ));
        }
        let sequence_bytes: [u8; 8] = record[1..RECORD_HEADER_BYTES].try_into().map_err(|_| {
            PqSessionError::InvalidFrame("record sequence is truncated".to_string())
        })?;
        let sequence = u64::from_be_bytes(sequence_bytes);
        if sequence != self.inbound_sequence {
            return Err(PqSessionError::UnexpectedSequence {
                expected: self.inbound_sequence,
                received: sequence,
            });
        }
        let next = sequence
            .checked_add(1)
            .ok_or(PqSessionError::SequenceExhausted)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.inbound_key));
        let nonce = record_nonce(sequence_bytes);
        let aad = record_aad(sequence_bytes);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &record[RECORD_HEADER_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| PqSessionError::Encryption("record authentication failed".to_string()))?;
        self.inbound_sequence = next;
        Ok(plaintext)
    }
}

impl Drop for PqSession {
    fn drop(&mut self) {
        self.outbound_key.zeroize();
        self.inbound_key.zeroize();
        self.outbound_sequence.zeroize();
        self.inbound_sequence.zeroize();
    }
}

/// Add a big-endian payload length so chunked `DataChannel` messages can be
/// reassembled without exposing an inner JSON header.
///
/// # Errors
///
/// Returns an error if the payload length does not fit the wire prefix.
pub fn encode_pq_frame(payload: &[u8]) -> Result<Vec<u8>, PqSessionError> {
    let length = u32::try_from(payload.len())
        .map_err(|_| PqSessionError::InvalidFrame("payload length does not fit u32".to_string()))?;
    let mut frame = Vec::with_capacity(PQ_FRAME_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Return the complete outer-frame length once its prefix is available.
///
/// # Errors
///
/// Returns an error if the declared payload violates the caller's limit or
/// overflows the platform frame size.
pub fn pq_frame_length(
    frame: &[u8],
    max_payload_bytes: usize,
) -> Result<Option<usize>, PqSessionError> {
    if frame.len() < PQ_FRAME_PREFIX_BYTES {
        return Ok(None);
    }
    let payload_length = u32::from_be_bytes(
        frame[..PQ_FRAME_PREFIX_BYTES]
            .try_into()
            .map_err(|_| PqSessionError::InvalidFrame("frame prefix is truncated".to_string()))?,
    ) as usize;
    if payload_length == 0 || payload_length > max_payload_bytes {
        return Err(PqSessionError::InvalidFrame(format!(
            "payload length {payload_length} is outside 1..={max_payload_bytes}"
        )));
    }
    PQ_FRAME_PREFIX_BYTES
        .checked_add(payload_length)
        .map(Some)
        .ok_or_else(|| PqSessionError::InvalidFrame("frame length overflow".to_string()))
}

/// Remove and validate a complete outer frame.
///
/// # Errors
///
/// Returns an error if the frame is incomplete, oversized, or has trailing
/// bytes.
pub fn decode_pq_frame(frame: &[u8], max_payload_bytes: usize) -> Result<Vec<u8>, PqSessionError> {
    let expected = pq_frame_length(frame, max_payload_bytes)?
        .ok_or_else(|| PqSessionError::InvalidFrame("frame prefix is truncated".to_string()))?;
    if frame.len() != expected {
        return Err(PqSessionError::InvalidFrame(format!(
            "received {} bytes; expected {expected}",
            frame.len()
        )));
    }
    Ok(frame[PQ_FRAME_PREFIX_BYTES..].to_vec())
}

#[derive(Clone, Copy)]
enum SessionRole {
    Client,
    Server,
}

struct ParsedServerAccept<'a> {
    ciphertext: &'a [u8],
    peer_id: [u8; PEER_ID_BYTES],
    public_key: &'a [u8],
    signature: &'a [u8],
}

fn validate_client_hello(client_hello: &[u8]) -> Result<(), PqSessionError> {
    if client_hello.len() != PQ_CLIENT_HELLO_BYTES {
        return Err(PqSessionError::InvalidFrame(format!(
            "client hello is {} bytes; expected {PQ_CLIENT_HELLO_BYTES}",
            client_hello.len()
        )));
    }
    validate_handshake_prefix(client_hello, CLIENT_HELLO_TAG, "client hello")
}

fn parse_server_accept(server_accept: &[u8]) -> Result<ParsedServerAccept<'_>, PqSessionError> {
    if server_accept.len() != PQ_SERVER_ACCEPT_BYTES {
        return Err(PqSessionError::InvalidFrame(format!(
            "server accept is {} bytes; expected {PQ_SERVER_ACCEPT_BYTES}",
            server_accept.len()
        )));
    }
    validate_handshake_prefix(server_accept, SERVER_ACCEPT_TAG, "server accept")?;
    let ciphertext_start = TAG_AND_VERSION_BYTES;
    let peer_id_start = ciphertext_start + ml_kem_768::CT_LEN;
    let public_key_start = peer_id_start + PEER_ID_BYTES;
    let signature_start = public_key_start + ML_DSA_65_PUBLIC_KEY_BYTES;
    Ok(ParsedServerAccept {
        ciphertext: &server_accept[ciphertext_start..peer_id_start],
        peer_id: server_accept[peer_id_start..public_key_start]
            .try_into()
            .map_err(|_| PqSessionError::InvalidFrame("peer ID is truncated".to_string()))?,
        public_key: &server_accept[public_key_start..signature_start],
        signature: &server_accept[signature_start..],
    })
}

fn validate_handshake_prefix(
    message: &[u8],
    expected_tag: u8,
    name: &str,
) -> Result<(), PqSessionError> {
    if message.first().copied() != Some(expected_tag) {
        return Err(PqSessionError::InvalidFrame(format!(
            "{name} has the wrong message type"
        )));
    }
    let version = u16::from_be_bytes(
        message[1..TAG_AND_VERSION_BYTES]
            .try_into()
            .map_err(|_| PqSessionError::InvalidFrame(format!("{name} version is truncated")))?,
    );
    if version != PQ_SESSION_VERSION {
        return Err(PqSessionError::InvalidFrame(format!(
            "{name} uses PQ session version {version}; expected {PQ_SESSION_VERSION}"
        )));
    }
    Ok(())
}

fn handshake_transcript(client_hello: &[u8], ciphertext: &[u8], peer_id: &[u8; 32]) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(HANDSHAKE_DOMAIN.len() + client_hello.len() + ciphertext.len() + 32);
    transcript.extend_from_slice(HANDSHAKE_DOMAIN);
    transcript.extend_from_slice(client_hello);
    transcript.extend_from_slice(ciphertext);
    transcript.extend_from_slice(peer_id);
    transcript
}

fn record_nonce(sequence: [u8; 8]) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&sequence);
    *Nonce::from_slice(&bytes)
}

fn record_aad(sequence: [u8; 8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD_DOMAIN.len() + sequence.len());
    aad.extend_from_slice(RECORD_AAD_DOMAIN);
    aad.extend_from_slice(&sequence);
    aad
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::ml_dsa_65;

    fn session_pair() -> (PqSession, PqSession) {
        let dsa = ml_dsa_65();
        let (public_key, secret_key) = dsa.generate_keypair().unwrap();
        let public_key = public_key.to_bytes();
        let peer_id = *blake3::hash(&public_key).as_bytes();
        let (client_handshake, client_hello) = PqClientHandshake::start().unwrap();
        let (server_accept, server_session) =
            accept_pq_session(&client_hello, &peer_id, &public_key, |transcript| {
                dsa.sign(&secret_key, transcript)
                    .map(|signature| signature.to_bytes())
            })
            .unwrap();
        let client_session = client_handshake.finish(&server_accept, &peer_id).unwrap();
        (client_session, server_session)
    }

    #[test]
    fn handshake_and_records_round_trip_in_both_directions() {
        let (mut client, mut server) = session_pair();
        let request = client.seal(b"private request").unwrap();
        assert_eq!(server.open(&request).unwrap(), b"private request");
        let response = server.seal(b"private response").unwrap();
        assert_eq!(client.open(&response).unwrap(), b"private response");
    }

    #[test]
    fn records_reject_tampering_and_replay() {
        let (mut client, mut server) = session_pair();
        let record = client.seal(b"payload").unwrap();
        let mut tampered = record.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(server.open(&tampered).is_err());
        assert_eq!(server.open(&record).unwrap(), b"payload");
        assert!(server.open(&record).is_err());
    }

    #[test]
    fn server_identity_is_bound_to_expected_peer() {
        let dsa = ml_dsa_65();
        let (public_key, secret_key) = dsa.generate_keypair().unwrap();
        let public_key = public_key.to_bytes();
        let peer_id = *blake3::hash(&public_key).as_bytes();
        let (client_handshake, client_hello) = PqClientHandshake::start().unwrap();
        let (server_accept, _) =
            accept_pq_session(&client_hello, &peer_id, &public_key, |transcript| {
                dsa.sign(&secret_key, transcript)
                    .map(|signature| signature.to_bytes())
            })
            .unwrap();
        assert!(client_handshake.finish(&server_accept, &[9u8; 32]).is_err());
    }

    #[test]
    fn server_accept_rejects_a_tampered_signature() {
        let dsa = ml_dsa_65();
        let (public_key, secret_key) = dsa.generate_keypair().unwrap();
        let public_key = public_key.to_bytes();
        let peer_id = *blake3::hash(&public_key).as_bytes();
        let (client_handshake, client_hello) = PqClientHandshake::start().unwrap();
        let (mut server_accept, _) =
            accept_pq_session(&client_hello, &peer_id, &public_key, |transcript| {
                dsa.sign(&secret_key, transcript)
                    .map(|signature| signature.to_bytes())
            })
            .unwrap();
        let last = server_accept.len() - 1;
        server_accept[last] ^= 1;
        assert!(client_handshake.finish(&server_accept, &peer_id).is_err());
    }

    #[test]
    fn outer_frame_round_trip_and_limits() {
        let frame = encode_pq_frame(b"hello").unwrap();
        assert_eq!(pq_frame_length(&frame[..3], 5).unwrap(), None);
        assert_eq!(pq_frame_length(&frame, 5).unwrap(), Some(frame.len()));
        assert_eq!(decode_pq_frame(&frame, 5).unwrap(), b"hello");
        assert!(decode_pq_frame(&frame, 4).is_err());
    }
}
