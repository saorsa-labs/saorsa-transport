//! Portable WebRTC Direct application wire contract.
//!
//! This module owns the constants, JSON schema, outer framing, and canonical
//! certificate-pinned endpoint syntax shared by nodes and browser clients.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr as _;

/// Current browser request/response protocol version.
pub const BROWSER_PROTOCOL_VERSION: u16 = 5;
/// Protocol name authenticated by the node HELLO response.
pub const BROWSER_PROTOCOL_NAME: &str = "autonomi.web.poc.v5";
/// Ordered WebRTC `DataChannel` label used by Autonomi nodes.
pub const WEBRTC_DIRECT_DATA_CHANNEL: &str = "autonomi.web.v5";
/// Maximum content carried by one browser protocol frame.
pub const MAX_BROWSER_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum JSON header carried by one browser protocol frame.
pub const MAX_BROWSER_HEADER_BYTES: usize = 64 * 1024;
/// Maximum encoded ant-protocol message, including payment proof overhead.
pub const MAX_BROWSER_CONTENT_BYTES: usize = 5 * 1024 * 1024;
/// Maximum complete browser application frame.
pub const MAX_BROWSER_FRAME_BYTES: usize = 4 + MAX_BROWSER_HEADER_BYTES + MAX_BROWSER_CONTENT_BYTES;
/// Backwards-compatible name for the maximum complete response frame.
pub const MAX_BROWSER_RESPONSE_BYTES: usize = MAX_BROWSER_FRAME_BYTES;
/// Maximum accepted WebRTC Direct multiaddress length.
pub const MAX_WEBRTC_DIRECT_MULTIADDR_LENGTH: usize = 2048;
/// `DataChannel` message size shared by native and browser adapters.
pub const WEBRTC_WRITE_CHUNK_BYTES: usize = 16 * 1024;

const SHA2_256_MULTIHASH_CODE: u8 = 0x12;
const SHA2_256_MULTIHASH_LENGTH: u8 = 32;

/// Errors produced by browser address, framing, and identity validation.
#[derive(Debug, thiserror::Error)]
pub enum BrowserProtocolError {
    /// An address or hexadecimal identifier is malformed.
    #[error("invalid browser endpoint: {0}")]
    Endpoint(String),
    /// A request or response frame is malformed or exceeds a bound.
    #[error("invalid browser frame: {0}")]
    Frame(String),
    /// A node identity response failed authentication.
    #[error("invalid node HELLO: {0}")]
    Identity(String),
}

/// Manifest- and wire-compatible wrapper around a WebRTC Direct multiaddress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEndpoint {
    /// `/ip4|ip6/.../udp/.../webrtc-direct/certhash/.../p2p/...` address.
    pub multiaddr: String,
}

impl BrowserEndpoint {
    /// Construct the canonical endpoint form used by manifests and RPCs.
    ///
    /// # Errors
    ///
    /// Returns an error when `advertised_addr` uses port zero.
    pub fn new(
        advertised_addr: SocketAddr,
        peer_id: &[u8; 32],
        certificate_hash: [u8; 32],
    ) -> Result<Self, BrowserProtocolError> {
        if advertised_addr.port() == 0 {
            return Err(BrowserProtocolError::Endpoint(
                "WebRtcDirect multiaddress has an invalid UDP port".to_string(),
            ));
        }
        let mut multihash = Vec::with_capacity(34);
        multihash.push(SHA2_256_MULTIHASH_CODE);
        multihash.push(SHA2_256_MULTIHASH_LENGTH);
        multihash.extend_from_slice(&certificate_hash);
        let host_protocol = if advertised_addr.is_ipv4() {
            "ip4"
        } else {
            "ip6"
        };
        let multiaddr = format!(
            "/{host_protocol}/{}/udp/{}/webrtc-direct/certhash/u{}/p2p/{}",
            advertised_addr.ip(),
            advertised_addr.port(),
            URL_SAFE_NO_PAD.encode(multihash),
            hex::encode(peer_id)
        );
        Ok(Self { multiaddr })
    }

    /// Parse this endpoint into portable address components.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is not canonical and fully pinned.
    pub fn parse(&self) -> Result<WebRtcDirectEndpoint, BrowserProtocolError> {
        parse_webrtc_direct_multiaddr(&self.multiaddr)
    }
}

/// Parsed, certificate-pinned direct endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebRtcDirectEndpoint {
    /// Canonical input multiaddress.
    pub multiaddr: String,
    /// `ip4` or `ip6`.
    #[serde(rename = "hostProtocol")]
    pub host_protocol: String,
    /// Literal IP address.
    pub host: String,
    /// UDP listener port.
    pub port: u16,
    /// Lowercase 32-byte ANT peer ID.
    #[serde(rename = "peerId")]
    pub peer_id: String,
    /// SHA-256 DTLS certificate digest.
    #[serde(rename = "certificateHash")]
    pub certificate_hash: [u8; 32],
}

impl WebRtcDirectEndpoint {
    /// Return the literal endpoint as a socket address.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance contains an invalid host.
    pub fn socket_addr(&self) -> Result<SocketAddr, BrowserProtocolError> {
        let address = if self.host_protocol == "ip6" {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        address.parse().map_err(|error| {
            BrowserProtocolError::Endpoint(format!(
                "WebRtcDirect endpoint has an invalid socket address: {error}"
            ))
        })
    }

    /// Decode the endpoint peer ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance contains an invalid peer ID.
    pub fn peer_id_bytes(&self) -> Result<[u8; 32], BrowserProtocolError> {
        decode_hex(&self.peer_id, 32)
            .and_then(|bytes| {
                bytes.try_into().map_err(|bytes: Vec<u8>| {
                    format!("expected 32 bytes, received {}", bytes.len())
                })
            })
            .map_err(BrowserProtocolError::Endpoint)
    }
}

/// Endpoint accepted from either a raw multiaddress or manifest object.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BrowserEndpointInput {
    /// Raw multiaddress string.
    Multiaddr(String),
    /// Manifest endpoint object.
    Structured(BrowserEndpoint),
}

impl BrowserEndpointInput {
    /// Return the contained multiaddress.
    #[must_use]
    pub fn multiaddr(&self) -> &str {
        match self {
            Self::Multiaddr(value) => value,
            Self::Structured(value) => &value.multiaddr,
        }
    }
}

/// Public EVM identity transmitted by manifests and HELLO responses.
/// RPC endpoints belong to the node operator or client application and never
/// form part of this wire record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPaymentNetwork {
    /// EVM chain ID used for payment verification.
    pub chain_id: u64,
    /// ERC-20 payment token contract.
    pub payment_token_address: String,
    /// Autonomi payment vault contract.
    pub payment_vault_address: String,
}

/// JSON-safe form of a node's signed storage commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserCommitmentArtifact {
    /// MessagePack-encoded native commitment.
    pub encoded: String,
    /// Merkle root.
    pub root: String,
    /// Number of committed keys.
    pub key_count: u32,
    /// Signing peer ID.
    pub sender_peer_id: String,
    /// ML-DSA-65 public key.
    pub sender_public_key: String,
    /// ML-DSA-65 signature.
    pub signature: String,
}

/// JSON-safe form of the native EVM payment quote returned over WebRTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserQuoteArtifact {
    /// Quoting node peer ID.
    pub peer_id: String,
    /// Content address being quoted.
    pub content: String,
    /// Quote timestamp in seconds since the Unix epoch.
    pub timestamp_secs: u64,
    /// Decimal token price.
    pub price: String,
    /// Twenty-byte node rewards address.
    pub rewards_address: String,
    /// ML-DSA-65 public key.
    pub public_key: String,
    /// ML-DSA-65 signature.
    pub signature: String,
    /// Storage commitment key count used by the pricing curve.
    pub committed_key_count: u32,
    /// Optional pinned storage commitment.
    pub commitment_pin: Option<String>,
    /// Keccak-256 EVM payment quote hash.
    pub quote_hash: String,
    /// Optional resolved native storage commitment.
    pub commitment: Option<BrowserCommitmentArtifact>,
}

/// One node returned by the browser closest-node RPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserNode {
    /// Hex-encoded owner-signed address record retained by client-side objects.
    /// FIND_NODE transfers proofs separately in its binary response body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_record: Option<String>,
    /// Hex-encoded native MessagePack peer record, retaining address tags and publish sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_record: Option<String>,
    /// Lowercase ANT peer ID.
    pub peer_id: String,
    /// Native transport addresses retained for diagnostics.
    #[serde(default)]
    pub native_addresses: Vec<String>,
    /// DHT reliability estimate.
    #[serde(default)]
    pub reliability: f64,
    /// Browser-dialable endpoint, when one is advertised.
    #[serde(default)]
    pub webrtc_direct: Option<BrowserEndpoint>,
}

/// A complete browser RPC request header.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserRequest {
    /// Browser protocol version.
    pub version: u16,
    /// Caller-selected request identifier.
    pub request_id: u64,
    /// Raw binary bytes following the JSON header.
    pub content_length: usize,
    /// Method-specific request fields.
    #[serde(flatten)]
    pub body: BrowserRequestBody,
}

impl BrowserRequest {
    /// Construct a request for the current protocol version.
    #[must_use]
    pub fn new(request_id: u64, body: BrowserRequestBody, content_length: usize) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            content_length,
            body,
        }
    }
}

/// Browser RPC request methods and their fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserRequestBody {
    /// An encoded ant-protocol request in the binary body.
    ChunkProtocol,
    /// Authenticate and describe the connected node.
    Hello,
    /// Return locally known nodes closest to `target`.
    FindNode {
        /// Request owner-signed address records in the binary response body.
        #[serde(default)]
        with_address_records: bool,
        /// Lowercase 32-byte lookup target.
        target: String,
        /// Optional bounded result count.
        #[serde(default)]
        count: Option<usize>,
    },
    /// Retrieve one immutable record.
    GetChunk {
        /// Lowercase 32-byte content address.
        address: String,
    },
    /// Request a signed storage quote.
    QuoteChunk {
        /// Lowercase 32-byte content address.
        address: String,
        /// Record size in bytes.
        size: u64,
    },
    /// Store one paid immutable record.
    PutChunk {
        /// Lowercase 32-byte content address.
        address: String,
        /// Quote previously returned by the target node.
        quote: Box<BrowserQuoteArtifact>,
        /// EVM transaction hash paying the quote.
        transaction_hash: String,
    },
}

/// A complete browser RPC response header.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserResponse {
    /// Browser protocol version.
    pub version: u16,
    /// Identifier copied from the request.
    pub request_id: u64,
    /// High-level response outcome.
    pub status: BrowserResponseStatus,
    /// Raw binary bytes following the JSON header.
    pub content_length: usize,
    /// Method-specific response fields.
    #[serde(flatten)]
    pub body: BrowserResponseBody,
}

impl BrowserResponse {
    /// Construct a successful response.
    #[must_use]
    pub fn ok(request_id: u64, body: BrowserResponseBody, content_length: usize) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            status: BrowserResponseStatus::Ok,
            content_length,
            body,
        }
    }

    /// Construct a missing-chunk response.
    #[must_use]
    pub fn not_found(request_id: u64, address: String) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            status: BrowserResponseStatus::NotFound,
            content_length: 0,
            body: BrowserResponseBody::ChunkNotFound { address },
        }
    }

    /// Construct a protocol or application error response.
    #[must_use]
    pub fn error(request_id: u64, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            status: BrowserResponseStatus::Error,
            content_length: 0,
            body: BrowserResponseBody::Error {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

/// High-level browser response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserResponseStatus {
    /// The request succeeded.
    Ok,
    /// The requested immutable record was absent.
    NotFound,
    /// The request was rejected or failed.
    Error,
}

/// Browser RPC response variants and their fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // Quote metadata intentionally stays inline.
pub enum BrowserResponseBody {
    /// An encoded ant-protocol response in the binary body.
    ChunkProtocol,
    /// Authenticated node and protocol metadata.
    Hello {
        /// Authenticated protocol name.
        protocol: String,
        /// Connected node peer ID.
        peer_id: String,
        /// Largest accepted immutable record.
        max_chunk_size: usize,
        /// Endpoint authenticated by the session.
        endpoint: BrowserEndpoint,
        /// Public payment configuration.
        payment: BrowserPaymentNetwork,
        /// Supported RPC operations.
        capabilities: Vec<String>,
    },
    /// Closest-node lookup result.
    Nodes {
        /// Lookup target copied from the request.
        target: String,
        /// Closest known nodes.
        nodes: Vec<BrowserNode>,
    },
    /// Immutable record metadata; bytes follow the header.
    Chunk {
        /// Record address.
        address: String,
        /// Record size.
        size: usize,
    },
    /// Missing immutable record metadata.
    ChunkNotFound {
        /// Requested record address.
        address: String,
    },
    /// Signed quote for storing an immutable record.
    StorageQuote {
        /// Record address.
        address: String,
        /// Whether the node already stores the record.
        already_stored: bool,
        /// Signed quote and optional commitment.
        quote: BrowserQuoteArtifact,
    },
    /// Confirmation that an immutable record was stored.
    ChunkStored {
        /// Stored record address.
        address: String,
        /// Whether it existed before this request.
        already_stored: bool,
    },
    /// Stable error code and human-readable detail.
    Error {
        /// Stable machine-readable error code.
        code: String,
        /// Human-readable error detail.
        message: String,
    },
}

/// Metadata returned by an authenticated node's encrypted HELLO response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserHello {
    /// Response discriminator.
    #[serde(rename = "type")]
    pub response_type: String,
    /// Browser protocol name.
    pub protocol: String,
    /// Lowercase peer ID.
    pub peer_id: String,
    /// Direct endpoint authenticated by the enclosing post-quantum session.
    pub endpoint: BrowserEndpoint,
    /// Maximum node record size.
    #[serde(default)]
    pub max_chunk_size: usize,
    /// Advertised browser operations.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Advertised browser payment network.
    pub payment: BrowserPaymentNetwork,
}

/// A decoded request frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserRequestFrame {
    /// Typed JSON request header.
    pub request: BrowserRequest,
    /// Binary request body.
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

/// A decoded response frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserResponseFrame {
    /// Typed JSON response header.
    pub header: BrowserResponse,
    /// Binary response body.
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

/// Parse and validate a signaling-free WebRTC Direct multiaddress.
///
/// # Errors
///
/// Returns an error for a malformed, non-canonical, or incompletely pinned address.
pub fn parse_webrtc_direct_multiaddr(
    multiaddr: &str,
) -> Result<WebRtcDirectEndpoint, BrowserProtocolError> {
    let multiaddr = multiaddr.trim();
    if multiaddr.is_empty()
        || multiaddr.len() > MAX_WEBRTC_DIRECT_MULTIADDR_LENGTH
        || !multiaddr.starts_with('/')
    {
        return Err(BrowserProtocolError::Endpoint(
            "invalid WebRtcDirect multiaddress length or prefix".to_string(),
        ));
    }
    let segments = multiaddr.split('/').collect::<Vec<_>>();
    if segments.len() != 10 {
        return Err(BrowserProtocolError::Endpoint(
            "WebRtcDirect multiaddress is incomplete".to_string(),
        ));
    }

    let host_protocol = segments[1];
    let host = segments[2];
    let host_ip = match host_protocol {
        "ip4" => IpAddr::V4(Ipv4Addr::from_str(host).map_err(|error| {
            BrowserProtocolError::Endpoint(format!("invalid IPv4 address {host}: {error}"))
        })?),
        "ip6" => IpAddr::V6(Ipv6Addr::from_str(host).map_err(|error| {
            BrowserProtocolError::Endpoint(format!("invalid IPv6 address {host}: {error}"))
        })?),
        _ => {
            return Err(BrowserProtocolError::Endpoint(
                "WebRTC Direct multiaddresses must use a literal IP address".to_string(),
            ));
        }
    };
    if segments[3] != "udp" {
        return Err(BrowserProtocolError::Endpoint(
            "WebRtcDirect multiaddress must use UDP".to_string(),
        ));
    }
    let port = segments[4].parse::<u16>().map_err(|error| {
        BrowserProtocolError::Endpoint(format!(
            "WebRtcDirect multiaddress has an invalid UDP port: {error}"
        ))
    })?;
    if port == 0 {
        return Err(BrowserProtocolError::Endpoint(
            "WebRtcDirect multiaddress has an invalid UDP port".to_string(),
        ));
    }
    if segments[5] != "webrtc-direct" {
        return Err(BrowserProtocolError::Endpoint(
            "WebRTC Direct multiaddress must contain /webrtc-direct".to_string(),
        ));
    }
    if segments[6] != "certhash" || segments[7].is_empty() {
        return Err(BrowserProtocolError::Endpoint(
            "WebRTC Direct multiaddress must contain exactly one certhash".to_string(),
        ));
    }
    let certificate_hash = decode_certificate_multihash(segments[7])?;
    if segments[8] != "p2p" {
        return Err(BrowserProtocolError::Endpoint(
            "WebRtcDirect multiaddress must end with /p2p/<peer-id>".to_string(),
        ));
    }
    let peer_id = normalize_hex(segments[9], 32).map_err(BrowserProtocolError::Endpoint)?;
    let peer_id_bytes: [u8; 32] = decode_hex(&peer_id, 32)
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, received {}", bytes.len()))
        })
        .map_err(BrowserProtocolError::Endpoint)?;
    let canonical = BrowserEndpoint::new(
        SocketAddr::new(host_ip, port),
        &peer_id_bytes,
        certificate_hash,
    )?;

    Ok(WebRtcDirectEndpoint {
        multiaddr: canonical.multiaddr,
        host_protocol: host_protocol.to_string(),
        host: host_ip.to_string(),
        port,
        peer_id,
        certificate_hash,
    })
}

fn decode_certificate_multihash(value: &str) -> Result<[u8; 32], BrowserProtocolError> {
    let encoded = value.strip_prefix('u').ok_or_else(|| {
        BrowserProtocolError::Endpoint(
            "certificate multihash must use base64url multibase (`u`)".to_string(),
        )
    })?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        BrowserProtocolError::Endpoint(format!(
            "certificate multihash is not valid unpadded base64url: {error}"
        ))
    })?;
    if decoded.len() != 34
        || decoded[0] != SHA2_256_MULTIHASH_CODE
        || decoded[1] != SHA2_256_MULTIHASH_LENGTH
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(BrowserProtocolError::Endpoint(
            "certificate multihash must contain a canonical 32-byte SHA-256 digest".to_string(),
        ));
    }
    decoded[2..].try_into().map_err(|_| {
        BrowserProtocolError::Endpoint(
            "certificate multihash must contain a 32-byte SHA-256 digest".to_string(),
        )
    })
}

/// Normalize a fixed-width hexadecimal wire field.
///
/// # Errors
///
/// Returns an error unless the input contains exactly `bytes` hexadecimal bytes.
pub fn normalize_hex(value: &str, bytes: usize) -> Result<String, String> {
    let normalized = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim())
        .replace(':', "");
    if normalized.len() != bytes.saturating_mul(2)
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("expected {bytes} hexadecimal bytes"));
    }
    Ok(normalized.to_ascii_lowercase())
}

/// Decode a fixed-width hexadecimal wire field.
///
/// # Errors
///
/// Returns an error unless the input contains exactly `bytes` hexadecimal bytes.
pub fn decode_hex(value: &str, bytes: usize) -> Result<Vec<u8>, String> {
    let normalized = normalize_hex(value, bytes)?;
    hex::decode(normalized).map_err(|error| error.to_string())
}

/// Encode one typed JSON-header-plus-binary request frame.
///
/// # Errors
///
/// Returns an error for a stale version, inconsistent length, or exceeded bound.
pub fn encode_request_frame(
    request: &BrowserRequest,
    content: &[u8],
) -> Result<Vec<u8>, BrowserProtocolError> {
    if request.version != BROWSER_PROTOCOL_VERSION {
        return Err(BrowserProtocolError::Frame(format!(
            "cannot encode request version {}; expected {BROWSER_PROTOCOL_VERSION}",
            request.version
        )));
    }
    validate_record_bound(
        request.content_length,
        matches!(request.body, BrowserRequestBody::ChunkProtocol),
    )?;
    encode_frame(request, request.content_length, content, "request")
}

/// Encode one typed JSON-header-plus-binary response frame.
///
/// # Errors
///
/// Returns an error for a stale version, inconsistent length, or exceeded bound.
pub fn encode_response_frame(
    response: &BrowserResponse,
    content: &[u8],
) -> Result<Vec<u8>, BrowserProtocolError> {
    if response.version != BROWSER_PROTOCOL_VERSION {
        return Err(BrowserProtocolError::Frame(format!(
            "cannot encode response version {}; expected {BROWSER_PROTOCOL_VERSION}",
            response.version
        )));
    }
    validate_record_bound(
        response.content_length,
        matches!(response.body, BrowserResponseBody::ChunkProtocol),
    )?;
    encode_frame(response, response.content_length, content, "response")
}

fn validate_record_bound(length: usize, chunk_protocol: bool) -> Result<(), BrowserProtocolError> {
    let maximum = if chunk_protocol {
        MAX_BROWSER_CONTENT_BYTES
    } else {
        MAX_BROWSER_RECORD_BYTES
    };
    if length > maximum {
        return Err(BrowserProtocolError::Frame(format!(
            "content must be at most {maximum} bytes"
        )));
    }
    Ok(())
}

fn encode_frame<T: Serialize>(
    header: &T,
    declared_content_length: usize,
    content: &[u8],
    direction: &str,
) -> Result<Vec<u8>, BrowserProtocolError> {
    validate_content_length(declared_content_length, content.len(), direction)?;
    let header = serde_json::to_vec(header)
        .map_err(|error| BrowserProtocolError::Frame(error.to_string()))?;
    validate_header_length(header.len())?;
    let capacity = 4usize
        .checked_add(header.len())
        .and_then(|size| size.checked_add(content.len()))
        .ok_or_else(|| BrowserProtocolError::Frame(format!("{direction} length overflow")))?;
    let header_length = u32::try_from(header.len())
        .map_err(|_| BrowserProtocolError::Frame(format!("{direction} header length overflow")))?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&header_length.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(content);
    Ok(frame)
}

/// Parse a complete request without copying its binary content.
///
/// The returned offset identifies the first content byte in `frame`.
///
/// # Errors
///
/// Returns an error for malformed JSON, invalid lengths, or exceeded bounds.
pub fn parse_request_header(
    frame: &[u8],
    max_header_bytes: usize,
) -> Result<(BrowserRequest, usize), BrowserProtocolError> {
    let (header, content_offset) = split_header(frame, max_header_bytes, "request")?;
    let request: BrowserRequest = serde_json::from_slice(header).map_err(|error| {
        BrowserProtocolError::Frame(format!("request JSON is invalid: {error}"))
    })?;
    validate_record_bound(
        request.content_length,
        matches!(request.body, BrowserRequestBody::ChunkProtocol),
    )?;
    validate_complete_length(
        frame.len(),
        content_offset,
        request.content_length,
        "request",
    )?;
    Ok((request, content_offset))
}

/// Parse one complete length-prefixed browser request.
///
/// # Errors
///
/// Returns an error for malformed JSON, invalid lengths, or exceeded bounds.
pub fn parse_request_frame(frame: &[u8]) -> Result<BrowserRequestFrame, BrowserProtocolError> {
    let (request, content_offset) = parse_request_header(frame, MAX_BROWSER_HEADER_BYTES)?;
    Ok(BrowserRequestFrame {
        request,
        content: frame[content_offset..].to_vec(),
    })
}

/// Parse one complete length-prefixed browser response.
///
/// # Errors
///
/// Returns an error for malformed JSON, stale versions, or invalid lengths.
pub fn parse_response_frame(frame: &[u8]) -> Result<BrowserResponseFrame, BrowserProtocolError> {
    let (response, content_offset, frame_length) = parse_response_header(frame)?;
    if frame.len() != frame_length {
        return Err(BrowserProtocolError::Frame(format!(
            "response length mismatch: declared {} content bytes",
            response.content_length
        )));
    }
    Ok(BrowserResponseFrame {
        header: response,
        content: frame[content_offset..].to_vec(),
    })
}

/// Determine a frame's complete length once its JSON header is available.
///
/// # Errors
///
/// Returns an error when an available header is malformed or exceeds a bound.
pub fn response_frame_length(frame: &[u8]) -> Result<Option<usize>, BrowserProtocolError> {
    if frame.len() < 4 {
        return Ok(None);
    }
    let header_length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| BrowserProtocolError::Frame("missing header length".to_string()))?,
    ) as usize;
    validate_header_length(header_length)?;
    if frame.len() < 4 + header_length {
        return Ok(None);
    }
    parse_response_header(frame).map(|(_, _, length)| Some(length))
}

fn parse_response_header(
    frame: &[u8],
) -> Result<(BrowserResponse, usize, usize), BrowserProtocolError> {
    let (header, content_offset) = split_header(frame, MAX_BROWSER_HEADER_BYTES, "response")?;
    let response: BrowserResponse = serde_json::from_slice(header).map_err(|error| {
        BrowserProtocolError::Frame(format!("response JSON is invalid: {error}"))
    })?;
    if response.version != BROWSER_PROTOCOL_VERSION {
        return Err(BrowserProtocolError::Frame(format!(
            "unsupported response version {}",
            response.version
        )));
    }
    validate_record_bound(
        response.content_length,
        matches!(response.body, BrowserResponseBody::ChunkProtocol),
    )?;
    let frame_length = content_offset
        .checked_add(response.content_length)
        .ok_or_else(|| BrowserProtocolError::Frame("response length overflow".to_string()))?;
    if response.content_length > MAX_BROWSER_CONTENT_BYTES {
        return Err(BrowserProtocolError::Frame(
            "invalid response content length".to_string(),
        ));
    }
    Ok((response, content_offset, frame_length))
}

fn split_header<'a>(
    frame: &'a [u8],
    max_header_bytes: usize,
    direction: &str,
) -> Result<(&'a [u8], usize), BrowserProtocolError> {
    if frame.len() < 4 {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} ended before its four-byte header length"
        )));
    }
    let header_length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| BrowserProtocolError::Frame("missing header length".to_string()))?,
    ) as usize;
    if header_length == 0 || header_length > max_header_bytes {
        return Err(BrowserProtocolError::Frame(format!(
            "invalid {direction} header length {header_length}"
        )));
    }
    let content_offset = 4usize.checked_add(header_length).ok_or_else(|| {
        BrowserProtocolError::Frame(format!("{direction} header length overflow"))
    })?;
    if content_offset > frame.len() {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} ended inside its JSON header"
        )));
    }
    Ok((&frame[4..content_offset], content_offset))
}

fn validate_header_length(header_length: usize) -> Result<(), BrowserProtocolError> {
    if header_length == 0 || header_length > MAX_BROWSER_HEADER_BYTES {
        return Err(BrowserProtocolError::Frame(format!(
            "invalid browser header length {header_length}"
        )));
    }
    Ok(())
}

fn validate_content_length(
    declared: usize,
    actual: usize,
    direction: &str,
) -> Result<(), BrowserProtocolError> {
    if declared > MAX_BROWSER_CONTENT_BYTES {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} content must be at most {MAX_BROWSER_CONTENT_BYTES} bytes"
        )));
    }
    if declared != actual {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} declares {declared} content bytes but carries {actual}"
        )));
    }
    Ok(())
}

fn validate_complete_length(
    frame_length: usize,
    content_offset: usize,
    content_length: usize,
    direction: &str,
) -> Result<(), BrowserProtocolError> {
    if content_length > MAX_BROWSER_CONTENT_BYTES {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} content length {content_length} exceeds {MAX_BROWSER_CONTENT_BYTES}"
        )));
    }
    let expected = content_offset
        .checked_add(content_length)
        .ok_or_else(|| BrowserProtocolError::Frame(format!("{direction} length overflow")))?;
    if frame_length != expected {
        return Err(BrowserProtocolError::Frame(format!(
            "{direction} contains {frame_length} bytes; declared frame length is {expected}"
        )));
    }
    Ok(())
}

/// Validate metadata received inside an authenticated post-quantum session.
///
/// # Errors
///
/// Returns an error if the protocol, endpoint, or peer identity does not match.
pub fn validate_hello_metadata(
    hello: &BrowserHello,
    expected_endpoint: &WebRtcDirectEndpoint,
) -> Result<String, BrowserProtocolError> {
    if hello.response_type != "hello" {
        return Err(BrowserProtocolError::Identity(
            "expected a HELLO response".to_string(),
        ));
    }
    if hello.protocol != BROWSER_PROTOCOL_NAME {
        return Err(BrowserProtocolError::Identity(format!(
            "unsupported browser protocol {}",
            hello.protocol
        )));
    }
    let peer_id = normalize_hex(&hello.peer_id, 32).map_err(BrowserProtocolError::Identity)?;
    let advertised = parse_webrtc_direct_multiaddr(&hello.endpoint.multiaddr)
        .map_err(|error| BrowserProtocolError::Identity(error.to_string()))?;
    if advertised.multiaddr != expected_endpoint.multiaddr || advertised.peer_id != peer_id {
        return Err(BrowserProtocolError::Identity(
            "node advertised a different WebRTC Direct endpoint".to_string(),
        ));
    }
    if peer_id != expected_endpoint.peer_id {
        return Err(BrowserProtocolError::Identity(format!(
            "endpoint identity mismatch: expected {}, received {peer_id}",
            expected_endpoint.peer_id
        )));
    }
    Ok(peer_id)
}

/// Build the certificate-pinned ICE-lite SDP answer for a direct endpoint.
///
/// # Errors
///
/// Returns an error when the v2 ICE credential is invalid.
pub fn server_answer_sdp(
    endpoint: &WebRtcDirectEndpoint,
    server_ufrag: &str,
) -> Result<String, BrowserProtocolError> {
    validate_v2_server_ufrag(server_ufrag)?;
    let ip_version = if endpoint.host_protocol == "ip4" {
        "IP4"
    } else {
        "IP6"
    };
    let fingerprint = endpoint
        .certificate_hash
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(format!(
        "v=0\r\no=- 0 0 IN {ip_version} {host}\r\ns=-\r\nt=0 0\r\na=ice-lite\r\nm=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN {ip_version} {host}\r\na=mid:0\r\na=ice-options:ice2\r\na=ice-ufrag:{credential}\r\na=ice-pwd:{credential}\r\na=fingerprint:sha-256 {fingerprint}\r\na=setup:passive\r\na=sctp-port:5000\r\na=max-message-size:{WEBRTC_WRITE_CHUNK_BYTES}\r\na=candidate:1467250027 1 UDP 1467250027 {host} {port} typ host\r\na=end-of-candidates\r\n",
        host = endpoint.host,
        port = endpoint.port,
        credential = server_ufrag,
    ))
}

/// Read the effective browser-generated ICE password from a local SDP offer.
///
/// # Errors
///
/// Returns an error for a missing, invalid, or ambiguous ICE password.
pub fn ice_password_from_sdp(sdp: &str) -> Result<String, BrowserProtocolError> {
    if sdp.is_empty() {
        return Err(BrowserProtocolError::Frame(
            "browser created an empty WebRTC offer".to_string(),
        ));
    }

    let mut passwords = sdp
        .lines()
        .filter_map(|line| line.strip_prefix("a=ice-pwd:"));
    let password = passwords.next().ok_or_else(|| {
        BrowserProtocolError::Frame(
            "browser local description did not contain an ICE password".to_string(),
        )
    })?;
    if !is_valid_ice_pwd(password) {
        return Err(BrowserProtocolError::Frame(
            "browser local description contained an invalid ICE password".to_string(),
        ));
    }
    if passwords.any(|other| other != password) {
        return Err(BrowserProtocolError::Frame(
            "browser local description contained multiple ICE passwords".to_string(),
        ));
    }
    Ok(password.to_string())
}

/// Build the v2 server username fragment that carries the browser's ICE password.
///
/// # Errors
///
/// Returns an error when the browser password cannot form a valid v2 credential.
pub fn v2_server_ice_credential(client_pwd: &str) -> Result<String, BrowserProtocolError> {
    if !is_valid_ice_pwd(client_pwd) {
        return Err(BrowserProtocolError::Endpoint(
            "invalid browser ICE password for WebRTC Direct v2".to_string(),
        ));
    }
    let server_ufrag = format!("saorsa+webrtc+v2/{client_pwd}");
    if !is_valid_ice_ufrag(&server_ufrag) {
        return Err(BrowserProtocolError::Endpoint(
            "browser ICE password is too long for WebRTC Direct v2".to_string(),
        ));
    }
    Ok(server_ufrag)
}

fn validate_v2_server_ufrag(value: &str) -> Result<(), BrowserProtocolError> {
    let client_pwd = value.strip_prefix("saorsa+webrtc+v2/").ok_or_else(|| {
        BrowserProtocolError::Endpoint(
            "unsupported Saorsa WebRTC Direct connection profile".to_string(),
        )
    })?;
    if !is_valid_ice_ufrag(value) || !is_valid_ice_pwd(client_pwd) {
        return Err(BrowserProtocolError::Endpoint(
            "invalid Saorsa WebRTC Direct v2 ICE credential".to_string(),
        ));
    }
    Ok(())
}

fn is_ice_char_string(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn is_valid_ice_ufrag(value: &str) -> bool {
    (4..=256).contains(&value.len()) && is_ice_char_string(value)
}

fn is_valid_ice_pwd(value: &str) -> bool {
    (22..=256).contains(&value.len()) && is_ice_char_string(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn shared_protocol_allows_proof_overhead_but_preserves_record_limit() {
        let content = vec![0; MAX_BROWSER_RECORD_BYTES + 4096];
        let request = BrowserRequest {
            version: BROWSER_PROTOCOL_VERSION,
            request_id: 1,
            content_length: content.len(),
            body: BrowserRequestBody::ChunkProtocol,
        };
        let encoded = encode_request_frame(&request, &content).unwrap();
        assert_eq!(parse_request_frame(&encoded).unwrap().content, content);
        let response = BrowserResponse::ok(1, BrowserResponseBody::ChunkProtocol, content.len());
        let encoded = encode_response_frame(&response, &content).unwrap();
        assert_eq!(parse_response_frame(&encoded).unwrap().content, content);
        let oversized = vec![0; MAX_BROWSER_CONTENT_BYTES + 1];
        let response = BrowserResponse::ok(1, BrowserResponseBody::ChunkProtocol, oversized.len());
        assert!(encode_response_frame(&response, &oversized).is_err());
        let response = BrowserResponse::ok(
            1,
            BrowserResponseBody::Chunk {
                address: "00".repeat(32),
                size: content.len(),
            },
            content.len(),
        );
        assert!(encode_response_frame(&response, &content).is_err());
        // Reject a forged length from the header before waiting for its body.
        let header = serde_json::to_vec(&response).unwrap();
        let mut forged = (header.len() as u32).to_be_bytes().to_vec();
        forged.extend(header);
        assert!(response_frame_length(&forged).is_err());
    }

    fn endpoint() -> BrowserEndpoint {
        BrowserEndpoint::new(
            "127.0.0.1:24000".parse().expect("socket address"),
            &[0xab; 32],
            [0x11; 32],
        )
        .expect("endpoint")
    }

    #[test]
    fn canonical_endpoint_round_trips() {
        let endpoint = endpoint();
        let parsed = endpoint.parse().expect("parse endpoint");
        assert_eq!(parsed.host_protocol, "ip4");
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 24000);
        assert_eq!(parsed.peer_id_bytes().expect("peer ID"), [0xab; 32]);
        assert_eq!(parsed.certificate_hash, [0x11; 32]);
        assert_eq!(
            parsed.socket_addr().expect("socket address"),
            "127.0.0.1:24000".parse().expect("socket address")
        );
    }

    #[test]
    fn rejects_noncanonical_or_unpinned_endpoints() {
        let endpoint = endpoint().multiaddr;
        assert!(
            parse_webrtc_direct_multiaddr(&endpoint.replace("/ip4/127.0.0.1", "/dns/node.example"))
                .is_err()
        );
        let normalized = parse_webrtc_direct_multiaddr(
            &endpoint
                .replace("/udp/24000", "/udp/024000")
                .replace(&"ab".repeat(32), &"AB".repeat(32)),
        )
        .expect("normalize endpoint");
        assert_eq!(normalized.multiaddr, endpoint);
    }

    #[test]
    fn typed_request_and_response_frames_round_trip() {
        let request = BrowserRequest::new(
            9,
            BrowserRequestBody::GetChunk {
                address: "11".repeat(32),
            },
            3,
        );
        let request_frame = encode_request_frame(&request, &[1, 2, 3]).expect("encode request");
        let parsed_request = parse_request_frame(&request_frame).expect("parse request");
        assert_eq!(parsed_request.request, request);
        assert_eq!(parsed_request.content, vec![1, 2, 3]);

        let response = BrowserResponse::ok(
            9,
            BrowserResponseBody::Chunk {
                address: "11".repeat(32),
                size: 3,
            },
            3,
        );
        let response_frame = encode_response_frame(&response, &[1, 2, 3]).expect("encode response");
        assert_eq!(
            response_frame_length(&response_frame).expect("length"),
            Some(response_frame.len())
        );
        let parsed_response = parse_response_frame(&response_frame).expect("parse response");
        assert_eq!(parsed_response.header, response);
        assert_eq!(parsed_response.content, vec![1, 2, 3]);
    }

    #[test]
    fn rejects_stale_v4_and_length_mismatches() {
        let stale = serde_json::json!({
            "version": 4,
            "request_id": 1,
            "status": "ok",
            "content_length": 0,
            "type": "chunk_not_found",
            "address": "11".repeat(32),
        });
        let header = serde_json::to_vec(&stale).expect("serialize");
        let mut frame = Vec::new();
        frame.extend_from_slice(
            &u32::try_from(header.len())
                .expect("header length")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&header);
        assert!(parse_response_frame(&frame).is_err());

        let request = BrowserRequest::new(1, BrowserRequestBody::Hello, 1);
        assert!(encode_request_frame(&request, &[]).is_err());
    }

    #[test]
    fn validates_hello_against_authenticated_endpoint() {
        let expected = endpoint().parse().expect("parse endpoint");
        let hello = BrowserHello {
            response_type: "hello".to_string(),
            protocol: BROWSER_PROTOCOL_NAME.to_string(),
            peer_id: "ab".repeat(32),
            endpoint: endpoint(),
            max_chunk_size: MAX_BROWSER_RECORD_BYTES,
            capabilities: vec!["get_chunk".to_string()],
            payment: BrowserPaymentNetwork {
                chain_id: 31337,
                payment_token_address: "11".repeat(20),
                payment_vault_address: "22".repeat(20),
            },
        };
        assert_eq!(
            validate_hello_metadata(&hello, &expected).expect("HELLO"),
            "ab".repeat(32)
        );
    }

    #[test]
    fn payment_metadata_contains_identity_without_rpc_configuration() {
        let payment = BrowserPaymentNetwork {
            chain_id: 31337,
            payment_token_address: "11".repeat(20),
            payment_vault_address: "22".repeat(20),
        };
        let value = serde_json::to_value(payment).expect("payment JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "chain_id": 31337,
                "payment_token_address": "11".repeat(20),
                "payment_vault_address": "22".repeat(20),
            })
        );
        assert!(
            serde_json::from_value::<BrowserPaymentNetwork>(serde_json::json!({
                "chain_id": 31337,
                "rpc_url": "https://operator.invalid/private-key",
                "payment_token_address": "11".repeat(20),
                "payment_vault_address": "22".repeat(20),
            }))
            .is_err()
        );
    }

    #[test]
    fn synthesizes_pinned_v2_answer_without_mutating_the_offer() {
        let endpoint = endpoint().parse().expect("parse endpoint");
        let offer = "v=0\r\na=ice-ufrag:browserUfrag\r\na=ice-pwd:browserClientPassword1234\r\n";
        let password = ice_password_from_sdp(offer).expect("ICE password");
        let credential = v2_server_ice_credential(&password).expect("credential");
        let answer = server_answer_sdp(&endpoint, &credential).expect("answer");
        assert!(answer.contains("a=ice-lite"));
        assert!(answer.contains("a=fingerprint:sha-256 11:11:11:11"));
        assert!(answer.contains(&format!("a=ice-ufrag:{credential}")));
    }

    #[test]
    fn value_shape_uses_the_v5_json_contract() {
        let response = BrowserResponse::ok(
            42,
            BrowserResponseBody::Chunk {
                address: "11".repeat(32),
                size: 3,
            },
            3,
        );
        let value = serde_json::to_value(response).expect("response JSON");
        assert_eq!(value["version"], Value::from(5));
        assert_eq!(value["request_id"], Value::from(42));
        assert_eq!(value["status"], Value::from("ok"));
        assert_eq!(value["type"], Value::from("chunk"));
    }
    #[test]
    fn legacy_find_node_defaults_to_unsigned_hints() {
        let request: BrowserRequestBody = serde_json::from_value(serde_json::json!({
            "type": "find_node", "target": "11".repeat(32), "count": 20
        }))
        .expect("legacy request");
        assert!(matches!(
            request,
            BrowserRequestBody::FindNode {
                with_address_records: false,
                ..
            }
        ));
        let node: BrowserNode = serde_json::from_value(serde_json::json!({
            "peer_id": "11".repeat(32), "native_addresses": [], "reliability": 1.0
        }))
        .expect("legacy node");
        assert!(node.address_record.is_none());
    }
}
