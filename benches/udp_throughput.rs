// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! End-to-end UDP/QUIC throughput benchmark.
//!
//! Measures unidirectional bulk transfer over a loopback QUIC connection to
//! establish a baseline for send-path changes (GSO coalescing, pacing,
//! bounded channels, etc.). Reports bytes/sec so Criterion prints MB/s.
//!
//! Run:   cargo bench --bench udp_throughput

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use saorsa_transport::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    high_level::default_runtime,
};
use tokio::runtime::Runtime;

/// Bytes transferred per iteration. 64 MiB gives a stable measurement while
/// keeping individual iterations under a second on typical loopback.
const TRANSFER_BYTES: u64 = 64 * 1024 * 1024;

/// Stream write chunk size. 256 KiB matches a typical bulk-upload application.
const CHUNK_SIZE: usize = 256 * 1024;

/// Server-side receive buffer size per `read()` call.
const RECV_BUF_SIZE: usize = 64 * 1024;

/// Fill byte for the synthetic payload — any non-zero value is fine; chosen so
/// that dropped bytes are trivially visible in a packet capture.
const FILL_BYTE: u8 = 0xAB;

/// ALPN used by the benchmark endpoints.
const ALPN: &[u8] = b"saorsa-bench";

/// Number of Criterion samples. Each sample is one full 64 MiB transfer over a
/// fresh connection, so 10 keeps total runtime bounded.
const BENCH_SAMPLE_SIZE: usize = 10;

/// Upper bound on total measurement time per benchmark function.
const BENCH_MEASUREMENT_SECS: u64 = 15;

fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

struct Pair {
    server: Endpoint,
    server_addr: SocketAddr,
    client: Endpoint,
}

fn build_pair() -> Pair {
    let (cert, key) = generate_test_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));

    let server_socket =
        std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let runtime = default_runtime().expect("default_runtime");
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .unwrap();

    let client_socket =
        std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let mut client =
        Endpoint::new(EndpointConfig::default(), None, client_socket, runtime).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client.set_default_client_config(client_config);

    Pair {
        server,
        server_addr,
        client,
    }
}

/// Run one unidirectional transfer of `TRANSFER_BYTES` and return elapsed time
/// from first byte written to server-side stream finish.
async fn one_transfer(pair: &Pair) -> Duration {
    let server = pair.server.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming");
        let connection = incoming.await.expect("accept");
        let mut recv = connection.accept_uni().await.expect("accept_uni");
        let mut total = 0u64;
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        while let Some(n) = recv.read(&mut buf).await.expect("read") {
            total += n as u64;
        }
        total
    });

    let connection = pair
        .client
        .connect(pair.server_addr, "localhost")
        .expect("connect")
        .await
        .expect("connect await");

    let mut send = connection.open_uni().await.expect("open_uni");
    let chunk = vec![FILL_BYTE; CHUNK_SIZE];

    let start = Instant::now();
    let mut remaining = TRANSFER_BYTES as usize;
    while remaining > 0 {
        let n = remaining.min(CHUNK_SIZE);
        send.write_all(&chunk[..n]).await.expect("write_all");
        remaining -= n;
    }
    send.finish().expect("finish");

    let total = server_task.await.expect("server join");
    let elapsed = start.elapsed();
    assert_eq!(total, TRANSFER_BYTES, "server did not receive full payload");
    elapsed
}

fn bench_udp_throughput(c: &mut Criterion) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("udp_throughput");
    group.throughput(Throughput::Bytes(TRANSFER_BYTES));
    group.sample_size(BENCH_SAMPLE_SIZE);
    group.measurement_time(Duration::from_secs(BENCH_MEASUREMENT_SECS));

    group.bench_function("loopback_uni_64mib", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let pair = build_pair();
                    total += one_transfer(&pair).await;
                }
                total
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_udp_throughput);
criterion_main!(benches);
