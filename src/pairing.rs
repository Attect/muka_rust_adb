use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
#[cfg(test)]
use aws_lc_sys::spake2_role_t_spake2_role_bob;
use aws_lc_sys::{
    SPAKE2_CTX, SPAKE2_CTX_free, SPAKE2_CTX_new, SPAKE2_MAX_KEY_SIZE, SPAKE2_MAX_MSG_SIZE,
    SPAKE2_generate_msg, SPAKE2_process_msg, spake2_role_t_spake2_role_alice,
};
use hkdf::Hkdf;
use rand::RngCore;
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::Sha256;

use crate::auth::{self, AuthKey};
use crate::error::{AdbError, Result};
use crate::protocol::{self, AdbMessage};

const TLS_EXPORT_LABEL: &[u8] = b"adb-label";
const TLS_EXPORT_SIZE: usize = 64;
const PAIRING_HEADER_VERSION: u8 = 1;
const PACKET_SPAKE2: u8 = 0;
const PACKET_PEER_INFO: u8 = 1;
const PEER_INFO_SIZE: usize = 8192;
const PEER_INFO_DATA_SIZE: usize = PEER_INFO_SIZE - 1;
const PEER_TYPE_RSA_PUBLIC_KEY: u8 = 0;
const PEER_TYPE_DEVICE_GUID: u8 = 1;
const MAX_PAIRING_PAYLOAD: usize = PEER_INFO_SIZE * 2;
const PAIRING_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_NAME: &[u8] = b"adb pair client\0";
const SERVER_NAME: &[u8] = b"adb pair server\0";
const AES_KEY_INFO: &[u8] = b"adb pairing_auth aes-128-gcm key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSuccess {
    pub guid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFailureKind {
    UnableToCreateClient,
    UnableToStartClient,
    AuthenticationFailed,
}

#[derive(Debug)]
pub struct PairingFailure {
    kind: PairingFailureKind,
    detail: String,
}

impl PairingFailure {
    fn new(kind: PairingFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub fn official_message(&self) -> &'static str {
        match self.kind {
            PairingFailureKind::UnableToCreateClient => "Failed: unable to create pairing client.",
            PairingFailureKind::UnableToStartClient => "Failed: Unable to start pairing client.",
            PairingFailureKind::AuthenticationFailed => {
                "Failed: Wrong password or connection was dropped."
            }
        }
    }
}

impl fmt::Display for PairingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.official_message(), self.detail)
    }
}

impl std::error::Error for PairingFailure {}

/// 按 AOSP pairing client 流程完成 TLS、SPAKE2 和 PeerInfo 交换。
pub fn pair_device(
    target: &str,
    password: &str,
    auth_key: &AuthKey,
) -> std::result::Result<PairingSuccess, PairingFailure> {
    let identity = TlsIdentity::from_auth_key(auth_key).map_err(|err| {
        PairingFailure::new(PairingFailureKind::UnableToCreateClient, err.to_string())
    })?;
    let public_key = auth_key.public_key_text().map_err(|err| {
        PairingFailure::new(PairingFailureKind::UnableToCreateClient, err.to_string())
    })?;
    let socket = connect_with_timeout(target).map_err(|err| {
        PairingFailure::new(PairingFailureKind::UnableToStartClient, err.to_string())
    })?;
    let mut tls = start_client_tls(socket, &identity).map_err(|err| {
        PairingFailure::new(PairingFailureKind::AuthenticationFailed, err.to_string())
    })?;

    let own_info =
        encode_peer_info(PEER_TYPE_RSA_PUBLIC_KEY, public_key.as_bytes()).map_err(|err| {
            PairingFailure::new(PairingFailureKind::UnableToCreateClient, err.to_string())
        })?;
    let peer_info = exchange_peer_info(&mut tls, PairingRole::Client, password, &own_info)
        .map_err(|err| {
            PairingFailure::new(PairingFailureKind::AuthenticationFailed, err.to_string())
        })?;
    let guid = decode_device_guid(&peer_info).map_err(|err| {
        PairingFailure::new(PairingFailureKind::AuthenticationFailed, err.to_string())
    })?;
    Ok(PairingSuccess { guid })
}

pub fn record_known_host(guid: &str) -> Result<()> {
    record_known_host_at(&auth::android_dir()?.join("adb_known_hosts.pb"), guid)
}

pub fn is_known_host(guid: &str) -> bool {
    auth::android_dir()
        .ok()
        .is_some_and(|directory| is_known_host_at(&directory.join("adb_known_hosts.pb"), guid))
}

fn connect_with_timeout(target: &str) -> io::Result<TcpStream> {
    let addresses = target.to_socket_addrs()?.collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pairing 地址没有可用的 socket address",
        ));
    }

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, PAIRING_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(PAIRING_TIMEOUT))?;
                stream.set_write_timeout(Some(PAIRING_TIMEOUT))?;
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("无法连接 pairing 地址")))
}

pub(crate) struct TlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
}

impl TlsIdentity {
    pub(crate) fn from_auth_key(auth_key: &AuthKey) -> Result<Self> {
        let private_key = auth_key.private_key_pkcs8_der()?;
        let private_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.clone()));
        let key_pair = KeyPair::from_der_and_sign_algo(&private_der, &PKCS_RSA_SHA256)
            .map_err(|err| AdbError::Protocol(format!("无法从 adbkey 创建 TLS key: {err}")))?;
        let certificate = CertificateParams::default()
            .self_signed(&key_pair)
            .map_err(|err| AdbError::Protocol(format!("无法生成 pairing X.509 证书: {err}")))?;
        Ok(Self {
            certificate: certificate.der().clone(),
            private_key,
        })
    }

    #[cfg(test)]
    pub(crate) fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate()
            .map_err(|err| AdbError::Protocol(format!("无法生成测试 TLS key: {err}")))?;
        let certificate = CertificateParams::default()
            .self_signed(&key_pair)
            .map_err(|err| AdbError::Protocol(format!("无法生成测试 X.509 证书: {err}")))?;
        Ok(Self {
            certificate: certificate.der().clone(),
            private_key: key_pair.serialize_der(),
        })
    }

    pub(crate) fn rustls_private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key.clone()))
    }
}

fn start_client_tls(
    socket: TcpStream,
    identity: &TlsIdentity,
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = Arc::new(AcceptAnyServerCertificate {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| AdbError::Protocol(format!("无法配置 pairing TLS 1.3: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![identity.certificate.clone()],
            identity.rustls_private_key(),
        )
        .map_err(|err| AdbError::Protocol(format!("无法配置 pairing 客户端证书: {err}")))?;
    let server_name = ServerName::try_from("adb-pairing")
        .map_err(|err| AdbError::Protocol(format!("非法 pairing TLS server name: {err}")))?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| AdbError::Protocol(format!("无法创建 pairing TLS 连接: {err}")))?;
    let mut stream = StreamOwned::new(connection, socket);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|err| AdbError::Protocol(format!("pairing TLS 握手失败: {err}")))?;
    }
    Ok(stream)
}

#[derive(Clone)]
pub(crate) struct AdbTlsConnection {
    shared: Arc<AdbTlsShared>,
}

struct AdbTlsShared {
    outgoing: Sender<OutgoingPacket>,
    incoming: Mutex<Receiver<IncomingPacket>>,
    socket: TcpStream,
    closed: Arc<AtomicBool>,
}

struct OutgoingPacket {
    packet: AdbMessage,
    protocol_version: u32,
}

enum IncomingPacket {
    Packet(AdbMessage),
    Error(String),
}

impl AdbTlsConnection {
    pub(crate) fn connect(socket: TcpStream, auth_key: &AuthKey) -> Result<Self> {
        let identity = TlsIdentity::from_auth_key(auth_key)?;
        let tls = start_client_tls(socket, &identity)?;
        tls.sock.set_nonblocking(true)?;
        let shutdown_socket = tls.sock.try_clone()?;
        let (outgoing, outgoing_receiver) = mpsc::channel();
        let (incoming_sender, incoming) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(AdbTlsShared {
            outgoing,
            incoming: Mutex::new(incoming),
            socket: shutdown_socket,
            closed: Arc::clone(&closed),
        });
        spawn_adb_tls_pump(tls, outgoing_receiver, incoming_sender, closed);
        Ok(Self { shared })
    }

    pub(crate) fn read_packet(&self, max_payload: usize) -> Result<AdbMessage> {
        let incoming = self.shared.incoming.lock().expect("TLS incoming poisoned");
        match incoming.recv() {
            Ok(IncomingPacket::Packet(packet)) => {
                if packet.payload.len() > max_payload {
                    return Err(AdbError::Protocol(format!(
                        "TLS ADB payload 过大: {} > {max_payload}",
                        packet.payload.len()
                    )));
                }
                Ok(packet)
            }
            Ok(IncomingPacket::Error(message)) => Err(AdbError::Protocol(message)),
            Err(_) => Err(AdbError::Protocol("TLS ADB transport 已关闭".to_string())),
        }
    }

    pub(crate) fn write_packet(&self, packet: &AdbMessage, protocol_version: u32) -> Result<()> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(AdbError::Protocol("TLS ADB transport 已关闭".to_string()));
        }
        self.shared
            .outgoing
            .send(OutgoingPacket {
                packet: packet.clone(),
                protocol_version,
            })
            .map_err(|_| AdbError::Protocol("TLS ADB writer 已关闭".to_string()))
    }

    pub(crate) fn close(&self) -> Result<()> {
        self.shared.closed.store(true, Ordering::SeqCst);
        match self.shared.socket.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }
}

fn spawn_adb_tls_pump(
    mut tls: StreamOwned<ClientConnection, TcpStream>,
    outgoing: Receiver<OutgoingPacket>,
    incoming: Sender<IncomingPacket>,
    closed: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        if let Err(err) = run_adb_tls_pump(&mut tls, &outgoing, &incoming, &closed) {
            let _ = incoming.send(IncomingPacket::Error(err.to_string()));
        }
        closed.store(true, Ordering::SeqCst);
        let _ = tls.sock.shutdown(Shutdown::Both);
    });
}

fn run_adb_tls_pump(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    outgoing: &Receiver<OutgoingPacket>,
    incoming: &Sender<IncomingPacket>,
    closed: &AtomicBool,
) -> Result<()> {
    let mut plaintext = VecDeque::new();
    let mut pending_write: Option<(Vec<u8>, usize)> = None;
    while !closed.load(Ordering::SeqCst) {
        let mut made_progress = false;
        if pending_write.is_none() {
            match outgoing.try_recv() {
                Ok(outgoing) => {
                    let mut wire = Vec::new();
                    outgoing
                        .packet
                        .write_to(&mut wire, outgoing.protocol_version)?;
                    pending_write = Some((wire, 0));
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        if let Some((wire, offset)) = pending_write.as_mut() {
            match tls.conn.writer().write(&wire[*offset..]) {
                Ok(0) => {}
                Ok(written) => {
                    *offset += written;
                    made_progress = true;
                    if *offset == wire.len() {
                        pending_write = None;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err.into()),
            }
        }

        while tls.conn.wants_write() {
            match tls.conn.write_tls(&mut tls.sock) {
                Ok(0) => break,
                Ok(_) => made_progress = true,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        match tls.conn.read_tls(&mut tls.sock) {
            Ok(0) => return Err(AdbError::Protocol("TLS ADB 对端已关闭连接".to_string())),
            Ok(_) => {
                tls.conn
                    .process_new_packets()
                    .map_err(|err| AdbError::Protocol(format!("TLS ADB record 处理失败: {err}")))?;
                made_progress = true;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err.into()),
        }

        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match tls.conn.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    plaintext.extend(&buffer[..read]);
                    made_progress = true;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }
        dispatch_complete_adb_packets(&mut plaintext, incoming)?;

        if !made_progress {
            thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

fn dispatch_complete_adb_packets(
    plaintext: &mut VecDeque<u8>,
    incoming: &Sender<IncomingPacket>,
) -> Result<()> {
    loop {
        if plaintext.len() < 24 {
            return Ok(());
        }
        let data_length =
            u32::from_le_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]])
                as usize;
        if data_length > protocol::MAX_PAYLOAD {
            return Err(AdbError::Protocol(format!(
                "TLS ADB payload 过大: {data_length} > {}",
                protocol::MAX_PAYLOAD
            )));
        }
        let packet_length = 24_usize
            .checked_add(data_length)
            .ok_or_else(|| AdbError::Protocol("TLS ADB packet 长度溢出".to_string()))?;
        if plaintext.len() < packet_length {
            return Ok(());
        }
        let wire = plaintext.drain(..packet_length).collect::<Vec<_>>();
        let packet = AdbMessage::read_from(&mut io::Cursor::new(wire), protocol::MAX_PAYLOAD)?;
        incoming
            .send(IncomingPacket::Packet(packet))
            .map_err(|_| AdbError::Protocol("TLS ADB reader 已关闭".to_string()))?;
    }
}

#[derive(Debug)]
struct AcceptAnyServerCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
#[derive(Debug)]
struct AcceptAnyClientCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

#[cfg(test)]
impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
pub(crate) fn start_test_server_tls(
    socket: TcpStream,
) -> Result<StreamOwned<rustls::ServerConnection, TcpStream>> {
    let identity = TlsIdentity::generate()?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = Arc::new(AcceptAnyClientCertificate {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| AdbError::Protocol(format!("无法配置测试 TLS 1.3: {err}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![identity.certificate.clone()],
            identity.rustls_private_key(),
        )
        .map_err(|err| AdbError::Protocol(format!("无法配置测试 TLS 证书: {err}")))?;
    let connection = rustls::ServerConnection::new(Arc::new(config))
        .map_err(|err| AdbError::Protocol(format!("无法创建测试 TLS server: {err}")))?;
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|err| AdbError::Protocol(format!("测试 TLS 握手失败: {err}")))?;
    }
    Ok(tls)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingRole {
    Client,
    #[cfg(test)]
    Server,
}

fn exchange_peer_info<S: Read + Write + ExportPairingKeyMaterial>(
    stream: &mut S,
    role: PairingRole,
    password: &str,
    own_info: &[u8; PEER_INFO_SIZE],
) -> Result<[u8; PEER_INFO_SIZE]> {
    let mut exported_key = [0_u8; TLS_EXPORT_SIZE];
    export_pairing_key_material(stream, &mut exported_key)?;
    exchange_peer_info_with_exported_key(stream, role, password, &exported_key, own_info)
}

trait ExportPairingKeyMaterial {
    fn export_pairing_key_material(&self, output: &mut [u8]) -> Result<()>;
}

#[cfg(test)]
impl ExportPairingKeyMaterial for StreamOwned<rustls::ServerConnection, TcpStream> {
    fn export_pairing_key_material(&self, output: &mut [u8]) -> Result<()> {
        self.conn
            .export_keying_material(output, TLS_EXPORT_LABEL, None)
            .map(|_| ())
            .map_err(|err| {
                AdbError::Protocol(format!("无法导出测试 pairing TLS key material: {err}"))
            })
    }
}

impl ExportPairingKeyMaterial for StreamOwned<ClientConnection, TcpStream> {
    fn export_pairing_key_material(&self, output: &mut [u8]) -> Result<()> {
        self.conn
            .export_keying_material(output, TLS_EXPORT_LABEL, None)
            .map(|_| ())
            .map_err(|err| AdbError::Protocol(format!("无法导出 pairing TLS key material: {err}")))
    }
}

fn export_pairing_key_material<S>(stream: &S, output: &mut [u8]) -> Result<()>
where
    S: Read + Write + ExportPairingKeyMaterial,
{
    stream.export_pairing_key_material(output)
}

fn exchange_peer_info_with_exported_key<S: Read + Write>(
    stream: &mut S,
    role: PairingRole,
    password: &str,
    exported_key: &[u8],
    own_info: &[u8; PEER_INFO_SIZE],
) -> Result<[u8; PEER_INFO_SIZE]> {
    let mut spake_password = password.as_bytes().to_vec();
    spake_password.extend_from_slice(exported_key);
    let (spake, our_message) = Spake2Context::new(role, &spake_password)?;

    write_pairing_packet(stream, PACKET_SPAKE2, &our_message)?;
    stream.flush()?;
    let their_message = read_pairing_packet(stream, PACKET_SPAKE2)?;
    let key_material = spake.finish(&their_message)?;
    let mut cipher = PairingCipher::new(&key_material)?;

    let encrypted = cipher.encrypt(own_info)?;
    write_pairing_packet(stream, PACKET_PEER_INFO, &encrypted)?;
    stream.flush()?;
    let encrypted_peer = read_pairing_packet(stream, PACKET_PEER_INFO)?;
    let peer = cipher.decrypt(&encrypted_peer)?;
    peer.try_into().map_err(|peer: Vec<u8>| {
        AdbError::Protocol(format!(
            "pairing PeerInfo 长度应为 {PEER_INFO_SIZE}，实际为 {}",
            peer.len()
        ))
    })
}

struct Spake2Context(*mut SPAKE2_CTX);

impl Spake2Context {
    fn new(role: PairingRole, password: &[u8]) -> Result<(Self, Vec<u8>)> {
        let (spake_role, our_name, their_name) = match role {
            PairingRole::Client => (spake2_role_t_spake2_role_alice, CLIENT_NAME, SERVER_NAME),
            #[cfg(test)]
            PairingRole::Server => (spake2_role_t_spake2_role_bob, SERVER_NAME, CLIENT_NAME),
        };
        // AWS-LC 与 AOSP 都继承 BoringSSL 的 SPAKE2 ABI；名字长度包含尾随 NUL。
        let context = unsafe {
            SPAKE2_CTX_new(
                spake_role,
                our_name.as_ptr(),
                our_name.len(),
                their_name.as_ptr(),
                their_name.len(),
            )
        };
        if context.is_null() {
            return Err(AdbError::Protocol("无法创建 SPAKE2 context".to_string()));
        }
        let context = Self(context);
        let mut message = vec![0_u8; SPAKE2_MAX_MSG_SIZE as usize];
        let mut message_len = 0_usize;
        let status = unsafe {
            SPAKE2_generate_msg(
                context.0,
                message.as_mut_ptr(),
                &mut message_len,
                message.len(),
                password.as_ptr(),
                password.len(),
            )
        };
        if status != 1 || message_len == 0 {
            return Err(AdbError::Protocol("无法生成 SPAKE2 消息".to_string()));
        }
        message.truncate(message_len);
        Ok((context, message))
    }

    fn finish(self, their_message: &[u8]) -> Result<Vec<u8>> {
        if their_message.is_empty() || their_message.len() > SPAKE2_MAX_MSG_SIZE as usize {
            return Err(AdbError::Protocol(format!(
                "非法 SPAKE2 消息长度 {}",
                their_message.len()
            )));
        }
        let mut key = vec![0_u8; SPAKE2_MAX_KEY_SIZE as usize];
        let mut key_len = 0_usize;
        let status = unsafe {
            SPAKE2_process_msg(
                self.0,
                key.as_mut_ptr(),
                &mut key_len,
                key.len(),
                their_message.as_ptr(),
                their_message.len(),
            )
        };
        if status != 1 || key_len == 0 {
            return Err(AdbError::Protocol("无法处理对端 SPAKE2 消息".to_string()));
        }
        key.truncate(key_len);
        Ok(key)
    }
}

impl Drop for Spake2Context {
    fn drop(&mut self) {
        unsafe { SPAKE2_CTX_free(self.0) };
    }
}

struct PairingCipher {
    cipher: Aes128Gcm,
    encrypt_sequence: u64,
    decrypt_sequence: u64,
}

impl PairingCipher {
    fn new(key_material: &[u8]) -> Result<Self> {
        let mut key = [0_u8; 16];
        Hkdf::<Sha256>::new(None, key_material)
            .expand(AES_KEY_INFO, &mut key)
            .map_err(|_| AdbError::Protocol("无法派生 pairing AES key".to_string()))?;
        Ok(Self {
            cipher: Aes128Gcm::new_from_slice(&key)
                .map_err(|_| AdbError::Protocol("无法初始化 pairing AES-128-GCM".to_string()))?,
            encrypt_sequence: 0,
            decrypt_sequence: 0,
        })
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = sequence_nonce(self.encrypt_sequence);
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| AdbError::Protocol("pairing PeerInfo 加密失败".to_string()))?;
        self.encrypt_sequence = self.encrypt_sequence.wrapping_add(1);
        Ok(encrypted)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = sequence_nonce(self.decrypt_sequence);
        let decrypted = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| AdbError::Protocol("pairing PeerInfo 解密失败".to_string()))?;
        self.decrypt_sequence = self.decrypt_sequence.wrapping_add(1);
        Ok(decrypted)
    }
}

fn sequence_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&sequence.to_ne_bytes());
    nonce
}

fn write_pairing_packet<W: Write>(writer: &mut W, packet_type: u8, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAIRING_PAYLOAD {
        return Err(AdbError::Protocol(format!(
            "pairing payload 长度越界: {}",
            payload.len()
        )));
    }
    let mut header = [0_u8; 6];
    header[0] = PAIRING_HEADER_VERSION;
    header[1] = packet_type;
    header[2..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(payload)?;
    Ok(())
}

fn read_pairing_packet<R: Read>(reader: &mut R, expected_type: u8) -> Result<Vec<u8>> {
    let mut header = [0_u8; 6];
    reader.read_exact(&mut header)?;
    if header[0] != PAIRING_HEADER_VERSION {
        return Err(AdbError::Protocol(format!(
            "不支持 pairing header version {}",
            header[0]
        )));
    }
    if header[1] != expected_type {
        return Err(AdbError::Protocol(format!(
            "pairing packet type 应为 {expected_type}，实际为 {}",
            header[1]
        )));
    }
    let payload_len = u32::from_be_bytes(header[2..].try_into().expect("header has 4 bytes"));
    let payload_len = payload_len as usize;
    if payload_len == 0 || payload_len > MAX_PAIRING_PAYLOAD {
        return Err(AdbError::Protocol(format!(
            "pairing payload 长度越界: {payload_len}"
        )));
    }
    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

fn encode_peer_info(kind: u8, data: &[u8]) -> Result<[u8; PEER_INFO_SIZE]> {
    if data.len() > PEER_INFO_DATA_SIZE - 1 {
        return Err(AdbError::Protocol(format!(
            "pairing PeerInfo 数据过长: {}",
            data.len()
        )));
    }
    let mut peer_info = [0_u8; PEER_INFO_SIZE];
    peer_info[0] = kind;
    peer_info[1..1 + data.len()].copy_from_slice(data);
    Ok(peer_info)
}

fn decode_device_guid(peer_info: &[u8; PEER_INFO_SIZE]) -> Result<String> {
    if peer_info[0] != PEER_TYPE_DEVICE_GUID {
        return Err(AdbError::Protocol(format!(
            "pairing server 返回未知 PeerInfo type {}",
            peer_info[0]
        )));
    }
    let data = &peer_info[1..];
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| AdbError::Protocol("pairing server GUID 缺少尾随 NUL".to_string()))?;
    if end == 0 {
        return Err(AdbError::Protocol("pairing server 返回空 GUID".to_string()));
    }
    String::from_utf8(data[..end].to_vec())
        .map_err(|err| AdbError::Protocol(format!("pairing server GUID 不是 UTF-8: {err}")))
}

fn record_known_host_at(path: &Path, guid: &str) -> Result<()> {
    let mut guids = match fs::read(path) {
        Ok(bytes) => decode_known_hosts(&bytes).unwrap_or_default(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err.into()),
    };
    guids.push(guid.to_string());
    let encoded = encode_known_hosts(&guids);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temporary_sibling(path, "tmp");
    let backup_path = temporary_sibling(path, "tbd");
    fs::write(&temp_path, encoded)?;
    let had_old = match fs::rename(path, &backup_path) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }
    };
    if let Err(err) = fs::rename(&temp_path, path) {
        if had_old {
            let _ = fs::rename(&backup_path, path);
        }
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }
    if had_old {
        let _ = fs::remove_file(&backup_path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    Ok(())
}

fn is_known_host_at(path: &Path, guid: &str) -> bool {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let Some(guids) = decode_known_hosts(&bytes) else {
        // 与 AOSP 一致，损坏的 known-hosts 文件不参与信任判断并予以删除。
        let _ = fs::remove_file(path);
        return false;
    };
    guids.iter().any(|known| known == guid)
}

fn temporary_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut random = rand::thread_rng();
    let nonce = random.next_u64();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("adb_known_hosts.pb");
    path.with_file_name(format!(".{name}.{suffix}.{}.{nonce}", std::process::id()))
}

fn encode_known_hosts(guids: &[String]) -> Vec<u8> {
    let mut output = Vec::new();
    for guid in guids {
        let mut host_info = Vec::new();
        encode_length_delimited_field(&mut host_info, 1, guid.as_bytes());
        encode_length_delimited_field(&mut output, 1, &host_info);
    }
    output
}

fn encode_length_delimited_field(output: &mut Vec<u8>, field: u64, value: &[u8]) {
    encode_varint(output, (field << 3) | 2);
    encode_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn encode_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_known_hosts(bytes: &[u8]) -> Option<Vec<String>> {
    let mut guids = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let key = decode_varint(bytes, &mut cursor)?;
        if key == (1 << 3) | 2 {
            let host_info = decode_length_delimited(bytes, &mut cursor)?;
            if let Some(guid) = decode_host_info(host_info) {
                guids.push(guid);
            }
        } else {
            skip_protobuf_field(bytes, &mut cursor, key & 7)?;
        }
    }
    Some(guids)
}

fn decode_host_info(bytes: &[u8]) -> Option<String> {
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let key = decode_varint(bytes, &mut cursor)?;
        if key == (1 << 3) | 2 {
            let guid = decode_length_delimited(bytes, &mut cursor)?;
            return String::from_utf8(guid.to_vec()).ok();
        }
        skip_protobuf_field(bytes, &mut cursor, key & 7)?;
    }
    None
}

fn decode_varint(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn decode_length_delimited<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let len = usize::try_from(decode_varint(bytes, cursor)?).ok()?;
    let end = cursor.checked_add(len)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn skip_protobuf_field(bytes: &[u8], cursor: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        0 => {
            decode_varint(bytes, cursor)?;
        }
        1 => *cursor = cursor.checked_add(8)?,
        2 => {
            decode_length_delimited(bytes, cursor)?;
        }
        5 => *cursor = cursor.checked_add(4)?,
        _ => return None,
    }
    (*cursor <= bytes.len()).then_some(())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use rsa::RsaPrivateKey;
    use rsa::rand_core::OsRng;
    use tempfile::tempdir;

    use super::*;

    fn start_pairing_server(
        password: &'static str,
    ) -> (String, thread::JoinHandle<Result<[u8; PEER_INFO_SIZE]>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(PAIRING_TIMEOUT)).unwrap();
            socket.set_write_timeout(Some(PAIRING_TIMEOUT)).unwrap();
            let mut tls = start_test_server_tls(socket)?;
            let server_info = encode_peer_info(PEER_TYPE_DEVICE_GUID, b"adb-test-guid")?;
            let mut exported_key = [0_u8; TLS_EXPORT_SIZE];
            tls.export_pairing_key_material(&mut exported_key)?;
            exchange_peer_info_with_exported_key(
                &mut tls,
                PairingRole::Server,
                password,
                &exported_key,
                &server_info,
            )
        });
        (address, server)
    }

    fn test_auth_key() -> AuthKey {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        AuthKey::from_private_key(private_key, Some("test-public-key user@host".to_string()))
    }

    #[test]
    fn simulated_device_completes_tls_spake2_and_peer_info_exchange() {
        let (address, server) = start_pairing_server("123456");
        let result = pair_device(&address, "123456", &test_auth_key()).unwrap();
        let client_info = server.join().unwrap().unwrap();

        assert_eq!(result.guid, "adb-test-guid");
        assert_eq!(client_info[0], PEER_TYPE_RSA_PUBLIC_KEY);
        assert!(client_info[1..].starts_with(b"test-public-key user@host\0"));
    }

    #[test]
    fn simulated_device_rejects_wrong_pairing_code() {
        let (address, server) = start_pairing_server("123456");
        let error = pair_device(&address, "654321", &test_auth_key()).unwrap_err();
        let server_result = server.join().unwrap();

        assert_eq!(error.kind, PairingFailureKind::AuthenticationFailed);
        assert!(server_result.is_err());
        assert_eq!(
            error.official_message(),
            "Failed: Wrong password or connection was dropped."
        );
    }

    #[test]
    fn pairing_packet_rejects_invalid_version_and_oversized_payload() {
        let mut invalid_version = io::Cursor::new([2, PACKET_SPAKE2, 0, 0, 0, 1, 7]);
        assert!(read_pairing_packet(&mut invalid_version, PACKET_SPAKE2).is_err());

        let size = (MAX_PAIRING_PAYLOAD as u32 + 1).to_be_bytes();
        let mut oversized = io::Cursor::new([
            PAIRING_HEADER_VERSION,
            PACKET_SPAKE2,
            size[0],
            size[1],
            size[2],
            size[3],
        ]);
        assert!(read_pairing_packet(&mut oversized, PACKET_SPAKE2).is_err());
    }

    #[test]
    fn device_guid_requires_nul_termination_inside_peer_info() {
        let mut peer_info = [b'x'; PEER_INFO_SIZE];
        peer_info[0] = PEER_TYPE_DEVICE_GUID;

        assert!(decode_device_guid(&peer_info).is_err());
    }

    #[test]
    fn known_hosts_round_trip_uses_aosp_protobuf_shape() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("adb_known_hosts.pb");
        record_known_host_at(&path, "first-guid").unwrap();
        record_known_host_at(&path, "second-guid").unwrap();

        let bytes = fs::read(path).unwrap();
        assert_eq!(
            decode_known_hosts(&bytes).unwrap(),
            vec!["first-guid".to_string(), "second-guid".to_string()]
        );
        assert_eq!(bytes[0], 0x0a);
        assert!(bytes.windows(2).any(|window| window == [0x0a, 10]));
    }

    #[test]
    fn corrupted_known_hosts_is_replaced_on_successful_pairing_record() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("adb_known_hosts.pb");
        fs::write(&path, [0x0a, 0xff]).unwrap();

        record_known_host_at(&path, "replacement-guid").unwrap();

        assert_eq!(
            decode_known_hosts(&fs::read(path).unwrap()).unwrap(),
            vec!["replacement-guid".to_string()]
        );
    }

    #[test]
    fn known_host_lookup_matches_guid_and_removes_corrupted_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("adb_known_hosts.pb");
        record_known_host_at(&path, "known-guid").unwrap();

        assert!(is_known_host_at(&path, "known-guid"));
        assert!(!is_known_host_at(&path, "other-guid"));

        fs::write(&path, [0xff, 0xff]).unwrap();
        assert!(!is_known_host_at(&path, "known-guid"));
        assert!(!path.exists());
    }
}
