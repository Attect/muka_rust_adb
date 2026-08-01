use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crate::auth::AuthKey;
use crate::error::{AdbError, Result};
use crate::pairing::AdbTlsConnection;
use crate::protocol::{self, AdbMessage};
use crate::usb::{self, UsbConnection};

pub const SUPPORTED_FEATURES: &[&str] = &[
    "shell_v2",
    "cmd",
    "stat_v2",
    "ls_v2",
    "fixed_push_mkdir",
    "apex",
    "abb",
    "fixed_push_symlink_timestamp",
    "abb_exec",
    "remount_shell",
    "track_app",
    "sendrecv_v2",
    "sendrecv_v2_brotli",
    "sendrecv_v2_lz4",
    "sendrecv_v2_zstd",
    "sendrecv_v2_dry_run_send",
    "openscreen_mdns",
    "devicetracker_proto_format",
    "devraw",
    "app_info",
    "server_status",
];

const FEATURE_DELAYED_ACK: &str = "delayed_ack";
const INITIAL_DELAYED_ACK_BYTES: u32 = 32 * 1024 * 1024;
const ADB_TRACE_TAGS: &[&str] = &[
    "adb",
    "sockets",
    "packets",
    "rwx",
    "usb",
    "sync",
    "sysdeps",
    "transport",
    "jdwp",
    "services",
    "auth",
    "fdevent",
    "shell",
    "incremental",
    "mdns",
    "mdns-stack",
];

pub fn burst_mode_enabled() -> bool {
    burst_mode_enabled_for_env(std::env::var("ADB_BURST_MODE").ok().as_deref())
}

fn burst_mode_enabled_for_env(value: Option<&str>) -> bool {
    value == Some("1")
}

fn supported_features_for_burst(burst_mode: bool) -> Vec<&'static str> {
    let mut features = SUPPORTED_FEATURES.to_vec();
    if burst_mode {
        features.push(FEATURE_DELAYED_ACK);
    }
    features
}

fn supported_features_string_for_burst(burst_mode: bool) -> String {
    supported_features_for_burst(burst_mode).join(",")
}

pub fn host_features_string() -> String {
    let mut features = supported_features_for_burst(burst_mode_enabled());
    if crate::usb::selected_usb_backend() == crate::usb::UsbHostBackend::Libusb {
        features.push("libusb");
    }
    features.push("push_sync");
    features.join(",")
}

pub fn is_supported_feature(feature: &str) -> bool {
    SUPPORTED_FEATURES.contains(&feature)
        || (feature == FEATURE_DELAYED_ACK && burst_mode_enabled())
}

pub fn can_use_feature(features: &str, feature: &str) -> bool {
    is_supported_feature(feature) && has_feature(features, feature)
}

pub fn filter_supported_features(features: &str) -> Vec<&str> {
    features
        .split(',')
        .filter(|feature| !feature.is_empty() && is_supported_feature(feature))
        .collect()
}

fn has_feature(features: &str, feature: &str) -> bool {
    features.split(',').any(|value| value == feature)
}

pub(crate) fn trace_enabled(tag: &str) -> bool {
    if std::env::var_os("ADB_RUST_TRACE_TRANSPORT").is_some() {
        return true;
    }
    trace_setting_enabled(std::env::var("ADB_TRACE").ok().as_deref(), tag)
}

fn trace_setting_enabled(setting: Option<&str>, tag: &str) -> bool {
    setting.is_some_and(|setting| {
        setting
            .split([',', ' '])
            .filter(|value| !value.is_empty())
            .any(|value| matches!(value, "1" | "all") || value == tag)
    })
}

fn unknown_trace_flags(setting: Option<&str>) -> Vec<&str> {
    setting
        .into_iter()
        .flat_map(|setting| setting.split([',', ' ']))
        .filter(|value| {
            !value.is_empty() && !matches!(*value, "1" | "all") && !ADB_TRACE_TAGS.contains(value)
        })
        .collect()
}

pub(crate) fn report_unknown_trace_flags() {
    let setting = std::env::var("ADB_TRACE").ok();
    for flag in unknown_trace_flags(setting.as_deref()) {
        eprintln!("Unknown trace flag: {flag}");
    }
}

pub(crate) trait ClientStream: Read + Write + Send + 'static {
    fn shutdown_stream(&self, how: Shutdown) -> std::io::Result<()>;
    fn try_clone_box(&self) -> std::io::Result<Box<dyn ClientStream>>;
}

impl ClientStream for TcpStream {
    fn shutdown_stream(&self, how: Shutdown) -> std::io::Result<()> {
        self.shutdown(how)
    }

    fn try_clone_box(&self) -> std::io::Result<Box<dyn ClientStream>> {
        Ok(Box::new(self.try_clone()?))
    }
}

#[cfg(unix)]
impl ClientStream for std::os::unix::net::UnixStream {
    fn shutdown_stream(&self, how: Shutdown) -> std::io::Result<()> {
        self.shutdown(how)
    }

    fn try_clone_box(&self) -> std::io::Result<Box<dyn ClientStream>> {
        Ok(Box::new(self.try_clone()?))
    }
}

#[cfg(target_os = "linux")]
struct VsockClientStream {
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
impl Read for VsockClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

#[cfg(target_os = "linux")]
impl Write for VsockClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(target_os = "linux")]
impl ClientStream for VsockClientStream {
    fn shutdown_stream(&self, how: Shutdown) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        if unsafe { libc::shutdown(self.file.as_raw_fd(), how) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn try_clone_box(&self) -> std::io::Result<Box<dyn ClientStream>> {
        Ok(Box::new(Self {
            file: self.file.try_clone()?,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Device,
    Recovery,
    Bootloader,
    Sideload,
    Rescue,
    Authorizing,
    Unauthorized,
    NoPermissions,
    Detached,
    Offline,
}

impl ConnectionState {
    pub fn as_adb(self) -> Cow<'static, str> {
        match self {
            ConnectionState::Device => Cow::Borrowed("device"),
            ConnectionState::Recovery => Cow::Borrowed("recovery"),
            ConnectionState::Bootloader => Cow::Borrowed("bootloader"),
            ConnectionState::Sideload => Cow::Borrowed("sideload"),
            ConnectionState::Rescue => Cow::Borrowed("rescue"),
            ConnectionState::Authorizing => Cow::Borrowed("authorizing"),
            ConnectionState::Unauthorized => Cow::Borrowed("unauthorized"),
            ConnectionState::NoPermissions => Cow::Owned(usb::no_permissions_short_help_text()),
            ConnectionState::Detached => Cow::Borrowed("detached"),
            ConnectionState::Offline => Cow::Borrowed("offline"),
        }
    }

    fn from_banner_type(value: &str) -> Self {
        match value {
            "device" => ConnectionState::Device,
            "recovery" => ConnectionState::Recovery,
            "bootloader" => ConnectionState::Bootloader,
            "sideload" => ConnectionState::Sideload,
            "rescue" => ConnectionState::Rescue,
            "detached" => ConnectionState::Detached,
            _ => ConnectionState::Offline,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportInfo {
    pub id: u64,
    pub serial: String,
    pub devpath: Option<String>,
    pub connection_type: TransportConnectionType,
    pub negotiated_speed_mbps: u64,
    pub max_speed_mbps: u64,
    pub state: ConnectionState,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub features: Option<String>,
    pub max_payload: usize,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConnectionType {
    Usb,
    Socket,
}

impl TransportConnectionType {
    fn aosp_sort_key(self) -> u8 {
        match self {
            Self::Usb => 0,
            Self::Socket => 1,
        }
    }

    pub fn is_usb(self) -> bool {
        matches!(self, Self::Usb)
    }

    pub fn is_local(self) -> bool {
        matches!(self, Self::Socket)
    }
}

impl TransportInfo {
    pub fn is_usb_transport(&self) -> bool {
        self.connection_type.is_usb()
    }

    pub fn is_local_transport(&self) -> bool {
        self.connection_type.is_local()
    }

    pub fn is_wait_active(&self) -> bool {
        !matches!(
            self.state,
            ConnectionState::Authorizing
                | ConnectionState::Unauthorized
                | ConnectionState::NoPermissions
                | ConnectionState::Detached
                | ConnectionState::Offline
        )
    }
}

#[derive(Clone)]
pub struct Transport {
    inner: Arc<TransportInner>,
}

struct TransportInner {
    info: Mutex<TransportInfo>,
    delayed_ack: AtomicBool,
    writer: Mutex<Box<dyn AdbConnection>>,
    streams: Mutex<HashMap<u32, Arc<StreamEntry>>>,
    reverse_forwards: Mutex<HashMap<String, String>>,
    next_local_id: AtomicU32,
    closed: AtomicBool,
}

pub(crate) trait AdbConnection: Send + 'static {
    fn read_packet(&mut self, max_payload: usize) -> Result<AdbMessage>;
    fn write_packet(&mut self, packet: &AdbMessage, protocol_version: u32) -> Result<()>;
    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>>;
    fn close_connection(&mut self) -> Result<()> {
        Ok(())
    }
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }
    fn start_tls(&mut self, _auth_key: &AuthKey) -> Result<()> {
        Err(AdbError::Server(
            "transport does not support A_STLS".to_string(),
        ))
    }
    #[cfg(test)]
    fn read_timeout_for_test(&self) -> Result<Option<Duration>> {
        Ok(None)
    }
}

enum TcpAdbConnection {
    Plain(TcpStream),
    Tls(AdbTlsConnection),
    Closed,
}

impl TcpAdbConnection {
    fn new(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }
}

impl AdbConnection for TcpAdbConnection {
    fn read_packet(&mut self, max_payload: usize) -> Result<AdbMessage> {
        match self {
            Self::Plain(stream) => AdbMessage::read_from(stream, max_payload),
            Self::Tls(connection) => connection.read_packet(max_payload),
            Self::Closed => Err(AdbError::Protocol("TCP transport 已关闭".to_string())),
        }
    }

    fn write_packet(&mut self, packet: &AdbMessage, protocol_version: u32) -> Result<()> {
        match self {
            Self::Plain(stream) => packet.write_to(stream, protocol_version),
            Self::Tls(connection) => connection.write_packet(packet, protocol_version),
            Self::Closed => Err(AdbError::Protocol("TCP transport 已关闭".to_string())),
        }
    }

    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
        match self {
            Self::Plain(stream) => Ok(Box::new(Self::Plain(stream.try_clone()?))),
            Self::Tls(connection) => Ok(Box::new(Self::Tls(connection.clone()))),
            Self::Closed => Err(AdbError::Protocol("TCP transport 已关闭".to_string())),
        }
    }

    fn close_connection(&mut self) -> Result<()> {
        match self {
            Self::Plain(stream) => {
                stream.shutdown(Shutdown::Both)?;
                Ok(())
            }
            Self::Tls(connection) => connection.close(),
            Self::Closed => Ok(()),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        if let Self::Plain(stream) = self {
            stream.set_read_timeout(timeout)?;
        }
        Ok(())
    }

    fn start_tls(&mut self, auth_key: &AuthKey) -> Result<()> {
        let previous = std::mem::replace(self, Self::Closed);
        let Self::Plain(stream) = previous else {
            return Err(AdbError::Protocol(
                "TCP transport 只能从明文状态升级一次 TLS".to_string(),
            ));
        };
        *self = Self::Tls(AdbTlsConnection::connect(stream, auth_key)?);
        Ok(())
    }

    #[cfg(test)]
    fn read_timeout_for_test(&self) -> Result<Option<Duration>> {
        match self {
            Self::Plain(stream) => Ok(stream.read_timeout()?),
            Self::Tls(_) | Self::Closed => Ok(None),
        }
    }
}

impl AdbConnection for TcpStream {
    fn read_packet(&mut self, max_payload: usize) -> Result<AdbMessage> {
        AdbMessage::read_from(self, max_payload)
    }

    fn write_packet(&mut self, packet: &AdbMessage, protocol_version: u32) -> Result<()> {
        packet.write_to(self, protocol_version)
    }

    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn close_connection(&mut self) -> Result<()> {
        self.shutdown(Shutdown::Both)?;
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        TcpStream::set_read_timeout(self, timeout)?;
        Ok(())
    }

    #[cfg(test)]
    fn read_timeout_for_test(&self) -> Result<Option<Duration>> {
        Ok(TcpStream::read_timeout(self)?)
    }
}

trait AdbConnectionMessageExt {
    fn write_to_connection(
        &self,
        connection: &mut dyn AdbConnection,
        protocol_version: u32,
    ) -> Result<()>;
}

impl AdbConnectionMessageExt for AdbMessage {
    fn write_to_connection(
        &self,
        connection: &mut dyn AdbConnection,
        protocol_version: u32,
    ) -> Result<()> {
        connection.write_packet(self, protocol_version)
    }
}

impl Transport {
    pub fn info(&self) -> TransportInfo {
        self.inner
            .info
            .lock()
            .expect("transport info poisoned")
            .clone()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn close(&self) {
        self.inner.close_all_streams();
    }

    pub(crate) fn set_connection_state(&self, state: ConnectionState) {
        self.inner
            .info
            .lock()
            .expect("transport info poisoned")
            .state = state;
    }

    fn activate(
        &self,
        info: TransportInfo,
        delayed_ack: bool,
        connection: Box<dyn AdbConnection>,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(AdbError::Server(
                "transport handshake cancelled".to_string(),
            ));
        }
        let read_connection = connection.try_clone_box()?;
        *self.inner.writer.lock().expect("transport writer poisoned") = connection;
        self.inner.delayed_ack.store(delayed_ack, Ordering::SeqCst);
        *self.inner.info.lock().expect("transport info poisoned") = info;
        spawn_transport_reader(Arc::clone(&self.inner), read_connection);
        Ok(())
    }

    pub(crate) fn serve_service<S>(&self, service: &str, mut client: S) -> Result<()>
    where
        S: ClientStream,
    {
        match self.open_service_stream(service, ClientStream::try_clone_box(&client)?)? {
            OpenServiceResult::Ready {
                local_id,
                remote_id,
                entry,
            } => {
                {
                    let mut client_guard = entry.client.lock().expect("client stream poisoned");
                    if let Err(err) = protocol::write_okay(&mut *client_guard) {
                        entry.mark_failed("client closed before smart-socket OKAY");
                        self.remove_stream(local_id);
                        return Err(err);
                    }
                }
                entry.set_input_client(ClientStream::try_clone_box(&client)?);
                if entry.mark_client_ready() {
                    entry.shutdown_output();
                    spawn_client_input_thread(
                        Box::new(client),
                        Arc::clone(&self.inner),
                        entry,
                        local_id,
                        remote_id,
                    );
                    return Ok(());
                }
                spawn_client_input_thread(
                    Box::new(client),
                    Arc::clone(&self.inner),
                    entry,
                    local_id,
                    remote_id,
                );
            }
            OpenServiceResult::Failed(reason) => {
                protocol::write_fail(&mut client, &reason)?;
            }
        }
        Ok(())
    }

    pub(crate) fn serve_raw_service<S>(&self, service: &str, client: S) -> Result<()>
    where
        S: ClientStream,
    {
        if let OpenServiceResult::Ready {
            local_id,
            remote_id,
            entry,
        } = self.open_service_stream(service, client.try_clone_box()?)?
        {
            entry.set_input_client(client.try_clone_box()?);
            if entry.mark_client_ready() {
                entry.shutdown_output();
                spawn_client_input_thread(
                    Box::new(client),
                    Arc::clone(&self.inner),
                    entry,
                    local_id,
                    remote_id,
                );
                return Ok(());
            }
            spawn_client_input_thread(
                Box::new(client),
                Arc::clone(&self.inner),
                entry,
                local_id,
                remote_id,
            );
        }
        Ok(())
    }

    fn open_service_stream(
        &self,
        service: &str,
        client: Box<dyn ClientStream>,
    ) -> Result<OpenServiceResult> {
        match self.info().state {
            ConnectionState::Authorizing => {
                return Ok(OpenServiceResult::Failed(
                    "device still authorizing".to_string(),
                ));
            }
            ConnectionState::Unauthorized => {
                return Ok(OpenServiceResult::Failed("device unauthorized".to_string()));
            }
            ConnectionState::NoPermissions => {
                return Ok(OpenServiceResult::Failed(
                    usb::no_permissions_long_help_text(),
                ));
            }
            ConnectionState::Detached | ConnectionState::Offline => {
                return Ok(OpenServiceResult::Failed(
                    "device offline (transport offline)".to_string(),
                ));
            }
            _ => {}
        }

        self.inner.update_reverse_config(service);

        let local_id = self.allocate_local_id();
        let entry = Arc::new(StreamEntry::new(client));
        self.inner
            .streams
            .lock()
            .expect("stream registry poisoned")
            .insert(local_id, Arc::clone(&entry));

        self.write_packet(AdbMessage::new(
            protocol::A_OPEN,
            local_id,
            self.open_initial_credit(),
            open_service_payload(service),
        )?)?;

        let remote_id = match entry.wait_open() {
            OpenResult::Ready(remote_id) => remote_id,
            OpenResult::Failed(reason) => {
                self.remove_stream(local_id);
                return Ok(OpenServiceResult::Failed(reason));
            }
        };

        Ok(OpenServiceResult::Ready {
            local_id,
            remote_id,
            entry,
        })
    }

    fn allocate_local_id(&self) -> u32 {
        loop {
            let id = self.inner.next_local_id.fetch_add(1, Ordering::SeqCst);
            if id != 0 {
                return id;
            }
        }
    }

    fn write_packet(&self, packet: AdbMessage) -> Result<()> {
        self.inner.write_packet(packet)
    }

    fn remove_stream(&self, local_id: u32) {
        self.inner
            .streams
            .lock()
            .expect("stream registry poisoned")
            .remove(&local_id);
    }

    fn open_initial_credit(&self) -> u32 {
        if self.inner.supports_delayed_ack() {
            INITIAL_DELAYED_ACK_BYTES
        } else {
            0
        }
    }

    #[cfg(test)]
    pub(crate) fn fake(info: TransportInfo) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (stream, _) = listener.accept().unwrap();
        drop(connector.join().unwrap());

        Self {
            inner: Arc::new(TransportInner {
                info: Mutex::new(info),
                delayed_ack: AtomicBool::new(false),
                writer: Mutex::new(Box::new(stream)),
                streams: Mutex::new(HashMap::new()),
                reverse_forwards: Mutex::new(HashMap::new()),
                next_local_id: AtomicU32::new(1),
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn detached(info: TransportInfo) -> Self {
        Self::inactive(info, ConnectionState::Detached)
    }

    pub(crate) fn offline(info: TransportInfo) -> Self {
        Self::inactive(info, ConnectionState::Offline)
    }

    pub(crate) fn no_permissions(info: TransportInfo) -> Self {
        Self::inactive(info, ConnectionState::NoPermissions)
    }

    fn pending(mut info: TransportInfo, connection: Box<dyn AdbConnection>) -> Self {
        info.state = ConnectionState::Offline;
        Self {
            inner: Arc::new(TransportInner {
                info: Mutex::new(info),
                delayed_ack: AtomicBool::new(false),
                writer: Mutex::new(connection),
                streams: Mutex::new(HashMap::new()),
                reverse_forwards: Mutex::new(HashMap::new()),
                next_local_id: AtomicU32::new(1),
                closed: AtomicBool::new(false),
            }),
        }
    }

    fn inactive(mut info: TransportInfo, state: ConnectionState) -> Self {
        info.state = state;
        let serial = info.serial.clone();
        Self {
            inner: Arc::new(TransportInner {
                info: Mutex::new(info),
                delayed_ack: AtomicBool::new(false),
                writer: Mutex::new(Box::new(InactiveConnection { serial, state })),
                streams: Mutex::new(HashMap::new()),
                reverse_forwards: Mutex::new(HashMap::new()),
                next_local_id: AtomicU32::new(1),
                closed: AtomicBool::new(false),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn mark_closed_for_test(&self) {
        self.close();
    }

    #[cfg(test)]
    pub(crate) fn read_timeout_for_test(&self) -> Result<Option<Duration>> {
        self.inner
            .writer
            .lock()
            .expect("transport writer poisoned")
            .read_timeout_for_test()
    }
}

#[derive(Clone)]
struct InactiveConnection {
    serial: String,
    state: ConnectionState,
}

impl AdbConnection for InactiveConnection {
    fn read_packet(&mut self, _max_payload: usize) -> Result<AdbMessage> {
        Err(AdbError::Server(format!(
            "transport {} is {}",
            self.serial,
            self.state.as_adb()
        )))
    }

    fn write_packet(&mut self, _packet: &AdbMessage, _protocol_version: u32) -> Result<()> {
        Err(AdbError::Server(format!(
            "transport {} is {}",
            self.serial,
            self.state.as_adb()
        )))
    }

    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
        Ok(Box::new(self.clone()))
    }
}

impl TransportInner {
    fn max_payload(&self) -> usize {
        self.info
            .lock()
            .expect("transport info poisoned")
            .max_payload
            .clamp(1, protocol::MAX_PAYLOAD)
    }

    fn protocol_version(&self) -> u32 {
        self.info
            .lock()
            .expect("transport info poisoned")
            .protocol_version
    }

    fn write_packet(&self, packet: AdbMessage) -> Result<()> {
        trace_packet("send", &packet);
        let result = {
            let mut writer = self.writer.lock().expect("transport writer poisoned");
            writer.write_packet(&packet, self.protocol_version())
        };
        if result.is_err() {
            self.close_all_streams();
        }
        result
    }

    fn dispatch_packet(self: &Arc<Self>, packet: AdbMessage) -> Result<()> {
        match packet.command {
            protocol::A_OPEN => self.dispatch_open(packet),
            protocol::A_OKAY => self.dispatch_okay(packet),
            protocol::A_WRTE => self.dispatch_write(packet),
            protocol::A_CLSE => self.dispatch_close(packet),
            _ => Ok(()),
        }
    }

    fn dispatch_open(self: &Arc<Self>, packet: AdbMessage) -> Result<()> {
        let remote_id = packet.arg0;
        if remote_id == 0 || self.supports_delayed_ack() != (packet.arg1 != 0) {
            return self.reject_incoming_open(remote_id);
        }

        let address_len = packet
            .payload
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |index| index + 1);
        let address = &packet.payload[..address_len];
        let Ok(address) = std::str::from_utf8(address) else {
            return self.reject_incoming_open(remote_id);
        };
        if !self.is_reverse_configured(address) {
            return self.reject_incoming_open(remote_id);
        }

        let client = match connect_reverse_service(address) {
            Ok(client) => client,
            Err(err) => {
                trace_transport_error("reverse connect", &err);
                return self.reject_incoming_open(remote_id);
            }
        };
        let output_client = match client.try_clone_box() {
            Ok(client) => client,
            Err(_) => return self.reject_incoming_open(remote_id),
        };
        let shutdown_client = match client.try_clone_box() {
            Ok(client) => client,
            Err(_) => return self.reject_incoming_open(remote_id),
        };

        let local_id = self.allocate_local_id();
        let entry = Arc::new(StreamEntry::new(output_client));
        entry.set_input_client(shutdown_client);
        entry.mark_open(remote_id);
        entry.mark_can_write(remote_id);
        let _ = entry.mark_client_ready();
        self.streams
            .lock()
            .expect("stream registry poisoned")
            .insert(local_id, Arc::clone(&entry));

        let initial_credit = if self.supports_delayed_ack() {
            INITIAL_DELAYED_ACK_BYTES as usize
        } else {
            0
        };
        if let Err(err) = self.write_packet(AdbMessage::new(
            protocol::A_OKAY,
            local_id,
            remote_id,
            self.okay_payload(initial_credit),
        )?) {
            self.streams
                .lock()
                .expect("stream registry poisoned")
                .remove(&local_id);
            entry.shutdown_clients();
            return Err(err);
        }

        spawn_client_input_thread(client, Arc::clone(self), entry, local_id, remote_id);
        Ok(())
    }

    fn reject_incoming_open(&self, remote_id: u32) -> Result<()> {
        if remote_id == 0 {
            return Ok(());
        }
        self.write_packet(AdbMessage::new(protocol::A_CLSE, 0, remote_id, Vec::new())?)
    }

    fn dispatch_okay(&self, packet: AdbMessage) -> Result<()> {
        let entry = self.find_stream(packet.arg1);
        if let Some(entry) = entry {
            entry.mark_open(packet.arg0);
            entry.mark_can_write(packet.arg0);
        }
        Ok(())
    }

    fn dispatch_write(&self, packet: AdbMessage) -> Result<()> {
        let entry = self.find_stream(packet.arg1);
        let Some(entry) = entry else {
            return Ok(());
        };

        if !entry.matches_remote(packet.arg0) {
            return Ok(());
        }
        if !entry.wait_client_ready() {
            return Ok(());
        }

        let written = packet.payload.len();
        {
            let mut client = entry.client.lock().expect("client stream poisoned");
            if client.write_all(&packet.payload).is_err() {
                entry.mark_failed("client write failed");
                let _ = client.shutdown_stream(Shutdown::Both);
                drop(client);
                entry.shutdown_input_client();
                self.streams
                    .lock()
                    .expect("stream registry poisoned")
                    .remove(&packet.arg1);
                if entry.try_mark_close_packet_sent() {
                    return self.write_packet(AdbMessage::new(
                        protocol::A_CLSE,
                        packet.arg1,
                        packet.arg0,
                        Vec::new(),
                    )?);
                }
                return Ok(());
            }
        }
        self.write_packet(AdbMessage::new(
            protocol::A_OKAY,
            packet.arg1,
            packet.arg0,
            self.okay_payload(written),
        )?)
    }

    fn dispatch_close(&self, packet: AdbMessage) -> Result<()> {
        let entry = self.find_stream(packet.arg1);
        if let Some(entry) = entry {
            let client_ready = entry.mark_closed();
            // 设备可能在 host 调度线程写 smart-socket OKAY 前连续发送 A_OKAY/A_CLSE。
            // 这种情况必须先让 serve_service 完成成功握手，再把 EOF 传给客户端。
            if client_ready {
                entry.shutdown_output();
            }
        }
        self.streams
            .lock()
            .expect("stream registry poisoned")
            .remove(&packet.arg1);
        Ok(())
    }

    fn find_stream(&self, local_id: u32) -> Option<Arc<StreamEntry>> {
        self.streams
            .lock()
            .expect("stream registry poisoned")
            .get(&local_id)
            .cloned()
    }

    fn allocate_local_id(&self) -> u32 {
        loop {
            let id = self.next_local_id.fetch_add(1, Ordering::SeqCst);
            if id != 0 {
                return id;
            }
        }
    }

    fn update_reverse_config(&self, service: &str) {
        let Some(command) = service.strip_prefix("reverse:") else {
            return;
        };
        let mut forwards = self
            .reverse_forwards
            .lock()
            .expect("reverse forward registry poisoned");

        if let Some(mut spec) = command.strip_prefix("forward:") {
            let no_rebind = spec
                .strip_prefix("norebind:")
                .map(|rest| {
                    spec = rest;
                    true
                })
                .unwrap_or(false);
            let Some((remote, local)) = spec.split_once(';') else {
                return;
            };
            if no_rebind && forwards.contains_key(remote) {
                return;
            }
            forwards.insert(remote.to_string(), local.to_string());
        } else if let Some(remote) = command.strip_prefix("killforward:") {
            if !remote.contains(';') {
                forwards.remove(remote);
            }
        } else if command == "killforward-all" {
            forwards.clear();
        }
    }

    fn is_reverse_configured(&self, local: &str) -> bool {
        self.reverse_forwards
            .lock()
            .expect("reverse forward registry poisoned")
            .values()
            .any(|configured| configured == local)
    }

    fn close_all_streams(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self
                .writer
                .lock()
                .expect("transport writer poisoned")
                .close_connection();
        }
        let streams: Vec<_> = self
            .streams
            .lock()
            .expect("stream registry poisoned")
            .drain()
            .map(|(_, entry)| entry)
            .collect();
        for entry in streams {
            entry.mark_failed("transport closed");
            // transport 失败时仍需让 smart-socket 已写出的响应有序到达客户端。
            // 输入线程会在观察到 failed 后排空剩余上传数据，避免 Windows 因未读数据发送 RST。
            entry.shutdown_output();
        }
    }

    fn supports_delayed_ack(&self) -> bool {
        self.delayed_ack.load(Ordering::SeqCst)
    }

    fn okay_payload(&self, written: usize) -> Vec<u8> {
        if self.supports_delayed_ack() {
            let acked = u32::try_from(written).unwrap_or(u32::MAX);
            acked.to_le_bytes().to_vec()
        } else {
            Vec::new()
        }
    }
}

fn connect_reverse_service(address: &str) -> Result<Box<dyn ClientStream>> {
    if let Some(target) = address.strip_prefix("tcp:") {
        return connect_reverse_tcp(target);
    }
    if let Some(path) = address.strip_prefix("local:") {
        return connect_reverse_local_filesystem(path, "local");
    }
    if let Some(path) = address.strip_prefix("localfilesystem:") {
        return connect_reverse_local_filesystem(path, "localfilesystem");
    }
    if let Some(name) = address.strip_prefix("localabstract:") {
        return connect_reverse_local_abstract(name);
    }
    if address.starts_with("localreserved:") {
        return Err(AdbError::Server(
            "socket type localreserved is unavailable on this platform".to_string(),
        ));
    }
    if address.starts_with("vsock:") {
        return connect_reverse_vsock(address);
    }
    if address.starts_with("acceptfd:") {
        return Err(AdbError::Server("cannot connect to acceptfd".to_string()));
    }
    Err(AdbError::Server(format!(
        "unknown socket specification: {address}"
    )))
}

fn connect_reverse_tcp(target: &str) -> Result<Box<dyn ClientStream>> {
    let target = if target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{target}")
    } else {
        target.to_string()
    };
    let stream = TcpStream::connect(target)?;
    stream.set_nodelay(true)?;
    Ok(Box::new(stream))
}

#[cfg(unix)]
fn connect_reverse_local_filesystem(
    path: &str,
    _socket_type: &str,
) -> Result<Box<dyn ClientStream>> {
    Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
}

#[cfg(not(unix))]
fn connect_reverse_local_filesystem(
    _path: &str,
    socket_type: &str,
) -> Result<Box<dyn ClientStream>> {
    Err(AdbError::Server(format!(
        "socket type {socket_type} is unavailable on this platform"
    )))
}

#[cfg(target_os = "linux")]
fn connect_reverse_local_abstract(name: &str) -> Result<Box<dyn ClientStream>> {
    use std::os::linux::net::SocketAddrExt;

    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    Ok(Box::new(std::os::unix::net::UnixStream::connect_addr(
        &address,
    )?))
}

#[cfg(not(target_os = "linux"))]
fn connect_reverse_local_abstract(_name: &str) -> Result<Box<dyn ClientStream>> {
    Err(AdbError::Server(
        "socket type localabstract is unavailable on this platform".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn connect_reverse_vsock(address: &str) -> Result<Box<dyn ClientStream>> {
    use std::os::fd::FromRawFd;

    let fragments: Vec<_> = address.split(':').collect();
    if !matches!(fragments.len(), 2 | 3) {
        return Err(AdbError::Server(format!(
            "expected vsock:cid or vsock:cid:port in '{address}'"
        )));
    }
    let cid = fragments[1]
        .parse::<u32>()
        .map_err(|_| AdbError::Server(format!("could not parse vsock cid in '{address}'")))?;
    let port = fragments
        .get(2)
        .map(|port| {
            port.parse::<u32>()
                .map_err(|_| AdbError::Server(format!("could not parse vsock port in '{address}'")))
        })
        .transpose()?
        .unwrap_or(0);
    if port == 0 {
        return Err(AdbError::Server("vsock port was not provided.".to_string()));
    }

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut socket_address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    socket_address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    socket_address.svm_cid = cid;
    socket_address.svm_port = port;
    let result = unsafe {
        libc::connect(
            fd,
            &socket_address as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Box::new(VsockClientStream { file }))
}

#[cfg(not(target_os = "linux"))]
fn connect_reverse_vsock(_address: &str) -> Result<Box<dyn ClientStream>> {
    Err(AdbError::Server(
        "vsock is only supported on Linux".to_string(),
    ))
}

fn open_service_payload(service: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(service.len() + 1);
    payload.extend_from_slice(service.as_bytes());
    payload.push(0);
    payload
}

struct StreamEntry {
    client: Mutex<Box<dyn ClientStream>>,
    input_client: Mutex<Option<Box<dyn ClientStream>>>,
    state: Mutex<StreamState>,
    cvar: Condvar,
    /// 保证 A_CLSE 只向对端发送一次，避免输入线程 EOF 与输出写失败并发时重复发关闭包。
    close_packet_sent: AtomicBool,
}

impl StreamEntry {
    fn new(client: Box<dyn ClientStream>) -> Self {
        Self {
            client: Mutex::new(client),
            input_client: Mutex::new(None),
            state: Mutex::new(StreamState::default()),
            cvar: Condvar::new(),
            close_packet_sent: AtomicBool::new(false),
        }
    }

    fn try_mark_close_packet_sent(&self) -> bool {
        !self.close_packet_sent.swap(true, Ordering::SeqCst)
    }

    fn set_input_client(&self, client: Box<dyn ClientStream>) {
        *self
            .input_client
            .lock()
            .expect("input client stream poisoned") = Some(client);
    }

    fn shutdown_clients(&self) {
        let _ = self
            .client
            .lock()
            .expect("client stream poisoned")
            .shutdown_stream(Shutdown::Both);
        self.shutdown_input_client();
    }

    fn shutdown_output(&self) {
        // 远端正常 A_CLSE 时只发送有序 FIN。若此时 smart-socket 仍有未读输入，
        // Windows 上双向 shutdown 会产生 RST，并可能丢弃已经写出的输出。
        let _ = self
            .client
            .lock()
            .expect("client stream poisoned")
            .shutdown_stream(Shutdown::Write);
    }

    fn shutdown_input_client(&self) {
        if let Some(input_client) = self
            .input_client
            .lock()
            .expect("input client stream poisoned")
            .as_mut()
        {
            let _ = input_client.shutdown_stream(Shutdown::Both);
        }
    }

    fn wait_open(&self) -> OpenResult {
        let mut state = self.state.lock().expect("stream state poisoned");
        loop {
            if let Some(reason) = &state.failed {
                return OpenResult::Failed(reason.clone());
            }
            if let Some(remote_id) = state.remote_id {
                return OpenResult::Ready(remote_id);
            }
            if state.closed {
                return OpenResult::Failed("remote service closed".to_string());
            }
            state = self.cvar.wait(state).expect("stream state poisoned");
        }
    }

    fn mark_open(&self, remote_id: u32) {
        if remote_id == 0 {
            return;
        }

        let mut state = self.state.lock().expect("stream state poisoned");
        if state.remote_id.is_none() {
            state.remote_id = Some(remote_id);
        }
        self.cvar.notify_all();
    }

    fn mark_can_write(&self, remote_id: u32) {
        let mut state = self.state.lock().expect("stream state poisoned");
        if state.remote_id == Some(remote_id) {
            state.can_write = true;
            self.cvar.notify_all();
        }
    }

    fn mark_failed(&self, reason: &str) {
        let mut state = self.state.lock().expect("stream state poisoned");
        state.failed = Some(reason.to_string());
        state.closed = true;
        self.cvar.notify_all();
    }

    fn mark_closed(&self) -> bool {
        let mut state = self.state.lock().expect("stream state poisoned");
        state.closed = true;
        self.cvar.notify_all();
        state.client_ready
    }

    fn mark_client_ready(&self) -> bool {
        let mut state = self.state.lock().expect("stream state poisoned");
        state.client_ready = true;
        self.cvar.notify_all();
        state.closed || state.failed.is_some()
    }

    fn wait_client_ready(&self) -> bool {
        let mut state = self.state.lock().expect("stream state poisoned");
        while !state.closed && state.failed.is_none() && !state.client_ready {
            state = self.cvar.wait(state).expect("stream state poisoned");
        }
        !state.closed && state.failed.is_none()
    }

    fn matches_remote(&self, remote_id: u32) -> bool {
        self.state.lock().expect("stream state poisoned").remote_id == Some(remote_id)
    }

    fn is_closed(&self) -> bool {
        let state = self.state.lock().expect("stream state poisoned");
        state.closed || state.failed.is_some()
    }

    fn wait_write_turn(&self, remote_id: u32) -> bool {
        let mut state = self.state.lock().expect("stream state poisoned");
        while !state.closed && state.failed.is_none() && !state.can_write {
            state = self.cvar.wait(state).expect("stream state poisoned");
        }
        if state.closed || state.failed.is_some() || state.remote_id != Some(remote_id) {
            return false;
        }
        state.can_write = false;
        true
    }
}

#[derive(Debug, Default)]
struct StreamState {
    remote_id: Option<u32>,
    can_write: bool,
    client_ready: bool,
    closed: bool,
    failed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenResult {
    Ready(u32),
    Failed(String),
}

#[derive(Clone)]
enum OpenServiceResult {
    Ready {
        local_id: u32,
        remote_id: u32,
        entry: Arc<StreamEntry>,
    },
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBanner {
    pub state: ConnectionState,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub features: Option<String>,
}

pub fn connect_tcp(id: u64, target: &str) -> Result<Transport> {
    connect_tcp_with_auth(id, target, AuthKey::load_all()?)
}

#[cfg(test)]
pub(crate) fn connect_tcp_with_burst_for_test(id: u64, target: &str) -> Result<Transport> {
    let serial = normalize_tcp_serial(target)?;
    let stream = TcpStream::connect(&serial)?;
    prepare_tcp_stream_with_serial_and_auth(id, serial, stream, AuthKey::load_all()?, true)?
        .finish(|_| {})
}

fn connect_tcp_with_auth(id: u64, target: &str, auth_keys: Vec<AuthKey>) -> Result<Transport> {
    let serial = normalize_tcp_serial(target)?;
    let stream = TcpStream::connect(&serial)?;
    prepare_tcp_stream_with_serial_and_auth(id, serial, stream, auth_keys, burst_mode_enabled())?
        .finish(|_| {})
}

pub(crate) fn prepare_tcp_stream_with_serial(
    id: u64,
    serial: String,
    stream: TcpStream,
) -> Result<PendingTransport> {
    prepare_tcp_stream_with_serial_and_auth(
        id,
        serial,
        stream,
        AuthKey::load_all()?,
        burst_mode_enabled(),
    )
}

fn prepare_tcp_stream_with_serial_and_auth(
    id: u64,
    serial: String,
    stream: TcpStream,
    auth_keys: Vec<AuthKey>,
    burst_mode: bool,
) -> Result<PendingTransport> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let connection: Box<dyn AdbConnection> = Box::new(TcpAdbConnection::new(stream));

    PendingTransport::new(
        id,
        serial,
        ConnectionMetadata::socket(),
        connection,
        auth_keys,
        burst_mode,
    )
}

pub fn connect_usb(id: u64, interface: &usb::UsbAdbInterface) -> Result<Transport> {
    connect_usb_with_serial(id, interface, None)
}

pub(crate) fn prepare_usb_for_scan(
    id: u64,
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> std::result::Result<PendingTransport, usb::UsbOpenError> {
    prepare_usb_with_serial_classified(id, interface, preserved_serial)
}

pub(crate) fn connect_usb_with_serial(
    id: u64,
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> Result<Transport> {
    connect_usb_with_serial_classified(id, interface, preserved_serial)
        .map_err(usb::UsbOpenError::into_adb_error)
}

pub(crate) fn prepare_usb_with_serial(
    id: u64,
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> Result<PendingTransport> {
    prepare_usb_with_serial_classified(id, interface, preserved_serial)
        .map_err(usb::UsbOpenError::into_adb_error)
}

fn connect_usb_with_serial_classified(
    id: u64,
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> std::result::Result<Transport, usb::UsbOpenError> {
    prepare_usb_with_serial_classified(id, interface, preserved_serial)?
        .finish(|_| {})
        .map_err(usb::UsbOpenError::Other)
}

fn prepare_usb_with_serial_classified(
    id: u64,
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> std::result::Result<PendingTransport, usb::UsbOpenError> {
    let serial = usb_transport_serial(interface, preserved_serial);
    let connection: Box<dyn AdbConnection> = Box::new(UsbConnection::open(interface)?);
    PendingTransport::new(
        id,
        serial,
        ConnectionMetadata::usb(interface),
        connection,
        AuthKey::load_all().map_err(usb::UsbOpenError::Other)?,
        burst_mode_enabled(),
    )
    .map_err(usb::UsbOpenError::Other)
}

fn usb_transport_serial(
    interface: &usb::UsbAdbInterface,
    preserved_serial: Option<&str>,
) -> String {
    preserved_serial
        .map(str::to_string)
        .unwrap_or_else(|| interface.serial_or_fallback())
}

struct ConnectionMetadata {
    devpath: Option<String>,
    connection_type: TransportConnectionType,
    negotiated_speed_mbps: u64,
    max_speed_mbps: u64,
}

pub(crate) struct PendingTransport {
    transport: Transport,
    connection: Box<dyn AdbConnection>,
    auth_keys: Vec<AuthKey>,
    burst_mode: bool,
}

impl PendingTransport {
    fn new(
        id: u64,
        serial: String,
        metadata: ConnectionMetadata,
        connection: Box<dyn AdbConnection>,
        auth_keys: Vec<AuthKey>,
        burst_mode: bool,
    ) -> Result<Self> {
        let info = TransportInfo {
            id,
            serial,
            devpath: metadata.devpath,
            connection_type: metadata.connection_type,
            negotiated_speed_mbps: metadata.negotiated_speed_mbps,
            max_speed_mbps: metadata.max_speed_mbps,
            state: ConnectionState::Offline,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD_V1,
            protocol_version: protocol::A_VERSION_MIN,
        };
        let transport = Transport::pending(info, connection.try_clone_box()?);
        Ok(Self {
            transport,
            connection,
            auth_keys,
            burst_mode,
        })
    }

    pub(crate) fn transport(&self) -> Transport {
        self.transport.clone()
    }

    pub(crate) fn finish<F>(self, on_state: F) -> Result<Transport>
    where
        F: FnMut(ConnectionState),
    {
        connect_with_auth(
            self.transport,
            self.connection,
            self.auth_keys,
            self.burst_mode,
            on_state,
        )
    }
}

impl ConnectionMetadata {
    fn socket() -> Self {
        Self {
            devpath: None,
            connection_type: TransportConnectionType::Socket,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
        }
    }

    fn usb(interface: &usb::UsbAdbInterface) -> Self {
        Self {
            devpath: Some(interface.bus_address.clone()),
            connection_type: TransportConnectionType::Usb,
            negotiated_speed_mbps: interface.negotiated_speed_mbps,
            max_speed_mbps: interface.max_speed_mbps,
        }
    }
}

fn connect_with_auth<F>(
    transport: Transport,
    mut connection: Box<dyn AdbConnection>,
    auth_keys: Vec<AuthKey>,
    burst_mode: bool,
    mut on_state: F,
) -> Result<Transport>
where
    F: FnMut(ConnectionState),
{
    let initial_info = transport.info();
    let banner = format!(
        "host::features={}",
        supported_features_string_for_burst(burst_mode)
    );
    AdbMessage::new(
        protocol::A_CNXN,
        protocol::A_VERSION,
        protocol::MAX_PAYLOAD as u32,
        banner.into_bytes(),
    )?
    .write_to_connection(&mut *connection, protocol::A_VERSION_MIN)?;

    let mut next_key = 0_usize;
    let mut info = loop {
        let message = connection.read_packet(protocol::MAX_PAYLOAD)?;
        match message.command {
            protocol::A_CNXN => {
                let banner = String::from_utf8_lossy(&message.payload);
                let parsed = parse_banner(&banner);
                break TransportInfo {
                    id: initial_info.id,
                    serial: initial_info.serial.clone(),
                    devpath: initial_info.devpath.clone(),
                    connection_type: initial_info.connection_type,
                    negotiated_speed_mbps: initial_info.negotiated_speed_mbps,
                    max_speed_mbps: initial_info.max_speed_mbps,
                    state: parsed.state,
                    product: parsed.product,
                    model: parsed.model,
                    device: parsed.device,
                    features: parsed.features,
                    max_payload: usize::min(message.arg1 as usize, protocol::MAX_PAYLOAD),
                    // AOSP stores the negotiated protocol as min(remote, A_VERSION);
                    // otherwise a newer peer could make later packet writes use a
                    // wire version that this host did not advertise.
                    protocol_version: message.arg0.min(protocol::A_VERSION),
                };
            }
            protocol::A_AUTH if message.arg0 == protocol::ADB_AUTH_TOKEN => {
                if transport.info().state != ConnectionState::Authorizing {
                    transport.set_connection_state(ConnectionState::Authorizing);
                    on_state(ConnectionState::Authorizing);
                }
                if let Some(auth_key) = auth_keys.get(next_key) {
                    let signature = auth_key.sign_token(&message.payload)?;
                    AdbMessage::new(protocol::A_AUTH, protocol::ADB_AUTH_SIGNATURE, 0, signature)?
                        .write_to_connection(&mut *connection, protocol::A_VERSION_MIN)?;
                    next_key += 1;
                    continue;
                }

                if let Some(public_key) = auth_keys.first().and_then(AuthKey::public_key_payload) {
                    AdbMessage::new(
                        protocol::A_AUTH,
                        protocol::ADB_AUTH_RSAPUBLICKEY,
                        0,
                        public_key,
                    )?
                    .write_to_connection(&mut *connection, protocol::A_VERSION_MIN)?;
                }

                break TransportInfo {
                    id: initial_info.id,
                    serial: initial_info.serial.clone(),
                    devpath: initial_info.devpath.clone(),
                    connection_type: initial_info.connection_type,
                    negotiated_speed_mbps: initial_info.negotiated_speed_mbps,
                    max_speed_mbps: initial_info.max_speed_mbps,
                    state: ConnectionState::Unauthorized,
                    product: None,
                    model: None,
                    device: None,
                    features: None,
                    max_payload: protocol::MAX_PAYLOAD_V1,
                    protocol_version: protocol::A_VERSION_MIN,
                };
            }
            protocol::A_STLS => {
                AdbMessage::new(protocol::A_STLS, protocol::A_STLS_VERSION, 0, Vec::new())?
                    .write_to_connection(&mut *connection, protocol::A_VERSION_MIN)?;
                let auth_key = auth_keys
                    .get(next_key.saturating_sub(1))
                    .or_else(|| auth_keys.first())
                    .ok_or_else(|| AdbError::Protocol("A_STLS 没有可用 adbkey".to_string()))?;
                connection.start_tls(auth_key)?;
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "TCP transport 握手收到意外消息 {}",
                    protocol::command_name(other)
                )));
            }
        }
    };

    if info.max_payload == 0 {
        info.max_payload = protocol::MAX_PAYLOAD_V1;
    }

    connection.set_read_timeout(None)?;
    let delayed_ack = burst_mode
        && info
            .features
            .as_deref()
            .is_some_and(|features| has_feature(features, FEATURE_DELAYED_ACK));
    transport.activate(info, delayed_ack, connection)?;
    Ok(transport)
}

fn spawn_transport_reader(inner: Arc<TransportInner>, mut connection: Box<dyn AdbConnection>) {
    thread::spawn(move || {
        loop {
            let packet = match connection.read_packet(inner.max_payload()) {
                Ok(packet) => {
                    trace_packet("recv", &packet);
                    packet
                }
                Err(err) => {
                    trace_transport_error("read", &err);
                    inner.close_all_streams();
                    return;
                }
            };

            if let Err(err) = inner.dispatch_packet(packet) {
                trace_transport_error("dispatch", &err);
                inner.close_all_streams();
                return;
            }
        }
    });
}

fn spawn_client_input_thread(
    mut client: Box<dyn ClientStream>,
    inner: Arc<TransportInner>,
    entry: Arc<StreamEntry>,
    local_id: u32,
    remote_id: u32,
) {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; inner.max_payload().min(64 * 1024)];
        loop {
            let read = match client.read(&mut buffer) {
                Ok(0) => {
                    close_remote_after_input_end(&inner, &entry, local_id, remote_id);
                    return;
                }
                Ok(read) => read,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    close_remote_after_input_end(&inner, &entry, local_id, remote_id);
                    return;
                }
            };

            if !entry.wait_write_turn(remote_id) {
                if entry.is_closed() {
                    // 远端已正常关闭输出，但 smart-socket 可能仍在持续发送输入。
                    // 继续读到对端 EOF，避免 Windows 丢弃带有未读数据的 socket 时发 RST。
                    while client.read(&mut buffer).is_ok_and(|read| read != 0) {}
                }
                return;
            }

            let packet = match AdbMessage::new(
                protocol::A_WRTE,
                local_id,
                remote_id,
                buffer[..read].to_vec(),
            ) {
                Ok(packet) => packet,
                Err(_) => return,
            };
            if inner.write_packet(packet).is_err() {
                entry.mark_failed("transport write failed");
                return;
            }
        }
    });
}

fn close_remote_after_input_end(
    inner: &TransportInner,
    entry: &StreamEntry,
    local_id: u32,
    remote_id: u32,
) {
    if !entry.is_closed() && entry.try_mark_close_packet_sent() {
        let _ = inner.write_packet(
            AdbMessage::new(protocol::A_CLSE, local_id, remote_id, Vec::new())
                .expect("A_CLSE packet should be valid"),
        );
    }
}

pub fn normalize_tcp_serial(target: &str) -> Result<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(AdbError::Usage("connect 目标不能为空".to_string()));
    }

    // Bracketed IPv6 literal already carries a port, leave as-is.
    if trimmed.starts_with('[') {
        return Ok(trimmed.to_string());
    }

    // Bare IPv6 literal contains multiple colons and no port.
    if trimmed.contains(':') && trimmed.matches(':').count() > 1 {
        return Ok(format!("[{trimmed}]:5555"));
    }

    if trimmed.rsplit_once(':').is_some() {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}:5555"))
    }
}

fn trace_packet(direction: &str, packet: &AdbMessage) {
    if !trace_enabled("packets") {
        return;
    }
    let mut payload = String::new();
    if packet.command == protocol::A_OPEN || packet.command == protocol::A_CNXN {
        payload = format!(" payload={:?}", String::from_utf8_lossy(&packet.payload));
    }
    eprintln!(
        "transport {direction} {} arg0={} arg1={} len={}{}",
        protocol::command_name(packet.command),
        packet.arg0,
        packet.arg1,
        packet.payload.len(),
        payload
    );
}

fn trace_transport_error(context: &str, err: &AdbError) {
    if trace_enabled("transport") {
        eprintln!("transport {context} error: {err}");
    }
}

pub fn parse_banner(banner: &str) -> ParsedBanner {
    let mut parts = banner.splitn(3, ':');
    let kind = parts.next().unwrap_or_default();
    let _serial = parts.next();
    let props = parts.next().unwrap_or_default();

    let mut parsed = ParsedBanner {
        state: ConnectionState::from_banner_type(kind),
        product: None,
        model: None,
        device: None,
        features: None,
    };

    for prop in props.split(';').filter(|prop| !prop.is_empty()) {
        let Some((key, value)) = prop.split_once('=') else {
            continue;
        };

        match key {
            "ro.product.name" => parsed.product = Some(value.to_string()),
            "ro.product.model" => parsed.model = Some(value.to_string()),
            "ro.product.device" => parsed.device = Some(value.to_string()),
            "features" => parsed.features = Some(value.to_string()),
            _ => {}
        }
    }

    parsed
}

pub fn format_devices(infos: &[TransportInfo], long: bool) -> String {
    let mut out = String::new();
    for info in sorted_device_infos(infos) {
        let serial = if info.serial.is_empty() {
            "(no serial number)"
        } else {
            &info.serial
        };
        if long {
            out.push_str(&format!("{serial:<22} {}", info.state.as_adb()));
            append_device_info(&mut out, "", info.devpath.as_deref(), false);
            append_device_info(&mut out, "product:", info.product.as_deref(), false);
            append_device_info(&mut out, "model:", info.model.as_deref(), true);
            append_device_info(&mut out, "device:", info.device.as_deref(), false);
            out.push_str(" transport_id:");
            out.push_str(&info.id.to_string());
        } else {
            out.push_str(serial);
            out.push('\t');
            out.push_str(&info.state.as_adb());
        }
        out.push('\n');
    }
    out
}

pub(crate) fn sorted_device_infos(infos: &[TransportInfo]) -> Vec<&TransportInfo> {
    let mut sorted = infos.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.connection_type
            .aosp_sort_key()
            .cmp(&right.connection_type.aosp_sort_key())
            .then_with(|| left.serial.cmp(&right.serial))
    });
    sorted
}

fn append_device_info(out: &mut String, key: &str, value: Option<&str>, alphanumeric: bool) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return;
    };
    out.push(' ');
    out.push_str(key);
    out.push_str(&sanitize_device_field(value, alphanumeric));
}

pub(crate) fn sanitize_device_field(value: &str, alphanumeric: bool) -> String {
    if alphanumeric {
        value
            .as_bytes()
            .iter()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() {
                    char::from(*byte)
                } else {
                    '_'
                }
            })
            .collect()
    } else {
        value.replace('\n', "_")
    }
}

pub fn transport_features(info: &TransportInfo) -> String {
    info.features.clone().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;

    use crate::test_adbd::StubAdbd;

    use super::*;

    fn fake_usb_interface_for_serial(serial_number: Option<&str>) -> usb::UsbAdbInterface {
        usb::UsbAdbInterface {
            backend: usb::UsbInterfaceBackend::Libusb,
            bus_number: 1,
            device_address: 19,
            bus_address: "usb:1-2".to_string(),
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            vendor_id: 0x2717,
            product_id: 0xff18,
            interface_number: 1,
            setting_number: 0,
            class_code: usb::ADB_CLASS,
            subclass_code: usb::ADB_SUBCLASS,
            protocol_code: usb::ADB_PROTOCOL,
            bulk_in: usb::UsbEndpoint {
                address: 0x81,
                max_packet_size: 512,
            },
            bulk_out: usb::UsbEndpoint {
                address: 0x01,
                max_packet_size: 512,
            },
            manufacturer: None,
            product: None,
            serial_number: serial_number.map(str::to_string),
        }
    }

    #[test]
    fn usb_attach_preserves_original_serial_when_descriptor_read_falls_back() {
        let interface = fake_usb_interface_for_serial(None);
        assert_eq!(
            usb_transport_serial(&interface, Some("8b876adb")),
            "8b876adb"
        );
        assert_eq!(
            usb_transport_serial(&interface, None),
            interface.usb_serial_fallback()
        );
    }

    #[test]
    fn parses_device_banner_properties() {
        let banner =
            "device::ro.product.name=a;ro.product.model=b;ro.product.device=c;features=x,y;";
        let parsed = parse_banner(banner);

        assert_eq!(parsed.state, ConnectionState::Device);
        assert_eq!(parsed.product.as_deref(), Some("a"));
        assert_eq!(parsed.model.as_deref(), Some("b"));
        assert_eq!(parsed.device.as_deref(), Some("c"));
        assert_eq!(parsed.features.as_deref(), Some("x,y"));
    }

    #[test]
    fn detached_state_matches_aosp_text_and_wait_semantics() {
        let parsed = parse_banner("detached::");

        assert_eq!(parsed.state, ConnectionState::Detached);
        assert_eq!(ConnectionState::Detached.as_adb(), "detached");
        let info = TransportInfo {
            id: 1,
            serial: "usb-1".to_string(),
            devpath: None,
            connection_type: TransportConnectionType::Usb,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Detached,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        };
        assert!(!info.is_wait_active());
    }

    #[test]
    fn supported_feature_filter_matches_can_use_feature_semantics() {
        let features = "unknown,cmd,track_app,openscreen_mdns,sendrecv_v2_zstd,push_sync,libusb";

        assert_eq!(
            filter_supported_features(features),
            vec!["cmd", "track_app", "openscreen_mdns", "sendrecv_v2_zstd"]
        );
        assert!(can_use_feature(features, "cmd"));
        assert!(can_use_feature(features, "openscreen_mdns"));
        assert!(!can_use_feature(features, "push_sync"));
        assert!(!can_use_feature(features, "libusb"));
        assert!(!can_use_feature(features, "unknown"));
    }

    #[test]
    fn host_features_string_is_backed_by_supported_feature_table() {
        let host_features = host_features_string();
        for feature in SUPPORTED_FEATURES {
            assert!(host_features.split(',').any(|value| value == *feature));
        }
        assert!(host_features.split(',').any(|value| value == "push_sync"));
        assert_eq!(
            host_features.split(',').any(|value| value == "libusb"),
            crate::usb::selected_usb_backend() == crate::usb::UsbHostBackend::Libusb
        );
    }

    #[test]
    fn burst_mode_and_delayed_ack_feature_match_aosp_env_gate() {
        assert!(!burst_mode_enabled_for_env(None));
        assert!(!burst_mode_enabled_for_env(Some("0")));
        assert!(!burst_mode_enabled_for_env(Some("true")));
        assert!(burst_mode_enabled_for_env(Some("1")));

        let normal = supported_features_string_for_burst(false);
        let burst = supported_features_string_for_burst(true);
        assert!(!has_feature(&normal, FEATURE_DELAYED_ACK));
        assert!(has_feature(&burst, FEATURE_DELAYED_ACK));
    }

    #[test]
    fn adb_trace_setting_accepts_official_all_and_tag_shapes() {
        assert!(!trace_setting_enabled(None, "packets"));
        assert!(!trace_setting_enabled(Some(""), "packets"));
        assert!(trace_setting_enabled(Some("1"), "packets"));
        assert!(trace_setting_enabled(Some("all"), "transport"));
        assert!(trace_setting_enabled(
            Some("adb,packets transport"),
            "packets"
        ));
        assert!(trace_setting_enabled(
            Some("adb,packets transport"),
            "transport"
        ));
        assert!(!trace_setting_enabled(Some("adb,services"), "packets"));
        assert!(unknown_trace_flags(Some("adb,unknown services")).contains(&"unknown"));
        assert!(unknown_trace_flags(Some("1,unknown")).contains(&"unknown"));
        assert!(unknown_trace_flags(Some("all")).is_empty());
    }

    #[test]
    fn negotiated_protocol_version_is_capped_to_host_version() {
        assert_eq!(
            protocol::A_VERSION.min(protocol::A_VERSION),
            protocol::A_VERSION
        );
        assert_eq!(
            protocol::A_VERSION.min(protocol::A_VERSION + 1),
            protocol::A_VERSION
        );
        assert_eq!(
            protocol::A_VERSION.min(protocol::A_VERSION_MIN),
            protocol::A_VERSION_MIN
        );
    }

    #[test]
    fn normalizes_tcp_targets_to_default_port() {
        assert_eq!(normalize_tcp_serial("192.0.2.1").unwrap(), "192.0.2.1:5555");
        assert_eq!(
            normalize_tcp_serial("192.0.2.1:4567").unwrap(),
            "192.0.2.1:4567"
        );
    }

    #[test]
    fn normalizes_bare_ipv6_to_bracketed_with_default_port() {
        assert_eq!(normalize_tcp_serial("::1").unwrap(), "[::1]:5555");
        assert_eq!(
            normalize_tcp_serial("2001:db8::1").unwrap(),
            "[2001:db8::1]:5555"
        );
    }

    #[test]
    fn preserves_bracketed_ipv6_with_explicit_port() {
        assert_eq!(normalize_tcp_serial("[::1]:1234").unwrap(), "[::1]:1234");
        assert_eq!(
            normalize_tcp_serial("[2001:db8::1]:5555").unwrap(),
            "[2001:db8::1]:5555"
        );
    }

    #[test]
    fn formats_long_device_list() {
        let list = vec![TransportInfo {
            id: 7,
            serial: "127.0.0.1:5555".to_string(),
            devpath: None,
            connection_type: TransportConnectionType::Socket,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Device,
            product: Some("sdk".to_string()),
            model: Some("Pixel".to_string()),
            device: Some("emu".to_string()),
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        }];

        assert_eq!(
            format_devices(&list, true),
            "127.0.0.1:5555         device product:sdk model:Pixel device:emu transport_id:7\n"
        );
    }

    #[test]
    fn device_list_uses_aosp_transport_type_then_serial_order() {
        let make_device = |serial: &str, connection_type: TransportConnectionType| TransportInfo {
            id: 7,
            serial: serial.to_string(),
            devpath: None,
            connection_type,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Device,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        };
        let devices = vec![
            make_device("socket-a", TransportConnectionType::Socket),
            make_device("usb-z", TransportConnectionType::Usb),
            make_device("usb-a", TransportConnectionType::Usb),
        ];

        assert_eq!(
            format_devices(&devices, false),
            "usb-a\tdevice\nusb-z\tdevice\nsocket-a\tdevice\n"
        );
        assert_eq!(
            format_devices(&devices, true),
            concat!(
                "usb-a                  device transport_id:7\n",
                "usb-z                  device transport_id:7\n",
                "socket-a               device transport_id:7\n"
            )
        );
    }

    #[test]
    fn long_device_list_matches_aosp_devpath_and_sanitizing() {
        let device = TransportInfo {
            id: 9,
            serial: String::new(),
            devpath: Some("usb:1-2\nextra".to_string()),
            connection_type: TransportConnectionType::Usb,
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            state: ConnectionState::Device,
            product: Some("prod\nuct".to_string()),
            model: Some("Pixel 8-Pro".to_string()),
            device: Some("dev\nice".to_string()),
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        };

        assert_eq!(
            format_devices(&[device], true),
            concat!(
                "(no serial number)     device usb:1-2_extra product:prod_uct ",
                "model:Pixel_8_Pro device:dev_ice transport_id:9\n"
            )
        );
    }

    #[test]
    fn device_list_uses_aosp_no_permissions_help_text() {
        let device = TransportInfo {
            id: 9,
            serial: "denied-usb".to_string(),
            devpath: Some("usb:1-2".to_string()),
            connection_type: TransportConnectionType::Usb,
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            state: ConnectionState::NoPermissions,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        };

        let short = format_devices(std::slice::from_ref(&device), false);
        assert!(short.starts_with("denied-usb\tno permissions"));
        assert!(short.ends_with("; see [http://developer.android.com/tools/device.html]\n"));

        let long = format_devices(&[device], true);
        assert!(long.starts_with("denied-usb             no permissions"));
        assert!(long.contains(" usb:1-2 transport_id:9\n"));
    }

    #[test]
    fn tcp_connect_reads_cnxn_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);

            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION + 1,
                protocol::MAX_PAYLOAD as u32,
                b"device::ro.product.name=sdk;ro.product.model=Pixel;ro.product.device=emu;"
                    .to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
        });

        let transport = connect_tcp(9, &addr.to_string()).unwrap();
        server.join().unwrap();

        assert_eq!(transport.info().id, 9);
        assert_eq!(transport.read_timeout_for_test().unwrap(), None);
        assert_eq!(transport.info().serial, addr.to_string());
        assert_eq!(transport.info().state, ConnectionState::Device);
        assert_eq!(transport.info().model.as_deref(), Some("Pixel"));
        assert_eq!(
            transport.info().protocol_version,
            protocol::A_VERSION,
            "设备报告更高版本时必须按 AOSP 协商到 host 支持的版本"
        );
    }

    #[test]
    fn stub_adbd_fixture_bridges_shell_service() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |stream| {
            let open = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"shell:stub\0");
            let host_id = open.arg0;
            let device_id = 91;

            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(protocol::A_WRTE, device_id, host_id, b"stub\n".to_vec())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            let ack = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            assert_eq!(ack.arg0, host_id);
            assert_eq!(ack.arg1, device_id);
            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        });

        let transport = adbd.connect_transport(16);
        let client = spawn_service_client(transport, "shell:stub");

        adbd.join();
        assert_eq!(client.join().unwrap(), b"OKAYstub\n");
    }

    #[test]
    fn incoming_reverse_open_bridges_configured_tcp_service() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_service = format!("tcp:{}", listener.local_addr().unwrap().port());
        let incoming_service = local_service.clone();
        let (configured_tx, configured_rx) = std::sync::mpsc::channel();

        let local = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(b"from-host").unwrap();
            let mut received = [0_u8; 11];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"from-device");
            let mut trailing = Vec::new();
            stream.read_to_end(&mut trailing).unwrap();
            assert!(trailing.is_empty());
        });

        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), move |stream| {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            configured_rx.recv().unwrap();
            let mut payload = incoming_service.into_bytes();
            payload.push(0);
            let device_id = 71;
            AdbMessage::new(protocol::A_OPEN, device_id, 0, payload)
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

            let ready = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ready.command, protocol::A_OKAY);
            assert_ne!(ready.arg0, 0);
            assert_eq!(ready.arg1, device_id);
            let host_id = ready.arg0;

            let host_write = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(host_write.command, protocol::A_WRTE);
            assert_eq!(host_write.arg0, host_id);
            assert_eq!(host_write.arg1, device_id);
            assert_eq!(host_write.payload, b"from-host");
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

            AdbMessage::new(
                protocol::A_WRTE,
                device_id,
                host_id,
                b"from-device".to_vec(),
            )
            .unwrap()
            .write_to(stream, protocol::A_VERSION)
            .unwrap();
            let ack = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            assert_eq!(ack.arg0, host_id);
            assert_eq!(ack.arg1, device_id);

            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        });

        let transport = adbd.connect_transport(21);
        transport
            .inner
            .update_reverse_config(&format!("reverse:forward:tcp:9000;{local_service}"));
        configured_tx.send(()).unwrap();

        adbd.join();
        local.join().unwrap();
    }

    #[cfg(unix)]
    fn assert_reverse_filesystem_round_trip(prefix: &str) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(format!("{prefix}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"from-host").unwrap();
            let mut received = [0_u8; 11];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"from-device");
        });

        let mut stream = connect_reverse_service(&format!("{prefix}:{}", path.display())).unwrap();
        let mut received = [0_u8; 9];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"from-host");
        stream.write_all(b"from-device").unwrap();

        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reverse_local_and_localfilesystem_connect_to_unix_socket() {
        assert_reverse_filesystem_round_trip("local");
        assert_reverse_filesystem_round_trip("localfilesystem");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reverse_localabstract_connects_to_linux_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("adb_rust_reverse_{}_{}", std::process::id(), stamp);
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind_addr(&address).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"from-host").unwrap();
            let mut received = [0_u8; 11];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"from-device");
        });

        let mut stream = connect_reverse_service(&format!("localabstract:{name}")).unwrap();
        let mut received = [0_u8; 9];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"from-host");
        stream.write_all(b"from-device").unwrap();

        server.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reverse_vsock_errors_match_aosp_parser_boundaries() {
        for (address, expected) in [
            ("vsock:", "could not parse vsock cid in 'vsock:'"),
            (
                "vsock:x:5555",
                "could not parse vsock cid in 'vsock:x:5555'",
            ),
            ("vsock:2:x", "could not parse vsock port in 'vsock:2:x'"),
            ("vsock:2", "vsock port was not provided."),
            ("vsock:2:0", "vsock port was not provided."),
            (
                "vsock:2:5555:extra",
                "expected vsock:cid or vsock:cid:port in 'vsock:2:5555:extra'",
            ),
        ] {
            match connect_reverse_service(address) {
                Err(AdbError::Server(message)) => assert_eq!(message, expected),
                Err(other) => panic!("unexpected error for {address}: {other}"),
                Ok(_) => panic!("unexpected success for {address}"),
            }
        }
    }

    #[test]
    fn reverse_connector_rejects_host_unavailable_socket_types() {
        for (address, expected) in [
            (
                "localreserved:adb-rust",
                "socket type localreserved is unavailable on this platform",
            ),
            ("acceptfd:42", "cannot connect to acceptfd"),
            (
                "unknown:value",
                "unknown socket specification: unknown:value",
            ),
        ] {
            match connect_reverse_service(address) {
                Err(AdbError::Server(message)) => assert_eq!(message, expected),
                Err(other) => panic!("unexpected error for {address}: {other}"),
                Ok(_) => panic!("unexpected success for {address}"),
            }
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn reverse_filesystem_socket_types_are_unavailable_on_windows() {
        for (address, expected) in [
            (
                "local:C:/adb-rust.sock",
                "socket type local is unavailable on this platform",
            ),
            (
                "localfilesystem:C:/adb-rust.sock",
                "socket type localfilesystem is unavailable on this platform",
            ),
        ] {
            match connect_reverse_service(address) {
                Err(AdbError::Server(message)) => assert_eq!(message, expected),
                Err(other) => panic!("unexpected error for {address}: {other}"),
                Ok(_) => panic!("unexpected success for {address}"),
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn reverse_linux_socket_types_are_unavailable_off_linux() {
        for (address, expected) in [
            (
                "localabstract:adb-rust",
                "socket type localabstract is unavailable on this platform",
            ),
            ("vsock:2:5555", "vsock is only supported on Linux"),
        ] {
            match connect_reverse_service(address) {
                Err(AdbError::Server(message)) => assert_eq!(message, expected),
                Err(other) => panic!("unexpected error for {address}: {other}"),
                Ok(_) => panic!("unexpected success for {address}"),
            }
        }
    }

    #[test]
    fn incoming_reverse_open_rejects_unconfigured_service() {
        let (send_tx, send_rx) = std::sync::mpsc::channel();
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), move |stream| {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            send_rx.recv().unwrap();
            AdbMessage::new(protocol::A_OPEN, 81, 0, b"tcp:65534\0\0".to_vec())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

            let close = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(close.command, protocol::A_CLSE);
            assert_eq!(close.arg0, 0);
            assert_eq!(close.arg1, 81);
        });

        let _transport = adbd.connect_transport(22);
        send_tx.send(()).unwrap();
        adbd.join();
    }

    #[test]
    fn reverse_config_updates_match_aosp_allowlist() {
        let transport = Transport::fake(TransportInfo {
            id: 23,
            serial: "reverse-config".to_string(),
            devpath: None,
            connection_type: TransportConnectionType::Socket,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Device,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        });
        let inner = &transport.inner;

        inner.update_reverse_config("reverse:forward:tcp:7000;tcp:8000");
        assert!(inner.is_reverse_configured("tcp:8000"));
        inner.update_reverse_config("reverse:forward:norebind:tcp:7000;tcp:8001");
        assert!(inner.is_reverse_configured("tcp:8000"));
        assert!(!inner.is_reverse_configured("tcp:8001"));

        inner.update_reverse_config("reverse:forward:tcp:7000;tcp:8001");
        assert!(!inner.is_reverse_configured("tcp:8000"));
        assert!(inner.is_reverse_configured("tcp:8001"));
        inner.update_reverse_config("reverse:killforward:tcp:7000");
        assert!(!inner.is_reverse_configured("tcp:8001"));

        inner.update_reverse_config("reverse:forward:tcp:7001;tcp:8002");
        inner.update_reverse_config("reverse:killforward-all");
        assert!(!inner.is_reverse_configured("tcp:8002"));
    }

    #[test]
    fn tcp_connect_can_override_registered_serial_for_emulator() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);

            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::ro.product.model=Emulator;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let transport = prepare_tcp_stream_with_serial(14, "emulator-5554".to_string(), stream)
            .unwrap()
            .finish(|_| {})
            .unwrap();
        server.join().unwrap();

        assert_eq!(transport.info().serial, "emulator-5554");
        assert_eq!(transport.info().model.as_deref(), Some("Emulator"));
    }

    #[test]
    fn tcp_connect_marks_auth_token_as_unauthorized() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_AUTH,
                protocol::ADB_AUTH_TOKEN,
                0,
                vec![7_u8; 20],
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION_MIN)
            .unwrap();
        });

        let transport = connect_tcp_with_auth(10, &addr.to_string(), Vec::new()).unwrap();
        server.join().unwrap();

        assert_eq!(transport.info().state, ConnectionState::Unauthorized);
    }

    #[test]
    fn pending_transport_reports_authorizing_before_online() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let auth_key = AuthKey::from_private_key(private_key, None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_AUTH,
                protocol::ADB_AUTH_TOKEN,
                0,
                vec![5_u8; 20],
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION_MIN)
            .unwrap();

            release_rx.recv().unwrap();
            let signature = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(signature.command, protocol::A_AUTH);
            assert_eq!(signature.arg0, protocol::ADB_AUTH_SIGNATURE);
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let pending = prepare_tcp_stream_with_serial_and_auth(
            25,
            "pending-device".to_string(),
            stream,
            vec![auth_key],
            false,
        )
        .unwrap();
        let placeholder = pending.transport();
        assert_eq!(placeholder.info().state, ConnectionState::Offline);
        let (state_tx, state_rx) = std::sync::mpsc::channel();
        let finisher =
            thread::spawn(move || pending.finish(move |state| state_tx.send(state).unwrap()));

        assert_eq!(
            state_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ConnectionState::Authorizing
        );
        assert_eq!(placeholder.info().state, ConnectionState::Authorizing);
        release_tx.send(()).unwrap();
        let transport = finisher.join().unwrap().unwrap();

        assert!(transport.same_instance(&placeholder));
        assert_eq!(transport.info().state, ConnectionState::Device);
        server.join().unwrap();
    }

    #[test]
    fn tcp_auth_token_is_signed_before_cnxn() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let auth_key = AuthKey::from_private_key(private_key, None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_AUTH,
                protocol::ADB_AUTH_TOKEN,
                0,
                vec![9_u8; 20],
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION_MIN)
            .unwrap();

            let signature = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(signature.command, protocol::A_AUTH);
            assert_eq!(signature.arg0, protocol::ADB_AUTH_SIGNATURE);
            assert_eq!(signature.payload.len(), 128);

            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
        });

        let transport = connect_tcp_with_auth(13, &addr.to_string(), vec![auth_key]).unwrap();
        server.join().unwrap();

        assert_eq!(transport.info().state, ConnectionState::Device);
    }

    #[test]
    fn tcp_connect_upgrades_stls_to_tls_and_receives_cnxn() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let auth_key =
            AuthKey::from_private_key(private_key, Some("test-public-key user@host".to_string()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);

            AdbMessage::new(protocol::A_STLS, protocol::A_STLS_VERSION, 0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION_MIN)
                .unwrap();

            let reply = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(reply.command, protocol::A_STLS);
            assert_eq!(reply.arg0, protocol::A_STLS_VERSION);
            assert_eq!(reply.arg1, 0);
            assert!(reply.payload.is_empty());

            let mut tls = crate::pairing::start_test_server_tls(stream).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut tls, protocol::A_VERSION)
            .unwrap();
            tls.flush().unwrap();
        });

        let transport = connect_tcp_with_auth(18, &addr.to_string(), vec![auth_key]).unwrap();
        assert_eq!(transport.info().state, ConnectionState::Device);
        assert_eq!(transport.info().features.as_deref(), Some("shell_v2"));
        server.join().unwrap();
    }

    #[test]
    fn tcp_tls_transport_bridges_service_packets_after_stls() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let auth_key =
            AuthKey::from_private_key(private_key, Some("test-public-key user@host".to_string()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);
            AdbMessage::new(protocol::A_STLS, protocol::A_STLS_VERSION, 0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION_MIN)
                .unwrap();
            let stls = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(stls.command, protocol::A_STLS);

            let mut tls = crate::pairing::start_test_server_tls(stream).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut tls, protocol::A_VERSION)
            .unwrap();
            tls.flush().unwrap();

            let open = AdbMessage::read_from(&mut tls, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"shell:echo secure\0");
            let host_id = open.arg0;
            let device_id = 77;
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut tls, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(
                protocol::A_WRTE,
                device_id,
                host_id,
                b"secure-ok\n".to_vec(),
            )
            .unwrap()
            .write_to(&mut tls, protocol::A_VERSION)
            .unwrap();
            tls.flush().unwrap();
            let ack = AdbMessage::read_from(&mut tls, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut tls, protocol::A_VERSION)
                .unwrap();
            tls.flush().unwrap();
        });

        let transport = connect_tcp_with_auth(19, &address.to_string(), vec![auth_key]).unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_address = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_address).unwrap();
            let mut status = [0_u8; 4];
            stream.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY");
            let mut output = Vec::new();
            stream.read_to_end(&mut output).unwrap();
            output
        });
        let (smart_client, _) = client_listener.accept().unwrap();
        transport
            .serve_service("shell:echo secure", smart_client)
            .unwrap();

        assert_eq!(client.join().unwrap(), b"secure-ok\n");
        adbd.join().unwrap();
    }

    #[test]
    fn tcp_tls_transport_retries_plaintext_short_writes_for_large_packets() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let auth_key =
            AuthKey::from_private_key(private_key, Some("test-public-key user@host".to_string()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = vec![0x5a; 64 * 1024];
        let server_expected = expected.clone();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);
            AdbMessage::new(protocol::A_STLS, protocol::A_STLS_VERSION, 0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION_MIN)
                .unwrap();
            let stls = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(stls.command, protocol::A_STLS);

            let mut tls = crate::pairing::start_test_server_tls(stream).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut tls, protocol::A_VERSION)
            .unwrap();
            tls.flush().unwrap();

            let open = AdbMessage::read_from(&mut tls, protocol::MAX_PAYLOAD).unwrap();
            let host_id = open.arg0;
            let device_id = 78;
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut tls, protocol::A_VERSION)
                .unwrap();
            tls.flush().unwrap();

            let write = AdbMessage::read_from(&mut tls, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(write.command, protocol::A_WRTE);
            assert_eq!(write.payload, server_expected);
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut tls, protocol::A_VERSION)
                .unwrap();
            tls.flush().unwrap();

            let close = AdbMessage::read_from(&mut tls, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(close.command, protocol::A_CLSE);
            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut tls, protocol::A_VERSION)
                .unwrap();
            tls.flush().unwrap();
        });

        let transport = connect_tcp_with_auth(20, &address.to_string(), vec![auth_key]).unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_address = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_address).unwrap();
            let mut status = [0_u8; 4];
            stream.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY");
            stream.write_all(&expected).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut output = Vec::new();
            stream.read_to_end(&mut output).unwrap();
            output
        });
        let (smart_client, _) = client_listener.accept().unwrap();
        transport.serve_service("sync:", smart_client).unwrap();

        assert!(client.join().unwrap().is_empty());
        adbd.join().unwrap();
    }

    #[test]
    fn service_bridge_opens_and_forwards_remote_output() {
        let transport_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport_addr = transport_listener.local_addr().unwrap();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = transport_listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let open = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"shell:echo ok\0");
            let host_id = open.arg0;
            let device_id = 91;

            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(protocol::A_WRTE, device_id, host_id, b"ok\n".to_vec())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            let ack = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            assert_eq!(ack.arg0, host_id);
            assert_eq!(ack.arg1, device_id);
            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
        });

        let transport = connect_tcp(11, &transport_addr.to_string()).unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_addr).unwrap();
            let mut out = Vec::new();
            stream.read_to_end(&mut out).unwrap();
            out
        });
        let (server_client, _) = client_listener.accept().unwrap();

        transport
            .serve_service("shell:echo ok", server_client)
            .unwrap();
        adbd.join().unwrap();

        assert_eq!(client.join().unwrap(), b"OKAYok\n");
    }

    #[test]
    fn remote_close_flushes_output_when_smart_socket_has_unread_input() {
        let transport_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport_addr = transport_listener.local_addr().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = transport_listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let open = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            let host_id = open.arg0;
            let device_id = 92;
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();

            let input = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(input.command, protocol::A_WRTE);
            assert!(!input.payload.is_empty());

            let output = vec![0_u8; 1024 * 1024];
            AdbMessage::new(protocol::A_WRTE, device_id, host_id, output)
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            let ack = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();

            release_rx.recv().unwrap();
        });

        let transport = connect_tcp(12, &transport_addr.to_string()).unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_addr).unwrap();
            let mut status = [0_u8; 4];
            stream.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY");

            let mut writer = stream.try_clone().unwrap();
            writer
                .set_write_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let spam = thread::spawn(move || {
                let input = [0_u8; 16 * 1024];
                while writer.write_all(&input).is_ok() {}
            });

            let mut output = Vec::new();
            let read_result = stream.read_to_end(&mut output);
            let _ = stream.shutdown(Shutdown::Both);
            spam.join().unwrap();
            (read_result, output)
        });
        let (server_client, _) = client_listener.accept().unwrap();
        transport
            .serve_service("shell:large-output", server_client)
            .unwrap();

        let (read_result, output) = client.join().unwrap();
        release_tx.send(()).unwrap();
        adbd.join().unwrap();
        read_result.unwrap();
        assert_eq!(output.len(), 1024 * 1024);
    }

    #[test]
    fn transport_failure_closes_smart_socket_without_resetting_pending_input() {
        let transport_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport_addr = transport_listener.local_addr().unwrap();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = transport_listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let open = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(protocol::A_OKAY, 93, open.arg0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            let input = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(input.command, protocol::A_WRTE);
            assert!(!input.payload.is_empty());
            // 不发送 A_CLSE，直接模拟 wireless transport 中断。
        });

        let transport = connect_tcp(13, &transport_addr.to_string()).unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_addr).unwrap();
            let mut status = [0_u8; 4];
            stream.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY");

            let mut writer = stream.try_clone().unwrap();
            writer
                .set_write_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let spam = thread::spawn(move || {
                let input = [0_u8; 16 * 1024];
                while writer.write_all(&input).is_ok() {}
            });

            let mut output = Vec::new();
            let read_result = stream.read_to_end(&mut output);
            let _ = stream.shutdown(Shutdown::Both);
            spam.join().unwrap();
            read_result
        });
        let (server_client, _) = client_listener.accept().unwrap();
        transport
            .serve_service("shell:transport-failure", server_client)
            .unwrap();

        adbd.join().unwrap();
        client.join().unwrap().unwrap();
    }

    #[test]
    fn detached_transport_rejects_device_service_as_offline() {
        let transport = Transport::fake(TransportInfo {
            id: 17,
            serial: "usb-detached".to_string(),
            devpath: None,
            connection_type: TransportConnectionType::Usb,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Detached,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        });
        let client = spawn_service_client(transport, "shell:id");

        let out = client.join().unwrap();
        assert!(out.starts_with(b"FAIL"));
        let reason = protocol::read_protocol_string(&mut &out[4..]).unwrap();
        assert_eq!(reason, "device offline (transport offline)");
    }

    #[test]
    fn transport_close_closes_underlying_connection() {
        let closed = Arc::new(AtomicBool::new(false));
        let transport = Transport {
            inner: Arc::new(TransportInner {
                info: Mutex::new(TransportInfo {
                    id: 18,
                    serial: "close-test".to_string(),
                    devpath: None,
                    connection_type: TransportConnectionType::Socket,
                    negotiated_speed_mbps: 0,
                    max_speed_mbps: 0,
                    state: ConnectionState::Device,
                    product: None,
                    model: None,
                    device: None,
                    features: None,
                    max_payload: protocol::MAX_PAYLOAD,
                    protocol_version: protocol::A_VERSION,
                }),
                delayed_ack: AtomicBool::new(false),
                writer: Mutex::new(Box::new(CloseTrackingConnection {
                    closed: Arc::clone(&closed),
                    fail_write: false,
                })),
                streams: Mutex::new(HashMap::new()),
                reverse_forwards: Mutex::new(HashMap::new()),
                next_local_id: AtomicU32::new(1),
                closed: AtomicBool::new(false),
            }),
        };

        transport.close();

        assert!(closed.load(Ordering::SeqCst));
        assert!(transport.is_closed());
    }

    #[test]
    fn transport_write_failure_closes_underlying_connection() {
        let closed = Arc::new(AtomicBool::new(false));
        let transport = Transport {
            inner: Arc::new(TransportInner {
                info: Mutex::new(TransportInfo {
                    id: 19,
                    serial: "write-failure".to_string(),
                    devpath: None,
                    connection_type: TransportConnectionType::Usb,
                    negotiated_speed_mbps: 0,
                    max_speed_mbps: 0,
                    state: ConnectionState::Device,
                    product: None,
                    model: None,
                    device: None,
                    features: None,
                    max_payload: protocol::MAX_PAYLOAD,
                    protocol_version: protocol::A_VERSION,
                }),
                delayed_ack: AtomicBool::new(false),
                writer: Mutex::new(Box::new(CloseTrackingConnection {
                    closed: Arc::clone(&closed),
                    fail_write: true,
                })),
                streams: Mutex::new(HashMap::new()),
                reverse_forwards: Mutex::new(HashMap::new()),
                next_local_id: AtomicU32::new(1),
                closed: AtomicBool::new(false),
            }),
        };

        let err = transport
            .write_packet(AdbMessage::new(protocol::A_OKAY, 1, 1, Vec::new()).unwrap())
            .unwrap_err();

        assert!(matches!(err, AdbError::Server(message) if message == "test write failed"));
        assert!(closed.load(Ordering::SeqCst));
        assert!(transport.is_closed());
    }

    #[test]
    fn device_rejects_open_with_close_writes_fail_to_client() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |stream| {
            let open = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            let host_id = open.arg0;

            // 设备直接拒绝 open：不发送 A_OKAY，只发送 A_CLSE。
            AdbMessage::new(protocol::A_CLSE, 0, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        });

        let transport = adbd.connect_transport(17);
        let client = spawn_service_client(transport, "unknown:");

        adbd.join();
        let response = client.join().unwrap();
        assert!(
            response.starts_with(b"FAIL"),
            "expected FAIL response when device rejects A_OPEN, got {response:?}"
        );
    }

    #[test]
    fn completed_open_remains_successful_when_remote_closes_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
        let (client, _) = listener.accept().unwrap();
        drop(connector.join().unwrap());

        let entry = StreamEntry::new(Box::new(client));
        entry.mark_open(73);
        assert!(!entry.mark_closed());
        assert!(entry.mark_client_ready());

        assert_eq!(entry.wait_open(), OpenResult::Ready(73));
    }

    #[test]
    fn service_bridge_uses_delayed_ack_open_credit_and_ack_payloads() {
        let adbd = StubAdbd::spawn(
            b"device::features=shell_v2,delayed_ack;".to_vec(),
            |stream| {
                let open = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
                assert_eq!(open.command, protocol::A_OPEN);
                assert_eq!(open.arg1, INITIAL_DELAYED_ACK_BYTES);
                assert_eq!(open.payload, b"shell:echo ok\0");
                let host_id = open.arg0;
                let device_id = 91;

                AdbMessage::new(
                    protocol::A_OKAY,
                    device_id,
                    host_id,
                    INITIAL_DELAYED_ACK_BYTES.to_le_bytes().to_vec(),
                )
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

                let stdin = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
                assert_eq!(stdin.command, protocol::A_WRTE);
                assert_eq!(stdin.arg0, host_id);
                assert_eq!(stdin.arg1, device_id);
                assert_eq!(stdin.payload, b"abc");

                AdbMessage::new(
                    protocol::A_OKAY,
                    device_id,
                    host_id,
                    3_u32.to_le_bytes().to_vec(),
                )
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
                AdbMessage::new(protocol::A_WRTE, device_id, host_id, b"ok\n".to_vec())
                    .unwrap()
                    .write_to(stream, protocol::A_VERSION)
                    .unwrap();
                let ack = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
                assert_eq!(ack.command, protocol::A_OKAY);
                assert_eq!(ack.arg0, host_id);
                assert_eq!(ack.arg1, device_id);
                assert_eq!(ack.payload, 3_u32.to_le_bytes().to_vec());
                AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                    .unwrap()
                    .write_to(stream, protocol::A_VERSION)
                    .unwrap();
            },
        );

        let transport = adbd.connect_transport_with_burst(14);
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(client_addr).unwrap();
            let mut status = [0_u8; 4];
            stream.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY");
            stream.write_all(b"abc").unwrap();
            let mut out = Vec::new();
            stream.read_to_end(&mut out).unwrap();
            out
        });
        let (server_client, _) = client_listener.accept().unwrap();

        transport
            .serve_service("shell:echo ok", server_client)
            .unwrap();
        adbd.join();

        assert_eq!(client.join().unwrap(), b"ok\n");
    }

    #[test]
    fn transport_reader_demultiplexes_two_services() {
        let transport_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport_addr = transport_listener.local_addr().unwrap();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = transport_listener.accept().unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let first = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            let second = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(first.command, protocol::A_OPEN);
            assert_eq!(second.command, protocol::A_OPEN);
            let mut payloads = vec![first.payload.clone(), second.payload.clone()];
            payloads.sort();
            assert_eq!(
                payloads,
                vec![b"shell:first\0".to_vec(), b"shell:second\0".to_vec()]
            );
            let first_remote = 101;
            let second_remote = 202;

            AdbMessage::new(protocol::A_OKAY, second_remote, second.arg0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(protocol::A_OKAY, first_remote, first.arg0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(
                protocol::A_WRTE,
                first_remote,
                first.arg0,
                b"one\n".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
            AdbMessage::new(
                protocol::A_WRTE,
                second_remote,
                second.arg0,
                b"two\n".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let mut acks = Vec::new();
            for _ in 0..2 {
                acks.push(AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap());
            }
            assert!(acks.iter().any(|ack| ack.arg1 == first_remote));
            assert!(acks.iter().any(|ack| ack.arg1 == second_remote));

            AdbMessage::new(protocol::A_CLSE, first_remote, first.arg0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(protocol::A_CLSE, second_remote, second.arg0, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
        });

        let transport = connect_tcp(12, &transport_addr.to_string()).unwrap();
        let first = spawn_service_client(transport.clone(), "shell:first");
        let second = spawn_service_client(transport, "shell:second");

        adbd.join().unwrap();
        let mut outputs = vec![first.join().unwrap(), second.join().unwrap()];
        outputs.sort();
        assert_eq!(outputs, vec![b"OKAYone\n".to_vec(), b"OKAYtwo\n".to_vec()]);
    }

    #[test]
    fn client_write_failure_closes_only_that_stream() {
        let transport_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport_addr = transport_listener.local_addr().unwrap();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = transport_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let _hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                b"device::features=shell_v2;".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            let open = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            let host_id = open.arg0;
            let device_id = 91;
            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(protocol::A_WRTE, device_id, host_id, b"late\n".to_vec())
                .unwrap()
                .write_to(&mut stream, protocol::A_VERSION)
                .unwrap();

            let close = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(close.command, protocol::A_CLSE);
            assert_eq!(close.arg0, host_id);
            assert_eq!(close.arg1, device_id);

            let second = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(second.command, protocol::A_OPEN);
            assert_eq!(second.payload, b"shell:ok\0");
            let second_host_id = second.arg0;
            let second_device_id = 92;
            AdbMessage::new(
                protocol::A_OKAY,
                second_device_id,
                second_host_id,
                Vec::new(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
            AdbMessage::new(
                protocol::A_WRTE,
                second_device_id,
                second_host_id,
                b"ok\n".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
            let ack = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            assert_eq!(ack.arg0, second_host_id);
            assert_eq!(ack.arg1, second_device_id);
            AdbMessage::new(
                protocol::A_CLSE,
                second_device_id,
                second_host_id,
                Vec::new(),
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();
        });

        let transport = connect_tcp(15, &transport_addr.to_string()).unwrap();
        transport
            .serve_raw_service("shell:closed-client", FailingClientStream)
            .unwrap();
        let second = spawn_service_client(transport, "shell:ok");
        adbd.join().unwrap();

        assert_eq!(second.join().unwrap(), b"OKAYok\n");
    }

    struct FailingClientStream;

    struct CloseTrackingConnection {
        closed: Arc<AtomicBool>,
        fail_write: bool,
    }

    impl AdbConnection for CloseTrackingConnection {
        fn read_packet(&mut self, _max_payload: usize) -> Result<AdbMessage> {
            Err(AdbError::Server(
                "test connection has no reader".to_string(),
            ))
        }

        fn write_packet(&mut self, _packet: &AdbMessage, _protocol_version: u32) -> Result<()> {
            if self.fail_write {
                Err(AdbError::Server("test write failed".to_string()))
            } else {
                Ok(())
            }
        }

        fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
            Ok(Box::new(Self {
                closed: Arc::clone(&self.closed),
                fail_write: self.fail_write,
            }))
        }

        fn close_connection(&mut self) -> Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    impl Read for FailingClientStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for FailingClientStream {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test client is closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ClientStream for FailingClientStream {
        fn shutdown_stream(&self, _how: Shutdown) -> std::io::Result<()> {
            Ok(())
        }

        fn try_clone_box(&self) -> std::io::Result<Box<dyn ClientStream>> {
            Ok(Box::new(Self))
        }
    }

    fn spawn_service_client(
        transport: Transport,
        service: &'static str,
    ) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let client = thread::spawn(move || {
                let mut stream = TcpStream::connect(addr).unwrap();
                let mut out = Vec::new();
                stream.read_to_end(&mut out).unwrap();
                out
            });
            let (server_client, _) = listener.accept().unwrap();
            transport.serve_service(service, server_client).unwrap();
            client.join().unwrap()
        })
    }
}
