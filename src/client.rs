use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
#[cfg(unix)]
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use crate::error::{AdbError, Result};
use crate::protocol;
#[cfg(windows)]
use crate::windows_console::WindowsConsoleInput;

pub const DEFAULT_SERVER_HOST: &str = "127.0.0.1";
pub const DEFAULT_SERVER_PORT: u16 = 5037;
const DEFAULT_ADB_LOCAL_TRANSPORT_PORT: u16 = 5555;
#[cfg(target_os = "linux")]
const SERVER_REEXEC_ARG0: &str = "adb (re-execed)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerSocketKind {
    Tcp,
    LocalFilesystem { name: String, alias: bool },
    LocalAbstract { name: String },
    LocalReserved { name: String },
    Vsock { first: u32, second: Option<u32> },
    AcceptFd { fd: u32 },
}

#[derive(Debug)]
pub enum ServerStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(unix)]
    Raw(File),
}

impl ServerStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            #[cfg(unix)]
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
            #[cfg(unix)]
            Self::Raw(file) => file.try_clone().map(Self::Raw),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(how),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(how),
            #[cfg(unix)]
            Self::Raw(file) => shutdown_raw_socket(file.as_raw_fd(), how),
        }
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::Raw(file) => set_raw_socket_nonblocking(file.as_raw_fd(), nonblocking),
        }
    }

    #[cfg(unix)]
    pub(crate) fn from_raw_file(file: File) -> Self {
        Self::Raw(file)
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Raw(file) => file.read(buf),
        }
    }
}

impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Raw(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Raw(file) => file.flush(),
        }
    }
}

impl crate::transport::ClientStream for ServerStream {
    fn shutdown_stream(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }

    fn try_clone_box(&self) -> io::Result<Box<dyn crate::transport::ClientStream>> {
        Ok(Box::new(self.try_clone()?))
    }
}

#[cfg(unix)]
impl AsRawFd for ServerStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(stream) => stream.as_raw_fd(),
            Self::Unix(stream) => stream.as_raw_fd(),
            Self::Raw(file) => file.as_raw_fd(),
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for ServerStream {
    fn as_raw_socket(&self) -> RawSocket {
        match self {
            Self::Tcp(stream) => stream.as_raw_socket(),
        }
    }
}

#[cfg(unix)]
fn set_raw_socket_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn shutdown_raw_socket(fd: RawFd, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Read => libc::SHUT_RD,
        Shutdown::Write => libc::SHUT_WR,
        Shutdown::Both => libc::SHUT_RDWR,
    };
    if unsafe { libc::shutdown(fd, how) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEndpoint {
    pub host: String,
    pub port: u16,
    kind: ServerSocketKind,
    // AOSP 会区分 `tcp:PORT` 与显式的 `tcp:HOST:PORT`：只有前者在配合
    // `-a` 时改为监听所有接口。这里保留该信息，避免解析后丢失绑定语义。
    socket_host_explicit: bool,
    socket_port_explicit: bool,
    listen_all: bool,
}

impl Default for ServerEndpoint {
    fn default() -> Self {
        Self::for_port(DEFAULT_SERVER_PORT)
    }
}

impl ServerEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self::from_parts(host.into(), port, true)
    }

    pub fn for_port(port: u16) -> Self {
        Self::from_parts(DEFAULT_SERVER_HOST.to_string(), port, false)
    }

    fn from_parts(host: String, port: u16, socket_host_explicit: bool) -> Self {
        Self {
            host,
            port,
            kind: ServerSocketKind::Tcp,
            socket_host_explicit,
            socket_port_explicit: true,
            listen_all: false,
        }
    }

    fn from_socket_kind(kind: ServerSocketKind) -> Self {
        Self {
            host: String::new(),
            port: 0,
            kind,
            socket_host_explicit: true,
            socket_port_explicit: true,
            listen_all: false,
        }
    }

    pub fn set_listen_all(&mut self, listen_all: bool) {
        self.listen_all = listen_all;
    }

    pub fn listen_all(&self) -> bool {
        self.listen_all
    }

    pub fn from_env() -> Result<Self> {
        Self::from_env_values(
            std::env::var("ADB_SERVER_SOCKET").ok().as_deref(),
            std::env::var("ANDROID_ADB_SERVER_ADDRESS").ok().as_deref(),
            std::env::var("ANDROID_ADB_SERVER_PORT").ok().as_deref(),
        )
    }

    fn from_env_values(
        adb_server_socket: Option<&str>,
        android_adb_server_address: Option<&str>,
        android_adb_server_port: Option<&str>,
    ) -> Result<Self> {
        if let Some(socket) = adb_server_socket.filter(|value| !value.trim().is_empty()) {
            return parse_socket_spec(socket);
        }

        let host = android_adb_server_address.filter(|value| !value.trim().is_empty());
        let socket_host_explicit = host.is_some();
        let host = host.unwrap_or(DEFAULT_SERVER_HOST).to_string();
        let port = android_adb_server_port
            .filter(|value| !value.trim().is_empty())
            .map(parse_port)
            .transpose()?
            .unwrap_or(DEFAULT_SERVER_PORT);

        Ok(Self::from_parts(host, port, socket_host_explicit))
    }

    /// AOSP 对 `tcp:localhost` 使用 IPv4-preferred loopback listener；Windows 的
    /// network_loopback_server 还会忽略 prefer_ipv4=false，始终使用 IPv4。
    /// 显式 IPv6 loopback 仅在 Windows 归一化，Unix 平台保持原值。
    fn bind_host(&self) -> &str {
        if self.host == "localhost" {
            return "127.0.0.1";
        }
        #[cfg(windows)]
        if self.host == "::1" || self.host == "[::1]" {
            return "127.0.0.1";
        }
        &self.host
    }

    pub fn address(&self) -> String {
        if !matches!(self.kind, ServerSocketKind::Tcp) {
            return self.socket_spec();
        }
        let host = self.bind_host();
        if host.contains(':') && !host.starts_with('[') {
            format!("[{}]:{}", host, self.port)
        } else {
            format!("{}:{}", host, self.port)
        }
    }

    pub fn socket_spec(&self) -> String {
        match &self.kind {
            ServerSocketKind::LocalFilesystem { name, alias } => {
                return format!(
                    "{}:{name}",
                    if *alias { "local" } else { "localfilesystem" }
                );
            }
            ServerSocketKind::LocalAbstract { name } => {
                return format!("localabstract:{name}");
            }
            ServerSocketKind::LocalReserved { name } => {
                return format!("localreserved:{name}");
            }
            ServerSocketKind::Vsock { first, second } => {
                return second
                    .map(|second| format!("vsock:{first}:{second}"))
                    .unwrap_or_else(|| format!("vsock:{first}"));
            }
            ServerSocketKind::AcceptFd { fd } => return format!("acceptfd:{fd}"),
            ServerSocketKind::Tcp => {}
        }
        if !self.socket_host_explicit {
            return format!("tcp:{}", self.port);
        }

        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if !self.socket_port_explicit {
            return format!("tcp:{host}");
        }
        format!("tcp:{host}:{}", self.port)
    }

    pub fn bind_address(&self) -> String {
        if self.listen_all && !self.socket_host_explicit {
            format!("0.0.0.0:{}", self.port)
        } else {
            self.address()
        }
    }

    pub fn is_localhost(&self) -> bool {
        if matches!(
            self.kind,
            ServerSocketKind::LocalFilesystem { .. }
                | ServerSocketKind::LocalAbstract { .. }
                | ServerSocketKind::LocalReserved { .. }
        ) {
            return true;
        }
        if !matches!(self.kind, ServerSocketKind::Tcp) {
            return false;
        }
        matches!(
            self.host.as_str(),
            "127.0.0.1" | "localhost" | "::1" | "[::1]"
        )
    }

    pub(crate) fn socket_kind(&self) -> &ServerSocketKind {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransportSelector {
    #[default]
    Any,
    Serial(String),
    TransportId(u64),
    Usb,
    Local,
}

impl TransportSelector {
    pub fn transport_service(&self) -> String {
        match self {
            TransportSelector::Any => "host:transport-any".to_string(),
            TransportSelector::Serial(serial) => format!("host:transport:{serial}"),
            TransportSelector::TransportId(id) => format!("host:transport-id:{id}"),
            TransportSelector::Usb => "host:transport-usb".to_string(),
            TransportSelector::Local => "host:transport-local".to_string(),
        }
    }

    pub fn tport_service(&self) -> String {
        match self {
            TransportSelector::Any => "host:tport:any".to_string(),
            TransportSelector::Serial(serial) => format!("host:tport:serial:{serial}"),
            TransportSelector::TransportId(id) => format!("host:transport-id:{id}"),
            TransportSelector::Usb => "host:tport:usb".to_string(),
            TransportSelector::Local => "host:tport:local".to_string(),
        }
    }

    pub fn host_prefix(&self) -> String {
        match self {
            TransportSelector::Any => "host".to_string(),
            TransportSelector::Serial(serial) => format!("host-serial:{serial}"),
            TransportSelector::TransportId(id) => format!("host-transport-id:{id}"),
            TransportSelector::Usb => "host-usb".to_string(),
            TransportSelector::Local => "host-local".to_string(),
        }
    }
}

pub fn parse_port(value: &str) -> Result<u16> {
    value.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| {
        AdbError::Usage(format!(
            "$ANDROID_ADB_SERVER_PORT must be a positive number less than 65535: got \"{value}\""
        ))
    })
}

pub fn parse_socket_spec(spec: &str) -> Result<ServerEndpoint> {
    if let Some(tcp) = spec.strip_prefix("tcp:") {
        return parse_tcp_socket_spec(tcp);
    }

    if let Some(name) = spec.strip_prefix("local:") {
        return parse_local_socket_name(name).map(|name| {
            ServerEndpoint::from_socket_kind(ServerSocketKind::LocalFilesystem {
                name,
                alias: true,
            })
        });
    }
    if let Some(name) = spec.strip_prefix("localfilesystem:") {
        return parse_local_socket_name(name).map(|name| {
            ServerEndpoint::from_socket_kind(ServerSocketKind::LocalFilesystem {
                name,
                alias: false,
            })
        });
    }
    if let Some(name) = spec.strip_prefix("localabstract:") {
        return parse_local_socket_name(name).map(|name| {
            ServerEndpoint::from_socket_kind(ServerSocketKind::LocalAbstract { name })
        });
    }
    if let Some(name) = spec.strip_prefix("localreserved:") {
        return parse_local_socket_name(name).map(|name| {
            ServerEndpoint::from_socket_kind(ServerSocketKind::LocalReserved { name })
        });
    }
    if let Some(value) = spec.strip_prefix("acceptfd:") {
        let fd = value
            .parse::<u32>()
            .map_err(|_| AdbError::Usage("invalid fd".to_string()))?;
        return Ok(ServerEndpoint::from_socket_kind(
            ServerSocketKind::AcceptFd { fd },
        ));
    }
    if let Some(value) = spec.strip_prefix("vsock:") {
        let mut parts = value.split(':');
        let first = parse_vsock_component(parts.next().unwrap_or_default(), spec)?;
        let second = parts
            .next()
            .map(|part| parse_vsock_component(part, spec))
            .transpose()?;
        if parts.next().is_some() {
            return Err(AdbError::Usage(format!(
                "invalid vsock socket specification: {spec}"
            )));
        }
        return Ok(ServerEndpoint::from_socket_kind(ServerSocketKind::Vsock {
            first,
            second,
        }));
    }

    Err(AdbError::Server(format!(
        "unknown socket specification: {spec}"
    )))
}

fn parse_tcp_socket_spec(tcp: &str) -> Result<ServerEndpoint> {
    if tcp.is_empty() {
        return Err(AdbError::Usage(
            "invalid tcp socket specification".to_string(),
        ));
    }

    if let Ok(port) = tcp.parse::<i64>() {
        if !(0..=u16::MAX as i64).contains(&port) {
            return Err(AdbError::Usage(format!("bad port number '{port}'")));
        }
        return Ok(ServerEndpoint::from_parts(
            DEFAULT_SERVER_HOST.to_string(),
            port as u16,
            false,
        ));
    }

    let (host, port, port_explicit) = if tcp.starts_with('[') {
        let closing = tcp
            .find(']')
            .ok_or_else(|| AdbError::Usage("invalid tcp socket specification".to_string()))?;
        let host = tcp[..=closing].to_string();
        let suffix = &tcp[closing + 1..];
        if suffix.is_empty() {
            (host, DEFAULT_ADB_LOCAL_TRANSPORT_PORT, false)
        } else {
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| AdbError::Usage("invalid tcp socket specification".to_string()))?;
            (host, parse_explicit_socket_port(port)?, true)
        }
    } else if let Some((host, port)) = tcp.rsplit_once(':') {
        if host.is_empty() {
            return Err(AdbError::Usage(
                "invalid tcp socket specification".to_string(),
            ));
        }
        (host.to_string(), parse_explicit_socket_port(port)?, true)
    } else {
        (tcp.to_string(), DEFAULT_ADB_LOCAL_TRANSPORT_PORT, false)
    };

    let mut endpoint = ServerEndpoint::from_parts(host, port, true);
    endpoint.socket_port_explicit = port_explicit;
    Ok(endpoint)
}

fn parse_explicit_socket_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| AdbError::Usage(format!("invalid tcp port: {value}")))?;
    if port == 0 {
        return Err(AdbError::Usage("invalid tcp port: 0".to_string()));
    }
    Ok(port)
}

fn parse_local_socket_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(AdbError::Usage("local socket name is empty".to_string()));
    }
    if name.as_bytes().contains(&0) {
        return Err(AdbError::Usage(
            "local socket name contains NUL".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn parse_vsock_component(value: &str, spec: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| AdbError::Usage(format!("invalid vsock socket specification: {spec}")))
}

pub fn connect(endpoint: &ServerEndpoint) -> Result<ServerStream> {
    match endpoint.socket_kind() {
        ServerSocketKind::Tcp => connect_tcp(endpoint),
        ServerSocketKind::LocalFilesystem { name, .. } => connect_local_filesystem(name),
        ServerSocketKind::LocalAbstract { name } => connect_local_abstract(name),
        ServerSocketKind::LocalReserved { .. } => Err(AdbError::Server(
            "socket type localreserved is unavailable on this platform".to_string(),
        )),
        ServerSocketKind::Vsock { first, second } => connect_vsock(*first, *second),
        ServerSocketKind::AcceptFd { .. } => {
            Err(AdbError::Server("cannot connect to acceptfd".to_string()))
        }
    }
}

fn connect_tcp(endpoint: &ServerEndpoint) -> Result<ServerStream> {
    let address = endpoint.address();
    let addresses = address
        .to_socket_addrs()
        .map_err(|err| {
            AdbError::Usage(format!(
                "无法解析 server 地址 '{}': {err}",
                endpoint.address()
            ))
        })?
        .collect::<Vec<_>>();
    #[cfg(unix)]
    let mut addresses = addresses;
    #[cfg(unix)]
    if endpoint.host == DEFAULT_SERVER_HOST || endpoint.host == "127.0.0.1" {
        // Unix 上 `-L tcp:[::1]:PORT` 是合法的 IPv6-only listener，而 ADB 的默认
        // client endpoint 仍是 127.0.0.1；按 loopback 语义补一次 IPv6 fallback。
        let ipv6_loopback =
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, endpoint.port, 0, 0));
        if !addresses.contains(&ipv6_loopback) {
            addresses.push(ipv6_loopback);
        }
    }
    let mut last_error = None;
    for addr in addresses {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(ServerStream::Tcp(stream));
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .map(AdbError::Io)
        .unwrap_or_else(|| AdbError::Usage(format!("server 地址没有可连接的目标: {address}"))))
}

#[cfg(unix)]
fn connect_local_filesystem(name: &str) -> Result<ServerStream> {
    std::os::unix::net::UnixStream::connect(name)
        .map(ServerStream::Unix)
        .map_err(AdbError::Io)
}

#[cfg(not(unix))]
fn connect_local_filesystem(_name: &str) -> Result<ServerStream> {
    Err(AdbError::Server(
        "socket type localfilesystem is unavailable on this platform".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn connect_local_abstract(name: &str) -> Result<ServerStream> {
    use std::os::linux::net::SocketAddrExt;

    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    std::os::unix::net::UnixStream::connect_addr(&address)
        .map(ServerStream::Unix)
        .map_err(AdbError::Io)
}

#[cfg(not(target_os = "linux"))]
fn connect_local_abstract(_name: &str) -> Result<ServerStream> {
    Err(AdbError::Server(
        "socket type localabstract is unavailable on this platform".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn connect_vsock(cid: u32, port: Option<u32>) -> Result<ServerStream> {
    use std::os::fd::FromRawFd;

    let port = port.ok_or_else(|| AdbError::Server("vsock port was not provided.".to_string()))?;
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(AdbError::Io(io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let address = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };
    let result = unsafe {
        libc::connect(
            file.as_raw_fd(),
            (&address as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(AdbError::Io(io::Error::last_os_error()));
    }
    Ok(ServerStream::from_raw_file(file))
}

#[cfg(not(target_os = "linux"))]
fn connect_vsock(_cid: u32, _port: Option<u32>) -> Result<ServerStream> {
    Err(AdbError::Server(
        "vsock is only supported on Linux".to_string(),
    ))
}

pub fn query(endpoint: &ServerEndpoint, service: &str) -> Result<String> {
    let bytes = query_bytes(endpoint, service)?;
    String::from_utf8(bytes).map_err(|err| AdbError::Protocol(format!("非 UTF-8 响应: {err}")))
}

pub fn query_bytes(endpoint: &ServerEndpoint, service: &str) -> Result<Vec<u8>> {
    let mut stream = connect(endpoint)?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)?;
    protocol::read_protocol_bytes(&mut stream)
}

pub fn request_ok(endpoint: &ServerEndpoint, service: &str) -> Result<()> {
    let mut stream = connect(endpoint)?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)
}

/// 按 AOSP `adb_kill_server` 语义等待 daemon 关闭 smart socket。
pub fn kill_server(endpoint: &ServerEndpoint) -> Result<()> {
    let mut stream = connect(endpoint)?;
    protocol::write_protocol_string(&mut stream, "host:kill")?;
    protocol::read_status(&mut stream)?;

    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Ok(_) => {
            return Err(AdbError::Protocol(
                "server sent unexpected data after host:kill".to_string(),
            ));
        }
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::NotConnected
            ) => {}
        Err(err) => return Err(err.into()),
    }
    wait_for_server_shutdown(endpoint)
}

pub fn open_host_service(endpoint: &ServerEndpoint, service: &str) -> Result<ServerStream> {
    let mut stream = connect(endpoint)?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)?;
    Ok(stream)
}

pub fn stream_host_service_to_stdout(endpoint: &ServerEndpoint, service: &str) -> Result<()> {
    let stream = open_host_service(endpoint, service)?;
    stream_to_stdout(stream)
}

pub fn request_forward_status(endpoint: &ServerEndpoint, service: &str) -> Result<Option<String>> {
    let mut stream = connect(endpoint)?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)?;
    protocol::read_status(&mut stream)?;
    read_optional_protocol_string(&mut stream)
}

pub fn switch_transport_with_id(
    stream: &mut ServerStream,
    selector: &TransportSelector,
) -> Result<Option<u64>> {
    match selector {
        TransportSelector::TransportId(id) => {
            protocol::write_protocol_string(stream, &selector.transport_service())?;
            protocol::read_status(stream)?;
            Ok(Some(*id))
        }
        _ => {
            protocol::write_protocol_string(stream, &selector.tport_service())?;
            protocol::read_status(stream)?;
            let mut raw = [0_u8; 8];
            stream.read_exact(&mut raw)?;
            Ok(Some(u64::from_le_bytes(raw)))
        }
    }
}

pub fn open_host_service_with_transport_id(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<(ServerStream, u64)> {
    let mut stream = connect(endpoint)?;
    let transport_id = switch_transport_with_id(&mut stream, selector)?
        .ok_or_else(|| AdbError::Protocol("server did not return a transport id".to_string()))?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)?;
    Ok((stream, transport_id))
}

pub fn query_host_service_with_transport(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<String> {
    let (mut stream, _) = open_host_service_with_transport_id(endpoint, selector, service)?;
    protocol::read_protocol_string(&mut stream)
}

pub fn query_device_service(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<String> {
    let mut stream = open_device_service(endpoint, selector, service)?;
    protocol::read_protocol_string(&mut stream)
}

pub fn request_device_service_status(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<Option<String>> {
    let mut stream = open_device_service(endpoint, selector, service)?;
    protocol::read_status(&mut stream)?;
    read_optional_protocol_string(&mut stream)
}

fn read_optional_protocol_string(stream: &mut ServerStream) -> Result<Option<String>> {
    match protocol::read_protocol_string(stream) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(AdbError::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn open_device_service(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<ServerStream> {
    let mut stream = connect(endpoint)?;
    let _ = switch_transport_with_id(&mut stream, selector)?;
    protocol::write_protocol_string(&mut stream, service)?;
    protocol::read_status(&mut stream)?;
    Ok(stream)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// 执行一次非交互 shell 命令，优先使用 shell v2，并为旧设备保留退出码回退。
pub fn run_shell_command_capture(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    command: &str,
) -> Result<ShellCommandOutput> {
    let v2_service = format!("shell,v2,raw:{command}");
    match open_device_service(endpoint, selector, &v2_service) {
        Ok(stream) => {
            let output = stream_shell_v2_to_buffers(stream)?;
            Ok(ShellCommandOutput {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code: i32::from(output.exit_code),
            })
        }
        Err(_) => run_shell_command_capture_legacy(endpoint, selector, command),
    }
}

pub(crate) fn run_shell_command_capture_legacy(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    command: &str,
) -> Result<ShellCommandOutput> {
    let legacy_command = wrap_legacy_shell_command(command);
    let stream = open_device_service(endpoint, selector, &format!("shell:{legacy_command}"))?;
    let mut stdout = read_stream_to_bytes(stream)?;
    let exit_code = parse_legacy_shell_exit_code(&mut stdout);
    Ok(ShellCommandOutput {
        stdout,
        stderr: Vec::new(),
        exit_code,
    })
}

pub(crate) fn wrap_legacy_shell_command(command: &str) -> String {
    if command.is_empty() {
        "echo \"\n$?: $?\"".to_string()
    } else {
        format!("{command}; echo \"\n$?: $?\"")
    }
}

pub(crate) fn parse_legacy_shell_exit_code(output: &mut Vec<u8>) -> i32 {
    let marker = b"$?: ";
    let Some(marker_pos) = output
        .windows(marker.len())
        .rposition(|window| window == marker)
    else {
        return 0;
    };

    let code_start = marker_pos + marker.len();
    let mut code_end = code_start;
    while code_end < output.len() && output[code_end].is_ascii_digit() {
        code_end += 1;
    }
    if code_start == code_end {
        return 0;
    }

    let code = String::from_utf8_lossy(&output[code_start..code_end])
        .parse::<i32>()
        .unwrap_or(0);
    let truncate_pos = output[..marker_pos]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap_or(0);
    output.truncate(truncate_pos);
    code
}

pub fn stream_device_service_to_stdout(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
) -> Result<()> {
    let stream = open_device_service(endpoint, selector, service)?;
    stream_to_stdout(stream)
}

pub fn server_version(endpoint: &ServerEndpoint) -> Result<u32> {
    let version = query(endpoint, "host:version")?;
    u32::from_str_radix(version.trim(), 16)
        .map_err(|err| AdbError::Protocol(format!("无法解析 server 版本 {version:?}: {err}")))
}

pub fn ensure_server_running(endpoint: &ServerEndpoint) -> Result<bool> {
    ensure_server_running_with_one_device(endpoint, None)
}

pub fn ensure_server_running_with_one_device(
    endpoint: &ServerEndpoint,
    one_device: Option<&str>,
) -> Result<bool> {
    match server_version(endpoint) {
        Ok(version) if version == protocol::ADB_SERVER_VERSION => return Ok(false),
        Ok(version) => {
            #[cfg(target_os = "linux")]
            if version > protocol::ADB_SERVER_VERSION && endpoint.is_localhost() {
                try_reexec_newer_server(endpoint);
            }
            eprintln!(
                "adb server version ({version}) doesn't match this client ({}); killing...",
                protocol::ADB_SERVER_VERSION
            );
            request_ok(endpoint, "host:kill")?;
            wait_for_server_shutdown(endpoint)?;
        }
        // AOSP 对不支持 `host:version` 的旧 server 仍会继续 kill/restart；
        // 其他 FAIL（以及已建立连接后的 EOF/协议损坏）必须原样返回。
        Err(AdbError::Server(reason)) if is_unknown_host_service(&reason) => {
            request_ok(endpoint, "host:kill")?;
            wait_for_server_shutdown(endpoint)?;
        }
        // 只有 socket 连接本身不存在时才允许自动拉起本地 server。
        Err(AdbError::Io(err)) if server_connection_unavailable(&err) => {}
        Err(err) => return Err(err),
    }

    if !endpoint.is_localhost() {
        return Err(AdbError::Server(format!(
            "cannot connect to daemon at {}",
            endpoint.address()
        )));
    }

    spawn_server(endpoint, one_device)?;

    Ok(true)
}

#[cfg(target_os = "linux")]
pub(crate) fn server_executable_marker_path(endpoint: &ServerEndpoint) -> Result<Option<PathBuf>> {
    if !matches!(endpoint.socket_kind(), ServerSocketKind::Tcp) {
        return Ok(None);
    }
    Ok(Some(
        crate::auth::android_dir()?.join(format!("adb.{}", endpoint.port)),
    ))
}

#[cfg(target_os = "linux")]
fn try_reexec_newer_server(endpoint: &ServerEndpoint) {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if std::env::args_os().next().as_deref() == Some(std::ffi::OsStr::new(SERVER_REEXEC_ARG0)) {
        return;
    }
    let Ok(Some(marker_path)) = server_executable_marker_path(endpoint) else {
        return;
    };
    let Ok(server_path) = std::fs::read(marker_path) else {
        return;
    };
    if server_path.is_empty() {
        return;
    }

    let server_path = std::ffi::OsString::from_vec(server_path);
    let mut command = Command::new(&server_path);
    command
        .arg0(SERVER_REEXEC_ARG0)
        .args(std::env::args_os().skip(1));
    let err = command.exec();
    eprintln!(
        "adb: failed to exec newer version at {}: {err}",
        Path::new(&server_path).display()
    );
}

fn is_unknown_host_service(reason: &str) -> bool {
    reason == "unknown host service" || reason.starts_with("unknown host service:")
}

fn server_connection_unavailable(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotFound
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::TimedOut
    )
}

fn wait_for_server_shutdown(endpoint: &ServerEndpoint) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if connect(endpoint).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(AdbError::Server("adb server did not shut down".to_string()))
}

pub fn spawn_server(endpoint: &ServerEndpoint, one_device: Option<&str>) -> Result<()> {
    #[cfg(unix)]
    return spawn_server_unix(endpoint, one_device);
    #[cfg(windows)]
    return spawn_server_windows(endpoint, one_device);
    #[cfg(not(any(unix, windows)))]
    return Err(AdbError::Unsupported(
        "spawn_server 仅支持 Unix/Windows 平台".to_string(),
    ));
}

fn server_launch_args(
    endpoint: &ServerEndpoint,
    reply_fd: impl ToString,
    one_device: Option<&str>,
) -> Vec<String> {
    let mut args = vec!["-L".to_string(), endpoint.socket_spec()];
    if endpoint.listen_all() {
        args.push("-a".to_string());
    }
    args.extend([
        "fork-server".to_string(),
        "server".to_string(),
        "--reply-fd".to_string(),
        reply_fd.to_string(),
    ]);
    if let Some(one_device) = one_device {
        args.push("--one-device".to_string());
        args.push(one_device.to_string());
    }
    args
}

#[derive(Debug, Clone, Copy)]
enum ChildOutputTarget {
    Stdout,
    Stderr,
}

fn spawn_child_output_relay(mut reader: File, target: ChildOutputTarget) -> thread::JoinHandle<()> {
    thread::spawn(move || match target {
        ChildOutputTarget::Stdout => {
            let mut stdout = io::stdout().lock();
            let _ = io::copy(&mut reader, &mut stdout);
            let _ = stdout.flush();
        }
        ChildOutputTarget::Stderr => {
            let mut stderr = io::stderr().lock();
            let _ = io::copy(&mut reader, &mut stderr);
            let _ = stderr.flush();
        }
    })
}

fn finish_child_output_relays(handles: Vec<thread::JoinHandle<()>>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while handles.iter().any(|handle| !handle.is_finished()) && std::time::Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    for handle in handles {
        if handle.is_finished() {
            let _ = handle.join();
        }
    }
}

#[cfg(unix)]
fn spawn_server_unix(endpoint: &ServerEndpoint, one_device: Option<&str>) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};

    let (ack_read, ack_write) = create_unix_pipe(true, false)?;
    let (stdout_read, stdout_write) = create_unix_pipe(true, true)?;
    let (stderr_read, stderr_write) = create_unix_pipe(true, true)?;
    let args = server_launch_args(endpoint, ack_write.as_raw_fd(), one_device);

    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_write))
        .stderr(Stdio::from(stderr_write));

    let child = command.spawn()?;
    drop(command);
    drop(child);
    drop(ack_write);

    let relays = vec![
        spawn_child_output_relay(stdout_read, ChildOutputTarget::Stdout),
        spawn_child_output_relay(stderr_read, ChildOutputTarget::Stderr),
    ];
    let result = read_ack_from_pipe(ack_read);
    finish_child_output_relays(relays);
    result
}

#[cfg(unix)]
fn create_unix_pipe(read_cloexec: bool, write_cloexec: bool) -> Result<(File, File)> {
    use std::os::fd::FromRawFd;

    let mut pipe_fds = [-1_i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(AdbError::Io(io::Error::last_os_error()));
    }

    let read = unsafe { File::from_raw_fd(pipe_fds[0]) };
    let write = unsafe { File::from_raw_fd(pipe_fds[1]) };
    set_unix_cloexec(&read, read_cloexec)?;
    set_unix_cloexec(&write, write_cloexec)?;
    Ok((read, write))
}

#[cfg(unix)]
fn set_unix_cloexec(file: &File, enabled: bool) -> Result<()> {
    use std::os::fd::AsRawFd;

    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(AdbError::Io(io::Error::last_os_error()));
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } != 0 {
        return Err(AdbError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
fn spawn_server_windows(endpoint: &ServerEndpoint, one_device: Option<&str>) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    unsafe {
        let (ack_read, ack_write) = create_windows_pipe()?;
        let (stdout_read, stdout_write) = create_windows_pipe()?;
        let (stderr_read, stderr_write) = create_windows_pipe()?;
        let nul_input = create_windows_null_input()?;

        let reply_handle = ack_write.as_raw_handle() as usize;
        let reply_handle_u32 = u32::try_from(reply_handle).map_err(|_| {
            AdbError::Server(format!(
                "cannot fit pipe handle value into 32-bits: 0x{reply_handle:x}"
            ))
        })?;
        let args = server_launch_args(endpoint, reply_handle_u32, one_device);

        // 父进程 stdout/stderr 不可继承，避免 shell 等待子进程继承的句柄
        let stdin = GetStdHandle(STD_INPUT_HANDLE);
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        let stderr = GetStdHandle(STD_ERROR_HANDLE);
        if !stdin.is_null() && stdin != INVALID_HANDLE_VALUE {
            SetHandleInformation(stdin, HANDLE_FLAG_INHERIT, 0);
        }
        if !stdout.is_null() && stdout != INVALID_HANDLE_VALUE {
            SetHandleInformation(stdout, HANDLE_FLAG_INHERIT, 0);
        }
        if !stderr.is_null() && stderr != INVALID_HANDLE_VALUE {
            SetHandleInformation(stderr, HANDLE_FLAG_INHERIT, 0);
        }

        let exe = std::env::current_exe()?;
        let exe_wide: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let command_line = windows_server_command_line(&args);
        let mut cmd_wide: Vec<u16> = std::ffi::OsStr::new(&command_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = nul_input.as_raw_handle() as HANDLE;
        si.hStdOutput = stdout_write.as_raw_handle() as HANDLE;
        si.hStdError = stderr_write.as_raw_handle() as HANDLE;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let result = CreateProcessW(
            exe_wide.as_ptr(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1, // bInheritHandles
            DETACHED_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &si,
            &mut pi,
        );

        if result == 0 {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        drop(nul_input);
        drop(ack_write);
        drop(stdout_write);
        drop(stderr_write);

        let relays = vec![
            spawn_child_output_relay(stdout_read, ChildOutputTarget::Stdout),
            spawn_child_output_relay(stderr_read, ChildOutputTarget::Stderr),
        ];
        let result = read_ack_from_pipe(ack_read);
        finish_child_output_relays(relays);
        result
    }
}

#[cfg(windows)]
fn create_windows_pipe() -> Result<(File, File)> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    unsafe {
        let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 1;
        sa.lpSecurityDescriptor = std::ptr::null_mut();

        let mut read_handle: HANDLE = std::ptr::null_mut();
        let mut write_handle: HANDLE = std::ptr::null_mut();
        if CreatePipe(&mut read_handle, &mut write_handle, &sa, 0) == 0 {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
        if SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0) == 0 {
            let err = io::Error::last_os_error();
            CloseHandle(read_handle);
            CloseHandle(write_handle);
            return Err(AdbError::Io(err));
        }

        Ok((
            File::from_raw_handle(read_handle),
            File::from_raw_handle(write_handle),
        ))
    }
}

#[cfg(windows)]
fn create_windows_null_input() -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    unsafe {
        let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 1;
        sa.lpSecurityDescriptor = std::ptr::null_mut();
        let path: Vec<u16> = std::ffi::OsStr::new("NUL")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle: HANDLE = CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
        Ok(File::from_raw_handle(handle))
    }
}

#[cfg(windows)]
fn windows_server_command_line(args: &[String]) -> String {
    std::iter::once("adb".to_string())
        .chain(args.iter().map(|arg| quote_windows_arg(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(windows)]
fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|ch| ch.is_whitespace() || ch == '"') {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(ch);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn read_ack_from_pipe(mut file: impl Read) -> Result<()> {
    let mut buffer = [0_u8; 4];
    let mut total = 0;
    while total < 3 {
        match file.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) => return Err(AdbError::Io(err)),
        }
    }
    if &buffer[..total] == b"OK\n" {
        Ok(())
    } else {
        Err(AdbError::Server(
            "daemon did not report startup OK".to_string(),
        ))
    }
}

pub fn stream_to_stdio(mut stream: ServerStream, interactive: bool) -> Result<()> {
    if interactive {
        let mut stdin_writer = stream.try_clone()?;
        thread::spawn(move || {
            let _ = io::copy(&mut io::stdin().lock(), &mut stdin_writer);
            let _ = stdin_writer.shutdown(Shutdown::Write);
        });
    }

    copy_stream_to_writer(&mut stream, &mut io::stdout().lock())
}

pub fn stream_legacy_shell_interactive(
    mut stream: ServerStream,
    raw_stdin: bool,
    escape_char: Option<u8>,
    exit_on_write_error: bool,
) -> Result<()> {
    let mut stdin_writer = stream.try_clone()?;
    let escape_disconnected = Arc::new(AtomicBool::new(false));
    let stdin_disconnected = Arc::clone(&escape_disconnected);
    thread::spawn(move || {
        let outcome = copy_process_legacy_shell_stdin(&mut stdin_writer, raw_stdin, escape_char);

        if matches!(outcome, Ok(RawStdinOutcome::Disconnect)) {
            trace_shell_stdin("legacy escape disconnect requested");
            let _ = disconnect_shell(&stdin_writer, &stdin_disconnected);
        } else if let Err(err) = outcome {
            trace_shell_stdin(&format!("legacy stdin failed: {err}"));
        }
        // AOSP 对 legacy shell 的 stdin EOF 不做 half-close，避免设备剩余输出被截断。
    });

    let result =
        copy_legacy_shell_output(&mut stream, &mut io::stdout().lock(), exit_on_write_error);
    if escape_disconnected.load(Ordering::Acquire) {
        Ok(())
    } else {
        result
    }
}

pub fn stream_legacy_shell_to_stdout(
    mut stream: ServerStream,
    exit_on_write_error: bool,
) -> Result<()> {
    copy_legacy_shell_output(&mut stream, &mut io::stdout().lock(), exit_on_write_error)
}

pub fn stream_to_stdout(mut stream: ServerStream) -> Result<()> {
    copy_stream_to_writer(&mut stream, &mut io::stdout().lock())
}

pub fn stream_stdin_to_service(mut stream: ServerStream, raw_stdin: bool) -> Result<()> {
    #[cfg(windows)]
    if raw_stdin {
        let mut stdin = WindowsConsoleInput::open()?;
        io::copy(&mut stdin, &mut stream)?;
        let _ = stream.shutdown(Shutdown::Write);
        return Ok(());
    }

    #[cfg(not(windows))]
    let _ = raw_stdin;

    io::copy(&mut io::stdin().lock(), &mut stream)?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

fn copy_stream_to_writer<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            writer.flush()?;
            return Ok(());
        }
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
    }
}

fn copy_legacy_shell_output<R, W>(
    reader: &mut R,
    writer: &mut W,
    exit_on_write_error: bool,
) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            let _ = writer.flush();
            return Ok(());
        }
        if (writer.write_all(&buffer[..read]).is_err() || writer.flush().is_err())
            && exit_on_write_error
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
fn stream_to_writer_with_input<R, W>(
    mut stream: ServerStream,
    mut input: R,
    writer: &mut W,
) -> Result<()>
where
    R: Read + Send + 'static,
    W: Write,
{
    let mut stdin_writer = stream.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut input, &mut stdin_writer);
        let _ = stdin_writer.shutdown(Shutdown::Write);
    });

    copy_stream_to_writer(&mut stream, writer)
}

pub fn read_stream_to_bytes(mut stream: ServerStream) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    stream.read_to_end(&mut output)?;
    Ok(output)
}

pub fn write_file_to_device_service(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    service: &str,
    local: &Path,
) -> Result<Vec<u8>> {
    let mut stream = open_device_service(endpoint, selector, service)?;
    let mut file = File::open(local)?;
    copy_file_to_sized_service(&mut file, &mut stream)
}

fn copy_file_to_sized_service<R, S>(file: &mut R, stream: &mut S) -> Result<Vec<u8>>
where
    R: Read,
    S: Read + Write,
{
    // install 的 `-S` 已声明输入长度；AOSP copy_to_file 后直接读取同一 fd，不能
    // half-close，否则 server 会把本地 EOF 翻译为 A_CLSE 并截断最终状态行。
    io::copy(file, &mut *stream)?;
    let mut output = Vec::new();
    stream.read_to_end(&mut output)?;
    Ok(output)
}

pub fn stream_shell_v2_to_stdio(mut stream: ServerStream, exit_on_write_error: bool) -> Result<u8> {
    write_shell_packet(&mut stream, SHELL_ID_CLOSE_STDIN, &[])?;

    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    read_shell_v2(&mut stream, &mut stdout, &mut stderr, exit_on_write_error)
}

pub fn stream_shell_v2_interactive(
    mut stream: ServerStream,
    options: ShellV2InteractiveOptions,
) -> Result<u8> {
    let disconnect_stream = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut last_window_size = None;
    if let Some(size) = options.initial_window_size {
        write_shared_shell_packet(
            &writer,
            SHELL_ID_WINDOW_SIZE_CHANGE,
            &shell_window_size_payload(size),
        )?;
        last_window_size = Some(size);
    }

    let running = Arc::new(AtomicBool::new(true));
    let escape_disconnected = Arc::new(AtomicBool::new(false));
    if options.watch_window_size {
        let resize_writer = Arc::clone(&writer);
        let resize_running = Arc::clone(&running);
        thread::spawn(move || {
            watch_shell_window_size(resize_writer, last_window_size, resize_running);
        });
    }

    if options.close_stdin {
        write_shared_shell_packet(&writer, SHELL_ID_CLOSE_STDIN, &[])?;
    } else {
        let stdin_writer = Arc::clone(&writer);
        let stdin_disconnected = Arc::clone(&escape_disconnected);
        thread::spawn(move || {
            if let Err(err) = write_stdin_to_shell_v2(
                stdin_writer,
                disconnect_stream,
                options,
                stdin_disconnected,
            ) {
                trace_shell_stdin(&format!("shell v2 stdin failed: {err}"));
            }
        });
    }

    // stdin 线程的紧急断开提示也写 stderr，不能在整个阻塞读取期间独占标准流锁。
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let result = read_shell_v2(
        &mut stream,
        &mut stdout,
        &mut stderr,
        options.exit_on_write_error,
    );
    running.store(false, Ordering::Release);
    if escape_disconnected.load(Ordering::Acquire) {
        Ok(0)
    } else {
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellV2Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellV2InteractiveOptions {
    pub close_stdin: bool,
    pub raw_stdin: bool,
    pub escape_char: Option<u8>,
    pub initial_window_size: Option<ShellWindowSize>,
    pub watch_window_size: bool,
    pub exit_on_write_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellWindowSize {
    pub rows: u16,
    pub cols: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

pub fn current_shell_window_size() -> Option<ShellWindowSize> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    if cols == 0 || rows == 0 {
        return None;
    }
    Some(ShellWindowSize {
        rows,
        cols,
        x_pixels: 0,
        y_pixels: 0,
    })
}

pub fn stream_shell_v2_to_buffers(mut stream: ServerStream) -> Result<ShellV2Output> {
    write_shell_packet(&mut stream, SHELL_ID_CLOSE_STDIN, &[])?;

    read_shell_v2_to_buffers_after_stdin(stream)
}

pub fn close_shell_v2_stdin(stream: &mut ServerStream) -> Result<()> {
    write_shell_packet(stream, SHELL_ID_CLOSE_STDIN, &[])
}

pub fn write_shell_v2_stdin_data(stream: &mut ServerStream, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(64 * 1024) {
        write_shell_packet(stream, SHELL_ID_STDIN, chunk)?;
    }
    Ok(())
}

/// 在调用方已经发送完 stdin packet 后读取 shell v2 输出。
pub fn read_shell_v2_to_buffers_after_stdin(mut stream: ServerStream) -> Result<ShellV2Output> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code = read_shell_v2(&mut stream, &mut stdout, &mut stderr, false)?;
    Ok(ShellV2Output {
        stdout,
        stderr,
        exit_code,
    })
}

const SHELL_ID_STDIN: u8 = 0;
const SHELL_ID_STDOUT: u8 = 1;
const SHELL_ID_STDERR: u8 = 2;
const SHELL_ID_EXIT: u8 = 3;
const SHELL_ID_CLOSE_STDIN: u8 = 4;
const SHELL_ID_WINDOW_SIZE_CHANGE: u8 = 5;
const SHELL_WINDOW_SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);

type SharedShellWriter = Arc<Mutex<ServerStream>>;

fn write_stdin_to_shell_v2(
    writer: SharedShellWriter,
    disconnect_stream: ServerStream,
    options: ShellV2InteractiveOptions,
    escape_disconnected: Arc<AtomicBool>,
) -> Result<()> {
    #[cfg(windows)]
    if options.raw_stdin {
        let mut stdin = WindowsConsoleInput::open()?;
        return write_reader_to_shell_v2(
            &writer,
            &disconnect_stream,
            &mut stdin,
            options,
            &escape_disconnected,
        );
    }

    let mut stdin = io::stdin().lock();
    write_reader_to_shell_v2(
        &writer,
        &disconnect_stream,
        &mut stdin,
        options,
        &escape_disconnected,
    )
}

fn write_reader_to_shell_v2<R: Read>(
    writer: &SharedShellWriter,
    disconnect_stream: &ServerStream,
    reader: &mut R,
    options: ShellV2InteractiveOptions,
    escape_disconnected: &AtomicBool,
) -> Result<()> {
    if options.raw_stdin
        && let Some(escape_char) = options.escape_char
    {
        let outcome = write_raw_stdin_with_escape_packets(
            |packet_id, payload| write_shared_shell_packet(writer, packet_id, payload),
            reader,
            escape_char,
        )?;
        if outcome == RawStdinOutcome::Disconnect {
            trace_shell_stdin("shell v2 escape disconnect requested");
            disconnect_shell(disconnect_stream, escape_disconnected)?;
        }
        return Ok(());
    }

    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            write_shared_shell_packet(writer, SHELL_ID_CLOSE_STDIN, &[])?;
            return Ok(());
        }
        write_shared_shell_packet(writer, SHELL_ID_STDIN, &buffer[..read])?;
    }
}

fn copy_process_legacy_shell_stdin<W: Write>(
    writer: &mut W,
    raw_stdin: bool,
    escape_char: Option<u8>,
) -> Result<RawStdinOutcome> {
    #[cfg(windows)]
    if raw_stdin {
        let mut stdin = WindowsConsoleInput::open()?;
        return copy_legacy_shell_stdin(writer, &mut stdin, true, escape_char);
    }

    let mut stdin = io::stdin().lock();
    copy_legacy_shell_stdin(writer, &mut stdin, raw_stdin, escape_char)
}

#[cfg(test)]
fn write_raw_stdin_with_escape<W, R>(
    writer: &mut W,
    reader: &mut R,
    escape_char: u8,
) -> Result<RawStdinOutcome>
where
    W: Write,
    R: Read,
{
    write_raw_stdin_with_escape_packets(
        |packet_id, payload| write_shell_packet(writer, packet_id, payload),
        reader,
        escape_char,
    )
}

fn write_raw_stdin_with_escape_packets<F, R>(
    mut write_packet: F,
    reader: &mut R,
    escape_char: u8,
) -> Result<RawStdinOutcome>
where
    F: FnMut(u8, &[u8]) -> Result<()>,
    R: Read,
{
    let outcome = copy_raw_stdin_with_escape(
        |payload| write_packet(SHELL_ID_STDIN, payload),
        reader,
        escape_char,
    )?;
    if outcome == RawStdinOutcome::Eof {
        write_packet(SHELL_ID_CLOSE_STDIN, &[])?;
    }
    Ok(outcome)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawStdinOutcome {
    Eof,
    Disconnect,
}

fn copy_raw_stdin_with_escape<F, R>(
    mut write_data: F,
    reader: &mut R,
    escape_char: u8,
) -> Result<RawStdinOutcome>
where
    F: FnMut(&[u8]) -> Result<()>,
    R: Read,
{
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum EscapeState {
        StartOfLine,
        MidFlow,
        InEscape,
    }

    let mut state = EscapeState::StartOfLine;
    let mut byte = [0_u8; 1];
    loop {
        if reader.read(&mut byte)? == 0 {
            return Ok(RawStdinOutcome::Eof);
        }

        let ch = byte[0];
        if ch == escape_char {
            if state == EscapeState::StartOfLine {
                state = EscapeState::InEscape;
                continue;
            }
            state = EscapeState::MidFlow;
            write_data(&[ch])?;
            continue;
        }

        if state == EscapeState::InEscape {
            if ch == b'.' {
                return Ok(RawStdinOutcome::Disconnect);
            }
            write_data(&[escape_char, ch])?;
        } else {
            write_data(&[ch])?;
        }

        state = if ch == b'\n' || ch == b'\r' {
            EscapeState::StartOfLine
        } else {
            EscapeState::MidFlow
        };
    }
}

fn copy_legacy_shell_stdin<W, R>(
    writer: &mut W,
    reader: &mut R,
    raw_stdin: bool,
    escape_char: Option<u8>,
) -> Result<RawStdinOutcome>
where
    W: Write,
    R: Read,
{
    if raw_stdin && let Some(escape_char) = escape_char {
        copy_raw_stdin_with_escape(
            |payload| writer.write_all(payload).map_err(Into::into),
            reader,
            escape_char,
        )
    } else {
        io::copy(reader, writer)
            .map(|_| RawStdinOutcome::Eof)
            .map_err(Into::into)
    }
}

fn report_shell_disconnect() {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"\r\n[ disconnected ]\r\n");
    let _ = stderr.flush();
}

fn trace_shell_stdin(message: &str) {
    if crate::transport::trace_enabled("shell") {
        eprintln!("adb: shell stdin: {message}");
    }
}

fn disconnect_shell(stream: &ServerStream, disconnected: &AtomicBool) -> Result<()> {
    report_shell_disconnect();
    disconnected.store(true, Ordering::Release);
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn watch_shell_window_size(
    writer: SharedShellWriter,
    mut last_size: Option<ShellWindowSize>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::Acquire) {
        thread::sleep(SHELL_WINDOW_SIZE_POLL_INTERVAL);
        if write_window_size_change_if_needed(
            |packet_id, payload| write_shared_shell_packet(&writer, packet_id, payload),
            &mut last_size,
            current_shell_window_size(),
        )
        .is_err()
        {
            break;
        }
    }
}

fn write_window_size_change_if_needed<F>(
    mut write_packet: F,
    last_size: &mut Option<ShellWindowSize>,
    current_size: Option<ShellWindowSize>,
) -> Result<()>
where
    F: FnMut(u8, &[u8]) -> Result<()>,
{
    let Some(size) = current_size else {
        return Ok(());
    };
    if *last_size == Some(size) {
        return Ok(());
    }

    write_packet(
        SHELL_ID_WINDOW_SIZE_CHANGE,
        &shell_window_size_payload(size),
    )?;
    *last_size = Some(size);
    Ok(())
}

fn shell_window_size_payload(size: ShellWindowSize) -> Vec<u8> {
    format!(
        "{}x{},{}x{}\0",
        size.rows, size.cols, size.x_pixels, size.y_pixels
    )
    .into_bytes()
}

fn read_shell_v2<R, O, E>(
    reader: &mut R,
    stdout: &mut O,
    stderr: &mut E,
    exit_on_write_error: bool,
) -> Result<u8>
where
    R: Read,
    O: Write,
    E: Write,
{
    let mut exit_code = 255_u8;

    while let Some((packet_id, payload)) = read_shell_packet(reader)? {
        match packet_id {
            SHELL_ID_STDOUT => {
                if !write_shell_output(stdout, &payload, exit_on_write_error) {
                    return Ok(128 + 13);
                }
            }
            SHELL_ID_STDERR => {
                if !write_shell_output(stderr, &payload, exit_on_write_error) {
                    return Ok(128 + 13);
                }
            }
            SHELL_ID_EXIT => {
                if let Some(code) = payload.first() {
                    exit_code = *code;
                }
            }
            other => {
                return Err(AdbError::Protocol(format!(
                    "未知 shell v2 packet id: {other}"
                )));
            }
        }
    }

    let _ = stdout.flush();
    let _ = stderr.flush();
    Ok(exit_code)
}

fn write_shell_output<W: Write>(writer: &mut W, payload: &[u8], return_errors: bool) -> bool {
    let okay = writer
        .write_all(payload)
        .and_then(|()| writer.flush())
        .is_ok();
    !return_errors || okay
}

fn read_shell_packet<R: Read>(reader: &mut R) -> Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0_u8; 5];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if payload_len > protocol::MAX_PAYLOAD {
        return Err(AdbError::Protocol(format!(
            "shell v2 payload 过大: {payload_len} > {}",
            protocol::MAX_PAYLOAD
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload)?;
    Ok(Some((header[0], payload)))
}

fn write_shell_packet<W: Write>(writer: &mut W, packet_id: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > protocol::MAX_PAYLOAD {
        return Err(AdbError::Protocol(format!(
            "shell v2 payload 过大: {} > {}",
            payload.len(),
            protocol::MAX_PAYLOAD
        )));
    }

    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(packet_id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

fn write_shared_shell_packet(
    writer: &SharedShellWriter,
    packet_id: u8,
    payload: &[u8],
) -> Result<()> {
    let mut writer = writer
        .lock()
        .map_err(|_| AdbError::Protocol("shell v2 写入锁已中毒".to_string()))?;
    write_shell_packet(&mut *writer, packet_id, payload)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, ErrorKind};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    use super::*;

    #[test]
    fn old_server_version_service_errors_are_restartable_but_other_failures_are_not() {
        assert!(is_unknown_host_service("unknown host service"));
        assert!(is_unknown_host_service(
            "unknown host service: host:version"
        ));
        assert!(!is_unknown_host_service("permission denied"));
        assert!(!is_unknown_host_service("cannot connect"));
    }

    #[test]
    fn server_connection_unavailable_only_accepts_socket_startup_errors() {
        assert!(server_connection_unavailable(&Error::from(
            ErrorKind::ConnectionRefused
        )));
        assert!(server_connection_unavailable(&Error::from(
            ErrorKind::NotFound
        )));
        assert!(!server_connection_unavailable(&Error::from(
            ErrorKind::InvalidData
        )));
    }

    fn shell_packet(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5 + payload.len());
        packet.push(id);
        packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(Error::new(ErrorKind::BrokenPipe, "测试写入失败"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(Error::new(ErrorKind::BrokenPipe, "测试刷新失败"))
        }
    }

    #[test]
    fn shell_v2_splits_stdout_stderr_and_exit_code() {
        let mut wire = Vec::new();
        wire.extend(shell_packet(SHELL_ID_STDOUT, b"out\n"));
        wire.extend(shell_packet(SHELL_ID_STDERR, b"err\n"));
        wire.extend(shell_packet(SHELL_ID_EXIT, &[7]));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = read_shell_v2(&mut Cursor::new(wire), &mut stdout, &mut stderr, false).unwrap();

        assert_eq!(stdout, b"out\n");
        assert_eq!(stderr, b"err\n");
        assert_eq!(code, 7);
    }

    #[test]
    fn shell_v2_defaults_to_255_without_exit_packet() {
        let mut wire = Vec::new();
        wire.extend(shell_packet(SHELL_ID_STDOUT, b"partial\n"));

        let code = read_shell_v2(
            &mut Cursor::new(wire),
            &mut Vec::new(),
            &mut Vec::new(),
            false,
        )
        .unwrap();

        assert_eq!(code, 255);
    }

    #[test]
    fn shell_v2_default_ignores_output_errors_and_keeps_device_exit_code() {
        let mut wire = Vec::new();
        wire.extend(shell_packet(SHELL_ID_STDOUT, b"out\n"));
        wire.extend(shell_packet(SHELL_ID_EXIT, &[7]));
        let mut reader = Cursor::new(wire);

        let code = read_shell_v2(&mut reader, &mut FailingWriter, &mut Vec::new(), false).unwrap();

        assert_eq!(code, 7);
        assert_eq!(reader.position(), reader.get_ref().len() as u64);
    }

    #[test]
    fn shell_v2_exit_on_write_error_returns_sigpipe_status() {
        let mut wire = Vec::new();
        let first_packet = shell_packet(SHELL_ID_STDOUT, b"out\n");
        wire.extend(&first_packet);
        wire.extend(shell_packet(SHELL_ID_EXIT, &[7]));
        let mut reader = Cursor::new(wire);

        let code = read_shell_v2(&mut reader, &mut FailingWriter, &mut Vec::new(), true).unwrap();

        assert_eq!(code, 128 + 13);
        assert_eq!(reader.position(), first_packet.len() as u64);
    }

    #[test]
    fn legacy_shell_default_ignores_output_errors_and_drains_input() {
        let input = vec![b'x'; 8193];
        let mut reader = Cursor::new(input);

        copy_legacy_shell_output(&mut reader, &mut FailingWriter, false).unwrap();

        assert_eq!(reader.position(), reader.get_ref().len() as u64);
    }

    #[test]
    fn legacy_shell_exit_on_write_error_stops_after_first_chunk() {
        let input = vec![b'x'; 8193];
        let mut reader = Cursor::new(input);

        copy_legacy_shell_output(&mut reader, &mut FailingWriter, true).unwrap();

        assert_eq!(reader.position(), 8192);
    }

    #[test]
    fn shell_v2_close_stdin_packet_uses_protocol_frame() {
        let mut wire = Vec::new();
        write_shell_packet(&mut wire, SHELL_ID_CLOSE_STDIN, &[]).unwrap();

        assert_eq!(wire, vec![SHELL_ID_CLOSE_STDIN, 0, 0, 0, 0]);
    }

    #[test]
    fn shell_v2_stdin_packet_uses_protocol_frame() {
        let mut wire = Vec::new();
        write_shell_packet(&mut wire, SHELL_ID_STDIN, b"input\n").unwrap();

        assert_eq!(wire, shell_packet(SHELL_ID_STDIN, b"input\n"));
    }

    #[test]
    fn shell_v2_window_size_payload_matches_aosp_shape() {
        let payload = shell_window_size_payload(ShellWindowSize {
            rows: 24,
            cols: 80,
            x_pixels: 0,
            y_pixels: 0,
        });

        assert_eq!(payload, b"24x80,0x0\0");
    }

    #[test]
    fn shell_v2_resize_writes_only_changed_window_size() {
        let first = ShellWindowSize {
            rows: 24,
            cols: 80,
            x_pixels: 0,
            y_pixels: 0,
        };
        let second = ShellWindowSize {
            rows: 30,
            cols: 100,
            x_pixels: 0,
            y_pixels: 0,
        };
        let mut last_size = None;
        let mut wire = Vec::new();

        write_window_size_change_if_needed(
            |packet_id, payload| write_shell_packet(&mut wire, packet_id, payload),
            &mut last_size,
            Some(first),
        )
        .unwrap();
        write_window_size_change_if_needed(
            |packet_id, payload| write_shell_packet(&mut wire, packet_id, payload),
            &mut last_size,
            Some(first),
        )
        .unwrap();
        write_window_size_change_if_needed(
            |packet_id, payload| write_shell_packet(&mut wire, packet_id, payload),
            &mut last_size,
            None,
        )
        .unwrap();
        write_window_size_change_if_needed(
            |packet_id, payload| write_shell_packet(&mut wire, packet_id, payload),
            &mut last_size,
            Some(second),
        )
        .unwrap();

        let mut expected = Vec::new();
        expected.extend(shell_packet(SHELL_ID_WINDOW_SIZE_CHANGE, b"24x80,0x0\0"));
        expected.extend(shell_packet(SHELL_ID_WINDOW_SIZE_CHANGE, b"30x100,0x0\0"));
        assert_eq!(wire, expected);
    }

    #[test]
    fn shell_v2_raw_escape_disconnect_closes_transport_without_stdin_packet() {
        let mut wire = Vec::new();
        let outcome =
            write_raw_stdin_with_escape(&mut wire, &mut Cursor::new(b"~.".as_slice()), b'~')
                .unwrap();

        assert_eq!(outcome, RawStdinOutcome::Disconnect);
        assert!(wire.is_empty());
    }

    #[test]
    fn shell_v2_raw_escape_replays_non_escape_sequence() {
        let mut wire = Vec::new();
        let outcome =
            write_raw_stdin_with_escape(&mut wire, &mut Cursor::new(b"~x".as_slice()), b'~')
                .unwrap();

        let mut expected = Vec::new();
        expected.extend(shell_packet(SHELL_ID_STDIN, b"~x"));
        expected.extend(shell_packet(SHELL_ID_CLOSE_STDIN, b""));
        assert_eq!(outcome, RawStdinOutcome::Eof);
        assert_eq!(wire, expected);
    }

    #[test]
    fn raw_escape_disconnect_only_matches_at_start_of_line() {
        let mut forwarded = Vec::new();
        let outcome = copy_raw_stdin_with_escape(
            |payload| {
                forwarded.extend_from_slice(payload);
                Ok(())
            },
            &mut Cursor::new(b"echo ~.\r~.".as_slice()),
            b'~',
        )
        .unwrap();

        assert_eq!(outcome, RawStdinOutcome::Disconnect);
        assert_eq!(forwarded, b"echo ~.\r");
    }

    #[test]
    fn shell_escape_disconnect_marks_state_and_closes_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let disconnected = AtomicBool::new(false);

        disconnect_shell(&ServerStream::Tcp(client), &disconnected).unwrap();

        assert!(disconnected.load(Ordering::Acquire));
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn legacy_shell_stdin_eof_only_forwards_input_bytes() {
        let mut forwarded = Vec::new();
        let outcome = copy_legacy_shell_stdin(
            &mut forwarded,
            &mut Cursor::new(b"legacy input".as_slice()),
            false,
            Some(b'~'),
        )
        .unwrap();

        assert_eq!(outcome, RawStdinOutcome::Eof);
        assert_eq!(forwarded, b"legacy input");
    }

    fn spawn_smart_socket_server<F>(handler: F) -> (ServerEndpoint, JoinHandle<()>)
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = ServerEndpoint::new("127.0.0.1", listener.local_addr().unwrap().port());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handler(stream);
        });
        (endpoint, server)
    }

    #[test]
    fn transport_id_selector_uses_official_service_names() {
        let selector = TransportSelector::TransportId(42);

        assert_eq!(selector.transport_service(), "host:transport-id:42");
        assert_eq!(selector.tport_service(), "host:transport-id:42");
        assert_eq!(selector.host_prefix(), "host-transport-id:42");

        let selector = TransportSelector::Serial("serial-1".to_string());
        assert_eq!(selector.tport_service(), "host:tport:serial:serial-1");
        assert_eq!(TransportSelector::Any.tport_service(), "host:tport:any");
        assert_eq!(TransportSelector::Usb.tport_service(), "host:tport:usb");
        assert_eq!(TransportSelector::Local.tport_service(), "host:tport:local");
    }

    #[test]
    fn server_endpoint_env_prefers_adb_server_socket() {
        let endpoint = ServerEndpoint::from_env_values(
            Some("tcp:192.0.2.10:6000"),
            Some("192.0.2.20"),
            Some("7000"),
        )
        .unwrap();

        assert_eq!(endpoint.host, "192.0.2.10");
        assert_eq!(endpoint.port, 6000);
        assert_eq!(endpoint.socket_spec(), "tcp:192.0.2.10:6000");
    }

    #[test]
    fn server_endpoint_env_uses_android_address_and_port() {
        let endpoint =
            ServerEndpoint::from_env_values(None, Some("192.0.2.20"), Some("7000")).unwrap();

        assert_eq!(endpoint.host, "192.0.2.20");
        assert_eq!(endpoint.port, 7000);
        assert_eq!(endpoint.socket_spec(), "tcp:192.0.2.20:7000");
    }

    #[test]
    fn server_endpoint_env_defaults_to_localhost() {
        let endpoint = ServerEndpoint::from_env_values(None, None, None).unwrap();

        assert_eq!(endpoint.host, DEFAULT_SERVER_HOST);
        assert_eq!(endpoint.port, DEFAULT_SERVER_PORT);
        assert_eq!(endpoint.socket_spec(), "tcp:5037");
    }

    #[test]
    fn server_endpoint_preserves_implicit_and_explicit_host_binding() {
        let mut implicit = parse_socket_spec("tcp:6000").unwrap();
        assert_eq!(implicit.socket_spec(), "tcp:6000");
        assert_eq!(implicit.bind_address(), "127.0.0.1:6000");
        implicit.set_listen_all(true);
        assert_eq!(implicit.bind_address(), "0.0.0.0:6000");

        let mut explicit = parse_socket_spec("tcp:127.0.0.1:6000").unwrap();
        assert_eq!(explicit.socket_spec(), "tcp:127.0.0.1:6000");
        explicit.set_listen_all(true);
        assert_eq!(explicit.bind_address(), "127.0.0.1:6000");

        let localhost = parse_socket_spec("tcp:localhost:6000").unwrap();
        assert_eq!(localhost.bind_address(), "127.0.0.1:6000");
    }

    #[test]
    fn tcp_socket_spec_matches_aosp_port_zero_and_default_port_rules() {
        let endpoint = parse_socket_spec("tcp:0").unwrap();
        assert_eq!(endpoint.port, 0);
        assert_eq!(endpoint.socket_spec(), "tcp:0");

        let endpoint = parse_socket_spec("tcp:localhost").unwrap();
        assert_eq!(endpoint.host, "localhost");
        assert_eq!(endpoint.port, DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
        assert_eq!(endpoint.socket_spec(), "tcp:localhost");

        let endpoint = parse_socket_spec("tcp:[::1]").unwrap();
        assert_eq!(endpoint.host, "[::1]");
        assert_eq!(endpoint.port, DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
        assert_eq!(endpoint.socket_spec(), "tcp:[::1]");

        assert!(parse_socket_spec("tcp:65536").is_err());
        assert!(parse_socket_spec("tcp:-1").is_err());
        assert!(parse_socket_spec("tcp:localhost:0").is_err());
    }

    #[test]
    fn server_endpoint_parses_aosp_non_tcp_socket_specs() {
        for spec in [
            "local:/tmp/adb.sock",
            "localfilesystem:/tmp/adb.sock",
            "localabstract:adb-rust",
            "localreserved:adb-rust",
            "vsock:2:5037",
            "acceptfd:42",
        ] {
            assert_eq!(parse_socket_spec(spec).unwrap().socket_spec(), spec);
        }

        assert!(
            parse_socket_spec("local:/tmp/adb.sock")
                .unwrap()
                .is_localhost()
        );
        assert!(
            parse_socket_spec("localabstract:adb-rust")
                .unwrap()
                .is_localhost()
        );
        assert!(!parse_socket_spec("vsock:2:5037").unwrap().is_localhost());
        assert!(!parse_socket_spec("acceptfd:42").unwrap().is_localhost());
        assert!(parse_socket_spec("acceptfd:not-a-fd").is_err());
        assert!(parse_socket_spec("vsock:2:5037:extra").is_err());
        assert!(matches!(
            parse_socket_spec("unknown:value").unwrap_err(),
            AdbError::Server(message)
                if message == "unknown socket specification: unknown:value"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn server_executable_marker_is_only_defined_for_tcp_endpoints() {
        let tcp = parse_socket_spec("tcp:6100").unwrap();
        assert_eq!(
            server_executable_marker_path(&tcp)
                .unwrap()
                .unwrap()
                .file_name()
                .unwrap(),
            "adb.6100"
        );

        for spec in [
            "localfilesystem:/tmp/adb.sock",
            "localabstract:adb-rust",
            "vsock:2:5037",
            "acceptfd:42",
        ] {
            let endpoint = parse_socket_spec(spec).unwrap();
            assert_eq!(server_executable_marker_path(&endpoint).unwrap(), None);
        }
    }

    #[test]
    fn client_connect_resolves_localhost_socket_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = ServerEndpoint::new("localhost", listener.local_addr().unwrap().port());
        let accept = thread::spawn(move || listener.accept().unwrap());

        let stream = connect(&endpoint).unwrap();
        drop(stream);
        let _ = accept.join().unwrap();
    }

    #[test]
    fn server_launch_args_match_aosp_order_and_flags() {
        let mut endpoint = parse_socket_spec("tcp:6000").unwrap();
        endpoint.set_listen_all(true);
        assert_eq!(
            server_launch_args(&endpoint, 42, Some("usb:1-2")),
            vec![
                "-L",
                "tcp:6000",
                "-a",
                "fork-server",
                "server",
                "--reply-fd",
                "42",
                "--one-device",
                "usb:1-2",
            ]
        );

        let endpoint = parse_socket_spec("tcp:localhost:7000").unwrap();
        assert_eq!(
            server_launch_args(&endpoint, 99, None),
            vec![
                "-L",
                "tcp:localhost:7000",
                "fork-server",
                "server",
                "--reply-fd",
                "99",
            ]
        );

        let endpoint = parse_socket_spec("localfilesystem:/tmp/adb.sock").unwrap();
        assert_eq!(
            server_launch_args(&endpoint, 43, None),
            vec![
                "-L",
                "localfilesystem:/tmp/adb.sock",
                "fork-server",
                "server",
                "--reply-fd",
                "43",
            ]
        );
    }

    #[test]
    fn startup_ack_requires_exact_ok_line() {
        read_ack_from_pipe(Cursor::new(b"OK\n".as_slice())).unwrap();
        let err = read_ack_from_pipe(Cursor::new(b"NO\n".as_slice())).unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "daemon did not report startup OK")
        );
    }

    #[test]
    fn kill_server_accepts_orderly_socket_shutdown() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                crate::protocol::read_protocol_string(&mut stream).unwrap(),
                "host:kill"
            );
            stream.write_all(b"OKAY").unwrap();
        });

        kill_server(&endpoint).unwrap();
        server.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_server_command_line_quotes_one_device_as_one_argument() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(
            quote_windows_arg("serial with space"),
            "\"serial with space\""
        );
        assert_eq!(
            windows_server_command_line(&[
                "--one-device".to_string(),
                "serial with space".to_string(),
            ]),
            "adb --one-device \"serial with space\""
        );
    }

    #[test]
    fn ipv6_loopback_address_is_native_on_unix_and_ipv4_on_windows() {
        let endpoint = ServerEndpoint::new("[::1]", 6000);
        #[cfg(windows)]
        assert_eq!(endpoint.address(), "127.0.0.1:6000");
        #[cfg(unix)]
        assert_eq!(endpoint.address(), "[::1]:6000");

        let endpoint = ServerEndpoint::new("::1", 6000);
        #[cfg(windows)]
        assert_eq!(endpoint.address(), "127.0.0.1:6000");
        #[cfg(unix)]
        assert_eq!(endpoint.address(), "[::1]:6000");
    }

    #[test]
    fn switch_transport_with_id_reads_tport_response() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:tport:serial:serial-1"
            );
            protocol::write_okay(&mut stream).unwrap();
            stream.write_all(&42_u64.to_le_bytes()).unwrap();
        });

        let mut stream = connect(&endpoint).unwrap();
        let transport_id = switch_transport_with_id(
            &mut stream,
            &TransportSelector::Serial("serial-1".to_string()),
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(transport_id, Some(42));
    }

    #[test]
    fn switch_transport_with_id_keeps_transport_id_legacy_wire() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:transport-id:42"
            );
            protocol::write_okay(&mut stream).unwrap();
        });

        let mut stream = connect(&endpoint).unwrap();
        let transport_id =
            switch_transport_with_id(&mut stream, &TransportSelector::TransportId(42)).unwrap();
        server.join().unwrap();

        assert_eq!(transport_id, Some(42));
    }

    #[test]
    fn query_device_service_switches_transport_first() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:tport:serial:serial-1"
            );
            protocol::write_okay(&mut stream).unwrap();
            stream.write_all(&7_u64.to_le_bytes()).unwrap();
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "reverse:list-forward"
            );
            protocol::write_okay(&mut stream).unwrap();
            protocol::write_protocol_string(&mut stream, "host tcp:8000 tcp:9000\n").unwrap();
        });

        let body = query_device_service(
            &endpoint,
            &TransportSelector::Serial("serial-1".to_string()),
            "reverse:list-forward",
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(body, "host tcp:8000 tcp:9000\n");
    }

    #[test]
    fn host_service_with_transport_id_matches_transport_id_command_wire() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:tport:serial:serial-1"
            );
            protocol::write_okay(&mut stream).unwrap();
            stream.write_all(&7_u64.to_le_bytes()).unwrap();
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:features"
            );
            protocol::write_okay(&mut stream).unwrap();
            protocol::write_protocol_string(&mut stream, "shell_v2,cmd").unwrap();
        });

        let (_stream, transport_id) = open_host_service_with_transport_id(
            &endpoint,
            &TransportSelector::Serial("serial-1".to_string()),
            "host:features",
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(transport_id, 7);
    }

    #[test]
    fn host_service_with_transport_reads_protocol_string_response() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:tport:serial:serial-1"
            );
            protocol::write_okay(&mut stream).unwrap();
            stream.write_all(&7_u64.to_le_bytes()).unwrap();
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:detach"
            );
            protocol::write_okay(&mut stream).unwrap();
            protocol::write_protocol_string(&mut stream, "detached serial-1").unwrap();
        });

        let body = query_host_service_with_transport(
            &endpoint,
            &TransportSelector::Serial("serial-1".to_string()),
            "host:detach",
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(body, "detached serial-1");
    }

    #[test]
    fn device_service_status_reads_second_status_and_optional_port() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:tport:serial:serial-1"
            );
            protocol::write_okay(&mut stream).unwrap();
            stream.write_all(&7_u64.to_le_bytes()).unwrap();
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "reverse:forward:tcp:0;tcp:9000"
            );
            protocol::write_okay(&mut stream).unwrap();
            protocol::write_okay(&mut stream).unwrap();
            protocol::write_protocol_string(&mut stream, "53775").unwrap();
        });

        let resolved = request_device_service_status(
            &endpoint,
            &TransportSelector::Serial("serial-1".to_string()),
            "reverse:forward:tcp:0;tcp:9000",
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(resolved.as_deref(), Some("53775"));
    }

    #[test]
    fn open_device_service_keeps_transport_id_legacy_switch() {
        let (endpoint, server) = spawn_smart_socket_server(|mut stream| {
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "host:transport-id:42"
            );
            protocol::write_okay(&mut stream).unwrap();
            assert_eq!(
                protocol::read_protocol_string(&mut stream).unwrap(),
                "shell:id"
            );
            protocol::write_okay(&mut stream).unwrap();
        });

        let _stream =
            open_device_service(&endpoint, &TransportSelector::TransportId(42), "shell:id")
                .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn stream_to_writer_with_input_forwards_stdin_then_reads_stdout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            assert_eq!(input, b"raw input");
            stream.write_all(b"raw output").unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut output = Vec::new();
        stream_to_writer_with_input(
            ServerStream::Tcp(stream),
            Cursor::new(b"raw input".to_vec()),
            &mut output,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(output, b"raw output");
    }

    #[test]
    fn sized_service_reads_status_without_half_closing_input() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = vec![0x5a; 64 * 1024];
        let expected = payload.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0_u8; expected.len()];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);

            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut probe = [0_u8; 1];
            let err = stream
                .read(&mut probe)
                .expect_err("sized service must remain open while waiting for status");
            assert!(matches!(
                err.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut
            ));
            stream.write_all(b"Success\n").unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let output = copy_file_to_sized_service(&mut Cursor::new(payload), &mut stream).unwrap();
        server.join().unwrap();

        assert_eq!(output, b"Success\n");
    }

    #[test]
    fn response_service_does_not_half_close_before_delayed_output() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut probe = [0_u8; 1];
            let err = stream
                .read(&mut probe)
                .expect_err("response-only service must remain open until remote output");
            assert!(matches!(
                err.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut
            ));
            stream.write_all(b"delayed output").unwrap();
        });

        let stream = ServerStream::Tcp(TcpStream::connect(addr).unwrap());
        let output = read_stream_to_bytes(stream).unwrap();
        server.join().unwrap();

        assert_eq!(output, b"delayed output");
    }
}
