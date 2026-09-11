use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::{fs, path::PathBuf};

use crate::auth::AuthKey;
use crate::client::{ServerEndpoint, ServerSocketKind, ServerStream};
use crate::device_tracker;
use crate::error::{AdbError, Result};
use crate::mdns;
use crate::pairing;
use crate::protocol;
use crate::server_status::AdbServerStatus;
use crate::transport::{self, ConnectionState, Transport, TransportInfo};
use crate::usb;

const DEFAULT_ADB_LOCAL_TRANSPORT_PORT: u16 = 5555;
const DEFAULT_ADB_LOCAL_TRANSPORT_MAX_PORT: u16 = DEFAULT_ADB_LOCAL_TRANSPORT_PORT + 16 * 2 - 1;
const MDNS_RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(250);
const MDNS_RECONNECT_RETRY_DELAY: Duration = Duration::from_secs(3);
const MDNS_RECONNECT_MAX_ATTEMPTS: usize = 20;
const TCP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(250);
const TCP_RECONNECT_RETRY_DELAY: Duration = Duration::from_secs(3);
const TCP_RECONNECT_MAX_ATTEMPTS: usize = 20;
const USB_RESUME_SERIAL_TTL: Duration = Duration::from_secs(30);

struct MdnsAutoConnectEntry {
    serial: Option<String>,
    next_attempt: Option<Instant>,
    attempts_left: usize,
    in_flight: bool,
    require_auto_allowed: bool,
}

struct TcpReconnectEntry {
    target: String,
    info: TransportInfo,
    next_attempt: Option<Instant>,
    attempts_left: usize,
    in_flight: bool,
}

struct TcpReconnectAttempt {
    serial: String,
    target: String,
    transport_id: u64,
}

struct UsbResumeIdentity {
    serial: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub endpoint: ServerEndpoint,
    pub one_device: Option<String>,
    pub ack_reply_fd: Option<u64>,
}

struct ServerState {
    next_transport_id: AtomicU64,
    transports: Mutex<Vec<Transport>>,
    forwards: Mutex<Vec<ForwardRule>>,
    attached_usb_serials: Mutex<HashSet<String>>,
    mdns: Mutex<Option<mdns::DiscoveryState>>,
    mdns_auto_connects: Mutex<HashMap<String, MdnsAutoConnectEntry>>,
    tcp_reconnects: Mutex<HashMap<String, TcpReconnectEntry>>,
    usb_resume_generation: AtomicU64,
    // Windows 恢复后的首次枚举可能暂时读不到 serial descriptor；按稳定 devpath 保留睡眠前身份。
    // transport 重新注册或短暂恢复窗口结束后立即清理，避免掩盖真实的设备更换。
    usb_resume_serials: Mutex<HashMap<String, UsbResumeIdentity>>,
    usb_scan_errors: Mutex<Vec<String>>,
    device_revision: Mutex<u64>,
    device_changed: Condvar,
    one_device: Option<String>,
    listen_all: bool,
}

impl ServerState {
    #[cfg(test)]
    fn new_with_mdns(one_device: Option<String>, mdns: Option<mdns::DiscoveryState>) -> Self {
        Self::new_with_options(one_device, mdns, false)
    }

    fn new_with_options(
        one_device: Option<String>,
        mdns: Option<mdns::DiscoveryState>,
        listen_all: bool,
    ) -> Self {
        Self {
            next_transport_id: AtomicU64::new(1),
            transports: Mutex::new(Vec::new()),
            forwards: Mutex::new(Vec::new()),
            attached_usb_serials: Mutex::new(HashSet::new()),
            mdns: Mutex::new(mdns),
            mdns_auto_connects: Mutex::new(HashMap::new()),
            tcp_reconnects: Mutex::new(HashMap::new()),
            usb_resume_generation: AtomicU64::new(usb::resume_generation()),
            usb_resume_serials: Mutex::new(HashMap::new()),
            usb_scan_errors: Mutex::new(Vec::new()),
            device_revision: Mutex::new(0),
            device_changed: Condvar::new(),
            one_device,
            listen_all,
        }
    }

    fn start_mdns(self: &Arc<Self>) {
        let weak_state = Arc::downgrade(self);
        let on_resolved = Arc::new(move |service| {
            if let Some(state) = weak_state.upgrade() {
                state.handle_mdns_service_resolved(service);
            }
        });
        *self.mdns.lock().expect("mDNS lock poisoned") =
            Some(mdns::DiscoveryState::start_with_handler(on_resolved));
    }

    fn is_mdns_enabled(&self) -> bool {
        self.mdns
            .lock()
            .expect("mDNS lock poisoned")
            .as_ref()
            .is_some_and(|m| m.is_enabled())
    }

    fn mdns_services(&self) -> Vec<mdns::ServiceInfo> {
        self.mdns
            .lock()
            .expect("mDNS lock poisoned")
            .as_ref()
            .map_or(Vec::new(), |m| m.services())
    }

    fn mdns_connect_target(&self, name: &str) -> Option<String> {
        self.mdns
            .lock()
            .expect("mDNS lock poisoned")
            .as_ref()
            .and_then(|m| m.connect_target(name))
    }

    fn mdns_connect_service(&self, name: &str) -> Option<mdns::ServiceInfo> {
        self.mdns
            .lock()
            .expect("mDNS lock poisoned")
            .as_ref()
            .and_then(|m| m.connect_service(name))
    }

    fn mdns_pairing_target(&self, name: &str) -> Option<String> {
        self.mdns
            .lock()
            .expect("mDNS lock poisoned")
            .as_ref()
            .and_then(|m| m.pairing_target(name))
    }

    fn list(&self) -> Vec<TransportInfo> {
        self.remove_closed_transports();
        self.transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .map(Transport::info)
            .collect()
    }

    fn connect_tcp(&self, target: &str) -> Result<(TransportInfo, bool)> {
        let mdns_service = self.mdns_connect_service(target);
        let result = self.connect_tcp_untracked(target)?;
        if let Some(service) = mdns_service {
            self.record_mdns_connected(&service, &result.0.serial, false);
        } else if !result.1 {
            let normalized = transport::normalize_tcp_serial(target)
                .map_err(|err| AdbError::Server(format!("couldn't parse '{target}': {err}")))?;
            self.record_tcp_connected(normalized, result.0.clone());
        }
        Ok(result)
    }

    fn record_tcp_connected(&self, target: String, info: TransportInfo) {
        self.tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned")
            .insert(
                info.serial.clone(),
                TcpReconnectEntry {
                    target,
                    info,
                    next_attempt: None,
                    attempts_left: TCP_RECONNECT_MAX_ATTEMPTS,
                    in_flight: false,
                },
            );
    }

    fn process_tcp_reconnects(&self) {
        self.process_tcp_reconnects_with(Instant::now(), |attempt| {
            let stream = TcpStream::connect(&attempt.target)?;
            let pending = transport::prepare_tcp_stream_with_serial(
                attempt.transport_id,
                attempt.serial.clone(),
                stream,
            )?;
            self.complete_pending_transport(pending)
        });
    }

    fn process_tcp_reconnects_with<F>(&self, now: Instant, mut connector: F)
    where
        F: FnMut(&TcpReconnectAttempt) -> Result<Transport>,
    {
        let due: Vec<TcpReconnectAttempt> = {
            let mut entries = self
                .tcp_reconnects
                .lock()
                .expect("TCP reconnect registry poisoned");
            entries
                .iter_mut()
                .filter_map(|(serial, entry)| {
                    let is_due = !entry.in_flight
                        && entry
                            .next_attempt
                            .is_some_and(|next_attempt| next_attempt <= now);
                    if !is_due {
                        return None;
                    }
                    entry.in_flight = true;
                    Some(TcpReconnectAttempt {
                        serial: serial.clone(),
                        target: entry.target.clone(),
                        transport_id: entry.info.id,
                    })
                })
                .collect()
        };

        for attempt in due {
            match connector(&attempt) {
                Ok(transport) => self.finish_tcp_reconnect(&attempt.serial, transport),
                Err(err) => {
                    if transport::trace_enabled("transport") {
                        eprintln!("TCP reconnect {} failed: {err}", attempt.serial);
                    }
                    self.retry_tcp_reconnect(&attempt.serial, now);
                }
            }
        }
    }

    fn finish_tcp_reconnect(&self, serial: &str, transport: Transport) {
        let info = transport.info();
        let mut entries = self
            .tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned");
        let Some(entry) = entries.get_mut(serial) else {
            transport.close();
            return;
        };
        if !entry.in_flight || entry.info.id != info.id {
            transport.close();
            return;
        }

        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut replaced = Vec::new();
        let mut already_registered = false;
        transports.retain(|item| {
            if item.same_instance(&transport) {
                already_registered = true;
                return true;
            }
            let item_info = item.info();
            if item_info.serial == serial && item_info.id == info.id {
                replaced.push(item.clone());
                false
            } else {
                true
            }
        });
        if !already_registered {
            transports.push(transport);
        }
        entry.info = info;
        entry.next_attempt = None;
        entry.attempts_left = TCP_RECONNECT_MAX_ATTEMPTS;
        entry.in_flight = false;
        drop(transports);
        drop(entries);

        for old in replaced {
            old.close();
        }
        self.notify_device_changed();
    }

    fn retry_tcp_reconnect(&self, serial: &str, now: Instant) {
        let mut entries = self
            .tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned");
        let mut exhausted_id = None;
        if let Some(entry) = entries.get_mut(serial) {
            entry.in_flight = false;
            if entry.attempts_left == 0 {
                exhausted_id = Some(entry.info.id);
            } else {
                entry.attempts_left -= 1;
                entry.next_attempt = Some(now + TCP_RECONNECT_RETRY_DELAY);
            }
        }
        let Some(exhausted_id) = exhausted_id else {
            return;
        };
        entries.remove(serial);

        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let before = transports.len();
        transports.retain(|transport| {
            let info = transport.info();
            info.serial != serial || info.id != exhausted_id
        });
        let removed = transports.len() != before;
        drop(transports);
        drop(entries);
        if removed {
            self.notify_device_changed();
        }
    }

    fn connect_tcp_untracked(&self, target: &str) -> Result<(TransportInfo, bool)> {
        let mdns_service = self.mdns_connect_service(target);
        let socket_target = mdns_service
            .as_ref()
            .map(|service| format!("{}:{}", service.address, service.port))
            .unwrap_or_else(|| target.to_string());
        let normalized = transport::normalize_tcp_serial(&socket_target)
            .map_err(|err| AdbError::Server(format!("couldn't parse '{socket_target}': {err}")))?;
        let serial = mdns_service
            .as_ref()
            .map(mdns::connect_service_name)
            .unwrap_or_else(|| normalized.clone());
        self.remove_closed_transports();
        if let Some(info) = self.find_transport_info_by_serial(&serial) {
            return Ok((info, true));
        }
        let id = self.next_transport_id.fetch_add(1, Ordering::SeqCst);
        let stream = TcpStream::connect(&normalized)?;
        if !self.owns_transport_serial(&serial) {
            return Err(AdbError::Server(format!(
                "server owns one device only: {}",
                self.one_device.as_deref().unwrap_or_default()
            )));
        }
        let pending = transport::prepare_tcp_stream_with_serial(id, serial, stream)?;
        let transport = self.complete_pending_transport(pending)?;
        Ok((transport.info(), false))
    }

    fn handle_mdns_service_resolved(&self, service: mdns::ServiceInfo) {
        self.handle_mdns_service_resolved_with(
            service,
            std::env::var("ADB_MDNS_AUTO_CONNECT").ok().as_deref(),
            pairing::is_known_host,
        );
    }

    fn handle_mdns_service_resolved_with<F>(
        &self,
        service: mdns::ServiceInfo,
        auto_connect: Option<&str>,
        is_known_host: F,
    ) where
        F: FnOnce(&str) -> bool,
    {
        if !mdns::should_auto_connect(&service, auto_connect, is_known_host) {
            return;
        }
        let serial = mdns::connect_service_name(&service);
        if self.find_transport_info_by_serial(&serial).is_some() {
            self.record_mdns_connected(&service, &serial, true);
            return;
        }

        let source = mdns::connect_service_name(&service);
        let mut entries = self
            .mdns_auto_connects
            .lock()
            .expect("mDNS auto-connect registry poisoned");
        let entry = entries.entry(source).or_insert(MdnsAutoConnectEntry {
            serial: None,
            next_attempt: None,
            attempts_left: MDNS_RECONNECT_MAX_ATTEMPTS,
            in_flight: false,
            require_auto_allowed: true,
        });
        entry.serial = None;
        entry.next_attempt = Some(Instant::now());
        entry.attempts_left = MDNS_RECONNECT_MAX_ATTEMPTS;
    }

    fn record_mdns_connected(
        &self,
        service: &mdns::ServiceInfo,
        serial: &str,
        require_auto_allowed: bool,
    ) {
        let source = mdns::connect_service_name(service);
        let mut entries = self
            .mdns_auto_connects
            .lock()
            .expect("mDNS auto-connect registry poisoned");
        let entry = entries.entry(source).or_insert(MdnsAutoConnectEntry {
            serial: None,
            next_attempt: None,
            attempts_left: MDNS_RECONNECT_MAX_ATTEMPTS,
            in_flight: false,
            require_auto_allowed,
        });
        entry.serial = Some(serial.to_string());
        entry.next_attempt = None;
        entry.attempts_left = MDNS_RECONNECT_MAX_ATTEMPTS;
        entry.in_flight = false;
        // 显式 connect/pair 建立的连接不能被后续发现事件降级为 allowlist 管理。
        entry.require_auto_allowed &= require_auto_allowed;
    }

    fn process_mdns_auto_connects(&self) {
        self.process_mdns_auto_connects_with(
            Instant::now(),
            std::env::var("ADB_MDNS_AUTO_CONNECT").ok().as_deref(),
            pairing::is_known_host,
            |target| self.connect_tcp_untracked(target),
        );
    }

    fn process_mdns_auto_connects_with<F, K>(
        &self,
        now: Instant,
        auto_connect: Option<&str>,
        is_known_host: K,
        mut connector: F,
    ) where
        F: FnMut(&str) -> Result<(TransportInfo, bool)>,
        K: Fn(&str) -> bool,
    {
        let due_sources: Vec<String> = {
            let mut entries = self
                .mdns_auto_connects
                .lock()
                .expect("mDNS auto-connect registry poisoned");
            entries
                .iter_mut()
                .filter_map(|(source, entry)| {
                    let due = !entry.in_flight
                        && entry
                            .next_attempt
                            .is_some_and(|next_attempt| next_attempt <= now);
                    if due {
                        entry.in_flight = true;
                        Some(source.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        for source in due_sources {
            let require_auto_allowed = self
                .mdns_auto_connects
                .lock()
                .expect("mDNS auto-connect registry poisoned")
                .get(&source)
                .is_some_and(|entry| entry.require_auto_allowed);
            let Some(service) = self.mdns_connect_service(&source) else {
                self.mdns_auto_connects
                    .lock()
                    .expect("mDNS auto-connect registry poisoned")
                    .remove(&source);
                continue;
            };
            if require_auto_allowed
                && !mdns::should_auto_connect(&service, auto_connect, &is_known_host)
            {
                self.mdns_auto_connects
                    .lock()
                    .expect("mDNS auto-connect registry poisoned")
                    .remove(&source);
                continue;
            }

            let active = self.find_transport_info_by_serial(&source);
            let result = match active {
                Some(info) => Ok((info, true)),
                None => connector(&source),
            };
            match result {
                Ok((info, _)) => {
                    self.record_mdns_connected(&service, &info.serial, require_auto_allowed);
                }
                Err(err) => {
                    if transport::trace_enabled("mdns") {
                        eprintln!("mDNS auto-connect {source} failed: {err}");
                    }
                    let mut entries = self
                        .mdns_auto_connects
                        .lock()
                        .expect("mDNS auto-connect registry poisoned");
                    let mut remove = false;
                    if let Some(entry) = entries.get_mut(&source) {
                        entry.in_flight = false;
                        if entry.attempts_left == 0 {
                            remove = true;
                        } else {
                            entry.attempts_left -= 1;
                            entry.next_attempt = Some(now + MDNS_RECONNECT_RETRY_DELAY);
                        }
                    }
                    if remove {
                        entries.remove(&source);
                    }
                }
            }
        }
    }

    fn reschedule_mdns_connections_for_serials(&self, serials: &[String]) {
        if serials.is_empty() {
            return;
        }
        let serials: HashSet<&str> = serials.iter().map(String::as_str).collect();
        let mut entries = self
            .mdns_auto_connects
            .lock()
            .expect("mDNS auto-connect registry poisoned");
        for entry in entries.values_mut() {
            if entry
                .serial
                .as_deref()
                .is_some_and(|serial| serials.contains(serial))
            {
                entry.serial = None;
                entry.next_attempt = Some(Instant::now() + MDNS_RECONNECT_INITIAL_DELAY);
                entry.attempts_left = MDNS_RECONNECT_MAX_ATTEMPTS;
                entry.in_flight = false;
            }
        }
    }

    fn cancel_mdns_connections_for_serials(&self, serials: &[String]) {
        if serials.is_empty() {
            return;
        }
        let serials: HashSet<&str> = serials.iter().map(String::as_str).collect();
        self.mdns_auto_connects
            .lock()
            .expect("mDNS auto-connect registry poisoned")
            .retain(|_, entry| {
                !entry
                    .serial
                    .as_deref()
                    .is_some_and(|serial| serials.contains(serial))
            });
    }

    /// 按 AOSP `host:emulator:<adb_port>` 语义，显式通知 server 某个模拟器实例已启动。
    /// 连接 127.0.0.1:<adb_port>，并以 `emulator-<console_port>`（console_port = adb_port - 1）注册。
    fn connect_emulator(&self, adb_port: u16) {
        self.remove_closed_transports();
        if self.has_emulator_transport_for_port(adb_port) {
            return;
        }
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), adb_port));
        let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
            return;
        };
        let id = self.next_transport_id.fetch_add(1, Ordering::SeqCst);
        let serial = emulator_serial_for_adb_port(adb_port);
        if !self.owns_transport_serial(&serial) {
            return;
        }
        if let Ok(pending) = transport::prepare_tcp_stream_with_serial(id, serial, stream) {
            let _ = self.complete_pending_transport(pending);
        }
    }

    fn scan_emulators_once(&self) -> usize {
        if std::env::var("ADB_EMU").ok().as_deref() == Some("0") {
            return 0;
        }

        let mut added = 0;
        for adb_port in emulator_scan_ports() {
            if self.has_emulator_transport_for_port(adb_port) {
                continue;
            }

            // 模拟器扫描使用短超时，避免黑端口长时间阻塞 server。
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), adb_port));
            if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                let id = self.next_transport_id.fetch_add(1, Ordering::SeqCst);
                let serial = emulator_serial_for_adb_port(adb_port);
                if !self.owns_transport_serial(&serial) {
                    continue;
                }
                match transport::prepare_tcp_stream_with_serial(id, serial, stream)
                    .and_then(|pending| self.complete_pending_transport(pending))
                {
                    Ok(_) => {
                        added += 1;
                    }
                    Err(err) => {
                        eprintln!("adb-rust emulator scan failed on port {adb_port}: {err}");
                    }
                }
            }
        }
        added
    }

    fn scan_usb_once(&self) -> usize {
        if std::env::var("ADB_USB").ok().as_deref() == Some("0") {
            self.usb_scan_errors
                .lock()
                .expect("USB scan errors poisoned")
                .clear();
            return 0;
        }

        let usb_list = match usb::list_adb_interfaces_with_diagnostics() {
            Ok(usb_list) => usb_list,
            Err(err) => {
                *self
                    .usb_scan_errors
                    .lock()
                    .expect("USB scan errors poisoned") = vec![err.to_string()];
                return 0;
            }
        };

        let mut added = 0;
        let mut errors = usb_list.diagnostics;
        let interfaces = usb_list.interfaces;
        self.expire_usb_resume_serials();
        self.reconcile_inactive_usb_transports(&interfaces);
        for interface in interfaces {
            let serial = self.usb_serial_for_scan(&interface);
            if !self.owns_usb_interface(&interface, &serial) {
                continue;
            }

            let existing = self.find_usb_transport_info(&interface, &serial);
            let retrying_no_permissions = existing
                .as_ref()
                .is_some_and(|info| info.state == ConnectionState::NoPermissions);
            if existing.is_some() && !retrying_no_permissions {
                self.clear_usb_resume_serial(&interface);
                continue;
            }
            let id = existing.map_or_else(
                || self.next_transport_id.fetch_add(1, Ordering::SeqCst),
                |info| info.id,
            );
            if self.should_start_usb_detached(&interface, &serial) {
                let transport = detached_usb_transport_from_interface(id, &interface, serial);
                self.register_transport(transport);
                self.clear_usb_resume_serial(&interface);
                added += 1;
                continue;
            }

            match transport::prepare_usb_for_scan(id, &interface, Some(&serial)) {
                Ok(pending) => match self.complete_pending_transport(pending) {
                    Ok(_) => added += 1,
                    Err(err) => errors.push(format!("{}: {err}", interface.short_description())),
                },
                Err(err) if err.is_permission_denied() => {
                    if !retrying_no_permissions {
                        let transport =
                            no_permissions_usb_transport_from_interface(id, &interface, serial);
                        self.register_transport(transport);
                        self.clear_usb_resume_serial(&interface);
                        added += 1;
                    }
                }
                Err(err) => errors.push(format!("{}: {err}", interface.short_description())),
            }
        }
        *self
            .usb_scan_errors
            .lock()
            .expect("USB scan errors poisoned") = errors;
        added
    }

    fn reconcile_inactive_usb_transports(&self, interfaces: &[usb::UsbAdbInterface]) -> usize {
        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut removed = Vec::new();
        transports.retain(|transport| {
            let info = transport.info();
            let inactive_usb = info.is_usb_transport()
                && matches!(
                    info.state,
                    ConnectionState::Detached | ConnectionState::NoPermissions
                );
            let present = !inactive_usb
                || interfaces.iter().any(|interface| {
                    let serial = interface.serial_or_fallback();
                    serial == info.serial
                        || info.devpath.as_deref() == Some(interface.bus_address.as_str())
                });
            if !present {
                removed.push(transport.clone());
            }
            present
        });
        drop(transports);

        let removed_serials: Vec<String> = removed
            .iter()
            .map(|transport| transport.info().serial)
            .collect();
        self.remove_forwards_for_serials(&removed_serials);
        for transport in removed {
            transport.close();
        }
        if !removed_serials.is_empty() {
            self.notify_device_changed();
        }
        removed_serials.len()
    }

    fn usb_serial_for_scan(&self, interface: &usb::UsbAdbInterface) -> String {
        if let Some(serial) = &interface.serial_number {
            return serial.clone();
        }

        let now = Instant::now();
        let mut resume_serials = self
            .usb_resume_serials
            .lock()
            .expect("USB resume serial registry poisoned");
        resume_serials.retain(|_, identity| identity.expires_at > now);
        resume_serials
            .get(&interface.bus_address)
            .map(|identity| identity.serial.clone())
            .unwrap_or_else(|| interface.usb_serial_fallback())
    }

    fn clear_usb_resume_serial(&self, interface: &usb::UsbAdbInterface) {
        self.usb_resume_serials
            .lock()
            .expect("USB resume serial registry poisoned")
            .remove(&interface.bus_address);
    }

    fn expire_usb_resume_serials(&self) {
        let now = Instant::now();
        self.usb_resume_serials
            .lock()
            .expect("USB resume serial registry poisoned")
            .retain(|_, identity| identity.expires_at > now);
    }

    fn handle_usb_resume(&self) -> bool {
        self.handle_usb_resume_generation(usb::resume_generation())
    }

    fn handle_usb_resume_generation(&self, generation: u64) -> bool {
        let previous = self
            .usb_resume_generation
            .swap(generation, Ordering::SeqCst);
        if generation == previous {
            return false;
        }

        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut removed = Vec::new();
        transports.retain(|transport| {
            if transport.info().is_usb_transport() {
                removed.push(transport.clone());
                false
            } else {
                true
            }
        });
        drop(transports);

        let expires_at = Instant::now() + USB_RESUME_SERIAL_TTL;
        let resume_serials = removed
            .iter()
            .filter_map(|transport| {
                let info = transport.info();
                info.devpath.map(|devpath| {
                    (
                        devpath,
                        UsbResumeIdentity {
                            serial: info.serial,
                            expires_at,
                        },
                    )
                })
            })
            .collect();
        *self
            .usb_resume_serials
            .lock()
            .expect("USB resume serial registry poisoned") = resume_serials;

        let removed_serials: Vec<String> = removed
            .iter()
            .map(|transport| transport.info().serial)
            .collect();
        self.remove_forwards_for_serials(&removed_serials);
        for transport in removed {
            transport.close();
        }
        if !removed_serials.is_empty() {
            self.notify_device_changed();
        }
        true
    }

    fn should_start_usb_detached(&self, interface: &usb::UsbAdbInterface, serial: &str) -> bool {
        self.should_start_usb_detached_for_env(
            interface,
            serial,
            std::env::var("ADB_LIBUSB_START_DETACHED").ok().as_deref(),
        )
    }

    fn should_start_usb_detached_for_env(
        &self,
        interface: &usb::UsbAdbInterface,
        serial: &str,
        env_value: Option<&str>,
    ) -> bool {
        env_value == Some("1")
            && usb_interface_supports_detach(interface)
            && !self.is_usb_attached(serial)
    }

    fn is_usb_attached(&self, serial: &str) -> bool {
        self.attached_usb_serials
            .lock()
            .expect("attached USB registry poisoned")
            .contains(serial)
    }

    fn register_usb_attach(&self, serial: &str) {
        self.attached_usb_serials
            .lock()
            .expect("attached USB registry poisoned")
            .insert(serial.to_string());
    }

    fn register_usb_detach(&self, serial: &str) {
        self.attached_usb_serials
            .lock()
            .expect("attached USB registry poisoned")
            .remove(serial);
    }

    fn register_transport(&self, transport: Transport) -> TransportInfo {
        let info = transport.info();
        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut replaced = Vec::new();
        let mut already_registered = false;
        transports.retain(|item| {
            if item.same_instance(&transport) {
                already_registered = true;
                return true;
            }
            let item_info = item.info();
            let same_usb_devpath = info.is_usb_transport()
                && item_info.is_usb_transport()
                && info.devpath.is_some()
                && info.devpath == item_info.devpath;
            if item_info.serial == info.serial || same_usb_devpath {
                replaced.push(item.clone());
                false
            } else {
                true
            }
        });
        if !already_registered {
            transports.push(transport);
        }
        drop(transports);
        let replaced_serials: Vec<String> = replaced
            .iter()
            .map(|transport| transport.info().serial)
            .collect();
        self.remove_forwards_for_serials(&replaced_serials);
        for transport in replaced {
            transport.close();
        }
        self.notify_device_changed();
        info
    }

    fn complete_pending_transport(
        &self,
        pending: transport::PendingTransport,
    ) -> Result<Transport> {
        let placeholder = pending.transport();
        self.register_transport(placeholder.clone());
        match pending.finish(|_| self.notify_device_changed()) {
            Ok(transport) => {
                let info = transport.info();
                if info.is_usb_transport()
                    && let Some(devpath) = info.devpath
                {
                    self.usb_resume_serials
                        .lock()
                        .expect("USB resume serial registry poisoned")
                        .remove(&devpath);
                }
                self.notify_device_changed();
                Ok(transport)
            }
            Err(err) => {
                let mut transports = self.transports.lock().expect("transport registry poisoned");
                let before = transports.len();
                transports.retain(|transport| !transport.same_instance(&placeholder));
                let removed = transports.len() != before;
                drop(transports);
                placeholder.close();
                if removed {
                    self.notify_device_changed();
                }
                Err(err)
            }
        }
    }

    fn owns_transport_serial(&self, serial: &str) -> bool {
        match self.one_device.as_deref() {
            Some(one_device) => one_device == serial,
            None => true,
        }
    }

    fn owns_usb_interface(&self, interface: &usb::UsbAdbInterface, serial: &str) -> bool {
        match self.one_device.as_deref() {
            Some(one_device) => {
                one_device == serial
                    || one_device == interface.bus_address
                    || one_device == interface.usb_serial_fallback()
            }
            None => true,
        }
    }

    fn find_transport_info_by_serial(&self, serial: &str) -> Option<TransportInfo> {
        self.remove_closed_transports();
        self.transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .find(|transport| transport.info().serial == serial)
            .map(|transport| transport.info())
    }

    fn find_usb_transport_info(
        &self,
        interface: &usb::UsbAdbInterface,
        serial: &str,
    ) -> Option<TransportInfo> {
        self.remove_closed_transports();
        self.transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .map(Transport::info)
            .find(|info| {
                info.is_usb_transport()
                    && (info.serial == serial
                        || info.devpath.as_deref() == Some(interface.bus_address.as_str()))
            })
    }

    fn has_emulator_transport_for_port(&self, adb_port: u16) -> bool {
        self.remove_closed_transports();
        let serial = emulator_serial_for_adb_port(adb_port);
        let host_serial = format!("127.0.0.1:{adb_port}");
        let localhost_serial = format!("localhost:{adb_port}");
        self.transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .any(|transport| {
                let info = transport.info();
                info.serial == serial
                    || info.serial == host_serial
                    || info.serial == localhost_serial
            })
    }

    fn disconnect(&self, target: Option<&str>) -> Result<String> {
        let mdns_serial = target
            .and_then(|target| self.mdns_connect_service(target))
            .map(|service| mdns::connect_service_name(&service));
        let mut tcp_reconnects = self
            .tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned");
        let mut transports = self.transports.lock().expect("transport registry poisoned");

        let Some(target) = target.filter(|target| !target.is_empty()) else {
            let mut removed = Vec::new();
            transports.retain(|transport| {
                if transport.info().is_local_transport() {
                    removed.push(transport.clone());
                    false
                } else {
                    true
                }
            });
            drop(transports);
            let removed_serials: Vec<String> = removed
                .iter()
                .map(|transport| transport.info().serial)
                .collect();
            let removed_set: HashSet<&str> = removed_serials.iter().map(String::as_str).collect();
            tcp_reconnects.retain(|serial, _| !removed_set.contains(serial.as_str()));
            drop(tcp_reconnects);
            self.cancel_mdns_connections_for_serials(&removed_serials);
            self.remove_forwards_for_serials(&removed_serials);
            for transport in removed {
                transport.close();
            }
            self.notify_device_changed();
            return Ok("disconnected everything".to_string());
        };

        let serial =
            disconnect_target_serial(&transports, mdns_serial.as_deref().unwrap_or(target))?;
        let mut removed = Vec::new();
        transports.retain(|transport| {
            if transport.info().serial == serial {
                removed.push(transport.clone());
                false
            } else {
                true
            }
        });
        drop(transports);

        if removed.is_empty() {
            return Err(AdbError::Server(format!("no such device '{serial}'")));
        }
        let removed_serials: Vec<String> = removed
            .iter()
            .map(|transport| transport.info().serial)
            .collect();
        let removed_set: HashSet<&str> = removed_serials.iter().map(String::as_str).collect();
        tcp_reconnects.retain(|serial, _| !removed_set.contains(serial.as_str()));
        drop(tcp_reconnects);
        self.cancel_mdns_connections_for_serials(&removed_serials);
        self.remove_forwards_for_serials(&removed_serials);
        for transport in removed {
            transport.close();
        }
        self.notify_device_changed();
        Ok(format!("disconnected {target}"))
    }

    fn reconnect_offline(&self) -> String {
        let mut tcp_reconnects = self
            .tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned");
        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut removed = Vec::new();
        transports.retain(|transport| {
            if matches!(
                transport.info().state,
                ConnectionState::Offline | ConnectionState::Unauthorized
            ) {
                removed.push(transport.clone());
                false
            } else {
                true
            }
        });
        drop(transports);
        let removed_serials: Vec<String> = removed
            .iter()
            .map(|transport| transport.info().serial)
            .collect();
        let removed_set: HashSet<&str> = removed_serials.iter().map(String::as_str).collect();
        tcp_reconnects.retain(|serial, _| !removed_set.contains(serial.as_str()));
        drop(tcp_reconnects);
        self.cancel_mdns_connections_for_serials(&removed_serials);
        self.remove_forwards_for_serials(&removed_serials);
        let mut response = String::new();
        for transport in removed {
            let info = transport.info();
            response.push_str("reconnecting ");
            response.push_str(&info.serial);
            response.push('\n');
            transport.close();
        }
        if response.ends_with('\n') {
            response.pop();
        }
        if !response.is_empty() {
            self.notify_device_changed();
        }
        response
    }

    fn reconnect_transport(&self, selector: HostSelector<'_>) -> String {
        match self.select_info_for_with_state(selector, true) {
            Ok(info) => {
                self.disconnect(Some(&info.serial)).ok();
                format!("reconnecting {} [{}]\n", info.serial, info.state.as_adb())
            }
            Err(AdbError::Server(reason)) => reason,
            Err(err) => err.to_string(),
        }
    }

    fn attach_transport(&self, selector: HostSelector<'_>) -> Result<String> {
        let info = self.select_info_for_with_state(selector, true)?;
        self.attach_selected_transport(&info)
    }

    fn detach_transport(&self, selector: HostSelector<'_>) -> Result<String> {
        let info = self.select_info_for_with_state(selector, true)?;
        self.detach_selected_transport(&info)
    }

    fn attach_selected_transport(&self, selected: &TransportInfo) -> Result<String> {
        self.attach_selected_transport_with(selected, |state, info| {
            state.reconnect_detached_usb(info)
        })
    }

    fn attach_selected_transport_with<F>(
        &self,
        selected: &TransportInfo,
        reconnect: F,
    ) -> Result<String>
    where
        F: FnOnce(&Self, &TransportInfo) -> Result<Transport>,
    {
        let info = self.current_transport_info(selected.id)?;
        if !transport_supports_detach(&info) {
            return Err(AdbError::Server(
                attach_detach_unsupported_message("attach").to_string(),
            ));
        }
        if info.state != ConnectionState::Detached {
            return Err(AdbError::Server(format!(
                "transport {} is not detached",
                info.serial
            )));
        }

        self.register_usb_attach(&info.serial);
        let transport = match reconnect(self, &info) {
            Ok(transport) => transport,
            Err(err) => {
                self.register_usb_detach(&info.serial);
                return Err(err);
            }
        };
        self.register_transport(transport);
        Ok(format!("{} attached", info.serial))
    }

    fn detach_selected_transport(&self, selected: &TransportInfo) -> Result<String> {
        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let Some(index) = transports
            .iter()
            .position(|transport| transport.info().id == selected.id)
        else {
            return Err(AdbError::Server(format!(
                "transport id '{}' not found",
                selected.id
            )));
        };

        let info = transports[index].info();
        if !transport_supports_detach(&info) {
            return Err(AdbError::Server(
                attach_detach_unsupported_message("detach").to_string(),
            ));
        }
        if info.state == ConnectionState::Detached {
            return Err(AdbError::Server(format!(
                "transport {} is already detached",
                info.serial
            )));
        }

        let removed = transports.remove(index);
        let detached = Transport::detached(info.clone());
        transports.push(detached);
        drop(transports);

        self.register_usb_detach(&info.serial);
        self.remove_forwards_for_serials(std::slice::from_ref(&info.serial));
        removed.close();
        self.notify_device_changed();
        Ok(format!("{} detached", info.serial))
    }

    fn current_transport_info(&self, id: u64) -> Result<TransportInfo> {
        self.transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .find(|transport| transport.info().id == id)
            .map(Transport::info)
            .ok_or_else(|| AdbError::Server(format!("transport id '{id}' not found")))
    }

    fn reconnect_detached_usb(&self, info: &TransportInfo) -> Result<Transport> {
        thread::sleep(usb::release_settle_delay());
        let mut last_error = None;
        for attempt in 0..20 {
            match self.reconnect_detached_usb_once(info) {
                Ok(transport) => return Ok(transport),
                Err(err) => {
                    last_error = Some(err.to_string());
                    if attempt != 19 {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }

        if self.current_transport_info(info.id).is_err() {
            self.register_transport(Transport::detached(info.clone()));
        }
        Err(AdbError::Server(last_error.unwrap_or_else(|| {
            format!("USB ADB interface for '{}' not found", info.serial)
        })))
    }

    fn reconnect_detached_usb_once(&self, info: &TransportInfo) -> Result<Transport> {
        let usb_list = usb::list_adb_interfaces_with_diagnostics()?;
        let mut interfaces: Vec<_> = usb_list
            .interfaces
            .into_iter()
            .filter(|interface| {
                let serial = interface.serial_or_fallback();
                self.owns_usb_interface(interface, &serial)
                    && (serial == info.serial
                        || info.devpath.as_deref() == Some(interface.bus_address.as_str()))
            })
            .collect();

        if interfaces.is_empty() {
            return Err(AdbError::Server(format!(
                "USB ADB interface for '{}' not found",
                info.serial
            )));
        }

        interfaces.sort_by_key(|interface| !usb_interface_supports_detach(interface));
        let mut last_error = None;
        for interface in interfaces {
            let serial = interface.serial_or_fallback();
            match transport::prepare_usb_with_serial(info.id, &interface, Some(&info.serial))
                .and_then(|pending| self.complete_pending_transport(pending))
            {
                Ok(transport) => return Ok(transport),
                Err(err) => {
                    last_error = Some(format!("{serial}: {err}"));
                }
            }
        }

        Err(AdbError::Server(last_error.unwrap_or_else(|| {
            format!("USB ADB interface for '{}' not found", info.serial)
        })))
    }

    fn remove_closed_transports(&self) -> usize {
        let now = Instant::now();
        let mut reconnects = self
            .tcp_reconnects
            .lock()
            .expect("TCP reconnect registry poisoned");
        let mut transports = self.transports.lock().expect("transport registry poisoned");
        let mut removed_serials = Vec::new();
        let mut offline_transports = Vec::new();
        transports.retain(|transport| {
            if transport.is_closed() {
                let mut info = transport.info();
                removed_serials.push(info.serial.clone());
                if let Some(entry) = reconnects.get_mut(&info.serial) {
                    info.state = ConnectionState::Offline;
                    entry.info = info.clone();
                    entry.next_attempt = Some(now + TCP_RECONNECT_INITIAL_DELAY);
                    entry.attempts_left = TCP_RECONNECT_MAX_ATTEMPTS;
                    entry.in_flight = false;
                    offline_transports.push(Transport::offline(info));
                }
                false
            } else {
                true
            }
        });
        transports.extend(offline_transports);
        let removed = removed_serials.len();
        drop(transports);
        drop(reconnects);
        if removed > 0 {
            self.reschedule_mdns_connections_for_serials(&removed_serials);
            self.remove_forwards_for_serials(&removed_serials);
            self.notify_device_changed();
        }
        removed
    }

    fn notify_device_changed(&self) {
        let mut revision = self
            .device_revision
            .lock()
            .expect("device revision poisoned");
        *revision = revision.wrapping_add(1);
        self.device_changed.notify_all();
    }

    fn device_revision(&self) -> u64 {
        *self
            .device_revision
            .lock()
            .expect("device revision poisoned")
    }

    fn wait_for_device_revision(&self, previous: u64, shutdown: &AtomicBool) -> u64 {
        let mut revision = self
            .device_revision
            .lock()
            .expect("device revision poisoned");
        while *revision == previous && !shutdown.load(Ordering::SeqCst) {
            let (guard, _) = self
                .device_changed
                .wait_timeout(revision, Duration::from_millis(250))
                .expect("device revision poisoned");
            revision = guard;
        }
        *revision
    }

    fn select_any(&self) -> Result<TransportInfo> {
        self.select_any_with_state(false)
    }

    fn select_any_with_state(&self, accept_any_state: bool) -> Result<TransportInfo> {
        let transports = self.transports.lock().expect("transport registry poisoned");
        let selectable: Vec<_> = transports
            .iter()
            .filter(|transport| transport.info().state != ConnectionState::NoPermissions)
            .collect();
        match selectable.as_slice() {
            [] => Err(no_permissions_selection_error(&transports)
                .unwrap_or_else(|| AdbError::Server("no devices/emulators found".to_string()))),
            [transport] => validate_selected_info(transport.info(), accept_any_state),
            _ => Err(AdbError::Server(
                "more than one device/emulator".to_string(),
            )),
        }
    }

    fn select_serial(&self, serial: &str) -> Result<TransportInfo> {
        self.select_serial_transport_with_state(serial, false)
            .map(|transport| transport.info())
    }

    fn select_serial_transport(&self, serial: &str) -> Result<Transport> {
        self.select_serial_transport_with_state(serial, false)
    }

    fn select_serial_transport_with_state(
        &self,
        serial: &str,
        accept_any_state: bool,
    ) -> Result<Transport> {
        let transports = self.transports.lock().expect("transport registry poisoned");
        let matches: Vec<_> = transports
            .iter()
            .filter(|transport| {
                let info = transport.info();
                info.state != ConnectionState::NoPermissions
                    && transport_matches_target(&info, serial)
            })
            .cloned()
            .collect();
        match matches.as_slice() {
            [] => Err(no_permissions_selection_error(&transports)
                .unwrap_or_else(|| AdbError::Server(format!("device '{serial}' not found")))),
            [transport] => validate_selected_transport(transport.clone(), accept_any_state),
            _ => Err(AdbError::Server(format!(
                "more than one device with serial {serial}"
            ))),
        }
    }

    fn select_id(&self, id: u64) -> Result<TransportInfo> {
        self.select_id_with_state(id, false)
    }

    fn select_id_with_state(&self, id: u64, accept_any_state: bool) -> Result<TransportInfo> {
        let transports = self.transports.lock().expect("transport registry poisoned");
        transports
            .iter()
            .find(|transport| {
                let info = transport.info();
                info.state != ConnectionState::NoPermissions && info.id == id
            })
            .map(Transport::info)
            .ok_or_else(|| AdbError::Server(format!("transport id '{id}' not found")))
            .or_else(|err| no_permissions_selection_error(&transports).map_or(Err(err), Err))
            .and_then(|info| validate_selected_info(info, accept_any_state))
    }

    fn select_info_for(&self, selector: HostSelector<'_>) -> Result<TransportInfo> {
        self.select_info_for_with_state(selector, false)
    }

    fn select_info_for_with_state(
        &self,
        selector: HostSelector<'_>,
        accept_any_state: bool,
    ) -> Result<TransportInfo> {
        match selector {
            HostSelector::Any => self.select_any_with_state(accept_any_state),
            HostSelector::Serial(serial) => self
                .select_serial_transport_with_state(serial, accept_any_state)
                .map(|transport| transport.info()),
            HostSelector::TransportId(id) => self.select_id_with_state(id, accept_any_state),
            HostSelector::Usb => self
                .select_usb_rescan_with_state(accept_any_state)
                .map(|transport| transport.info()),
            HostSelector::Local => self
                .select_local_with_state(accept_any_state)
                .map(|transport| transport.info()),
        }
    }

    fn select_transport_for(&self, selector: HostSelector<'_>) -> Result<Transport> {
        if matches!(selector, HostSelector::Usb) {
            return self.select_usb_rescan();
        }
        if matches!(selector, HostSelector::Local) {
            return self.select_local();
        }

        let transports = self.transports.lock().expect("transport registry poisoned");
        match selector {
            HostSelector::Any => {
                let selectable: Vec<_> = transports
                    .iter()
                    .filter(|transport| transport.info().state != ConnectionState::NoPermissions)
                    .cloned()
                    .collect();
                match selectable.as_slice() {
                    [] => Err(
                        no_permissions_selection_error(&transports).unwrap_or_else(|| {
                            AdbError::Server("no devices/emulators found".to_string())
                        }),
                    ),
                    [transport] => validate_selected_transport(transport.clone(), false),
                    _ => Err(AdbError::Server(
                        "more than one device/emulator".to_string(),
                    )),
                }
            }
            HostSelector::Serial(serial) => {
                drop(transports);
                self.select_serial_transport(serial)
            }
            HostSelector::TransportId(id) => transports
                .iter()
                .find(|transport| {
                    let info = transport.info();
                    info.state != ConnectionState::NoPermissions && info.id == id
                })
                .cloned()
                .ok_or_else(|| AdbError::Server(format!("transport id '{id}' not found")))
                .or_else(|err| no_permissions_selection_error(&transports).map_or(Err(err), Err))
                .and_then(|transport| validate_selected_transport(transport, false)),
            HostSelector::Usb | HostSelector::Local => unreachable!(),
        }
    }

    fn select_usb_rescan(&self) -> Result<Transport> {
        self.select_usb_rescan_with_state(false)
    }

    fn select_usb_rescan_with_state(&self, accept_any_state: bool) -> Result<Transport> {
        match self.select_usb_registered_with_state(accept_any_state) {
            Ok(transport) => return Ok(transport),
            Err(_) => {
                let _ = self.scan_usb_once();
            }
        }
        self.select_usb_registered_with_state(accept_any_state)
    }

    fn select_usb_registered_with_state(&self, accept_any_state: bool) -> Result<Transport> {
        let transports = self.transports.lock().expect("transport registry poisoned");
        let matches: Vec<_> = transports
            .iter()
            .filter(|transport| {
                let info = transport.info();
                info.is_usb_transport() && info.state != ConnectionState::NoPermissions
            })
            .cloned()
            .collect();
        match matches.as_slice() {
            [] => Err(no_permissions_selection_error(&transports)
                .unwrap_or_else(|| AdbError::Server(self.usb_selection_message()))),
            [transport] => validate_selected_transport(transport.clone(), accept_any_state),
            _ => Err(AdbError::Server("more than one USB device".to_string())),
        }
    }

    fn select_local(&self) -> Result<Transport> {
        self.select_local_with_state(false)
    }

    fn select_local_with_state(&self, accept_any_state: bool) -> Result<Transport> {
        let transports = self.transports.lock().expect("transport registry poisoned");
        let matches: Vec<_> = transports
            .iter()
            .filter(|transport| transport.info().is_local_transport())
            .cloned()
            .collect();
        match matches.as_slice() {
            [] => Err(no_permissions_selection_error(&transports)
                .unwrap_or_else(|| AdbError::Server("no emulators found".to_string()))),
            [transport] => validate_selected_transport(transport.clone(), accept_any_state),
            _ => Err(AdbError::Server("more than one emulator".to_string())),
        }
    }

    fn usb_selection_message(&self) -> String {
        let errors = self
            .usb_scan_errors
            .lock()
            .expect("USB scan errors poisoned")
            .clone();
        if !errors.is_empty() {
            return format!("no USB devices registered ({})", errors.join("; "));
        }

        usb_selection_message()
    }

    fn list_forwards(&self) -> String {
        self.remove_closed_transports();
        let mut rules = self
            .forwards
            .lock()
            .expect("forward registry poisoned")
            .clone();
        rules.sort_by(|left, right| {
            left.serial
                .cmp(&right.serial)
                .then_with(|| left.local.cmp(&right.local))
        });

        let mut out = String::new();
        for rule in rules {
            out.push_str(&rule.serial);
            out.push(' ');
            out.push_str(&rule.local);
            out.push(' ');
            out.push_str(&rule.remote);
            out.push('\n');
        }
        out
    }

    fn install_forward(
        &self,
        selector: HostSelector<'_>,
        spec: &str,
        no_rebind: bool,
    ) -> Result<Option<String>> {
        let transport = self.select_transport_for(selector)?;
        let info = transport.info();
        let serial = info.serial;
        let (local, remote) = parse_forward_spec(spec)?;
        let canonical_local = canonical_forward_local(local)?;

        {
            let mut forwards = self.forwards.lock().expect("forward registry poisoned");
            if let Some(rule) = forwards
                .iter_mut()
                .find(|rule| rule.local == canonical_local)
            {
                if no_rebind {
                    return Err(AdbError::Server(
                        "cannot rebind existing socket".to_string(),
                    ));
                }

                // AOSP 原地更新已有 listener，保持本地 socket/端口不变；接受下一条
                // 连接时从共享目标读取新的 transport 和 remote service。
                rule.serial = serial;
                rule.remote = remote.to_string();
                let mut target = rule.target.lock().expect("forward target poisoned");
                target.transport = transport;
                target.remote = remote.to_string();
                return Ok(None);
            }
        }

        let (listener, bound_local, resolved_port) = bind_forward_listener(local, self.listen_all)
            .map_err(|err| match err {
                AdbError::Io(err) => AdbError::Server(format!("cannot bind listener: {err}")),
                other => other,
            })?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let target = Arc::new(Mutex::new(ForwardTarget {
            transport: transport.clone(),
            remote: remote.to_string(),
        }));
        spawn_forward_listener(listener, Arc::clone(&shutdown), Arc::clone(&target));

        self.forwards
            .lock()
            .expect("forward registry poisoned")
            .push(ForwardRule {
                serial,
                local: bound_local,
                remote: remote.to_string(),
                shutdown,
                target,
            });

        Ok(resolved_port)
    }

    fn remove_forward(
        &self,
        serial: Option<&str>,
        local: &str,
        fail_if_missing: bool,
    ) -> Result<()> {
        let mut forwards = self.forwards.lock().expect("forward registry poisoned");
        let before = forwards.len();
        forwards.retain(|rule| {
            let matches_serial = serial.is_none_or(|serial| serial == rule.serial);
            let should_remove = matches_serial && rule.local == local;
            if should_remove {
                rule.shutdown.store(true, Ordering::SeqCst);
            }
            !should_remove
        });

        if fail_if_missing && before == forwards.len() {
            return Err(AdbError::Server(format!("listener '{local}' not found")));
        }
        Ok(())
    }

    fn remove_forwards_for_serials(&self, serials: &[String]) -> usize {
        if serials.is_empty() {
            return 0;
        }

        let mut forwards = self.forwards.lock().expect("forward registry poisoned");
        let before = forwards.len();
        forwards.retain(|rule| {
            let should_remove = serials.iter().any(|serial| serial == &rule.serial);
            if should_remove {
                rule.shutdown.store(true, Ordering::SeqCst);
            }
            !should_remove
        });
        before - forwards.len()
    }

    fn remove_all_forwards(&self) {
        let mut forwards = self.forwards.lock().expect("forward registry poisoned");
        for rule in forwards.iter() {
            rule.shutdown.store(true, Ordering::SeqCst);
        }
        forwards.clear();
    }

    fn serve_device_service(
        &self,
        selected: &TransportInfo,
        service: &str,
        mut client: ServerStream,
    ) -> Result<()> {
        let transport = self
            .transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .find(|transport| transport.info().id == selected.id)
            .cloned();
        let Some(transport) = transport else {
            protocol::write_fail(&mut client, "selected transport is no longer available")?;
            return Ok(());
        };

        transport.serve_service(service, client)
    }

    fn wait_for(
        &self,
        selector: HostSelector<'_>,
        spec: &str,
        shutdown: &AtomicBool,
    ) -> Result<()> {
        let spec = WaitSpec::parse(spec)?;
        let mut revision = self.device_revision();

        loop {
            match self.wait_spec_status(selector, &spec) {
                WaitStatus::Satisfied => return Ok(()),
                WaitStatus::Pending => {}
                WaitStatus::Ambiguous(reason) => return Err(AdbError::Server(reason)),
            }
            if shutdown.load(Ordering::SeqCst) {
                return Err(AdbError::Server("server shutting down".to_string()));
            }
            revision = self.wait_for_device_revision(revision, shutdown);
        }
    }

    #[cfg(test)]
    fn wait_spec_is_satisfied(&self, selector: HostSelector<'_>, spec: &WaitSpec) -> bool {
        self.wait_spec_status(selector, spec) == WaitStatus::Satisfied
    }

    fn wait_spec_status(&self, selector: HostSelector<'_>, spec: &WaitSpec) -> WaitStatus {
        self.remove_closed_transports();
        let candidates = self.wait_candidates(selector, spec.transport);

        if spec.states.contains(&WaitState::Disconnect) && candidates.is_empty() {
            return WaitStatus::Satisfied;
        }

        match candidates.as_slice() {
            [] => WaitStatus::Pending,
            [info] => {
                let active = info.is_wait_active();
                let disconnect_satisfied = spec.states.contains(&WaitState::Disconnect) && !active;
                let state_satisfied =
                    active && spec.states.iter().any(|state| state.matches(info.state));

                if disconnect_satisfied || state_satisfied {
                    WaitStatus::Satisfied
                } else {
                    WaitStatus::Pending
                }
            }
            _ => WaitStatus::Ambiguous(wait_ambiguous_message(selector, spec.transport)),
        }
    }

    fn wait_candidates(
        &self,
        selector: HostSelector<'_>,
        transport: WaitTransport,
    ) -> Vec<TransportInfo> {
        let mut candidates: Vec<_> = self
            .transports
            .lock()
            .expect("transport registry poisoned")
            .iter()
            .map(Transport::info)
            .filter(|info| info.state != ConnectionState::NoPermissions)
            .filter(|info| selector.matches_wait_target(info))
            .collect();
        if !matches!(
            selector,
            HostSelector::Serial(_) | HostSelector::TransportId(_)
        ) {
            candidates.retain(|info| transport.matches(info));
        }
        candidates
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WaitStatus {
    Satisfied,
    Pending,
    Ambiguous(String),
}

fn disconnect_target_serial(transports: &[Transport], target: &str) -> Result<String> {
    if let Some(info) = transports
        .iter()
        .map(Transport::info)
        .find(|info| transport_matches_target(info, target))
    {
        return Ok(info.serial);
    }

    let serial = parse_disconnect_target_serial(target)?;
    if transports
        .iter()
        .map(Transport::info)
        .any(|info| info.serial == serial)
    {
        Ok(serial)
    } else {
        Err(AdbError::Server(format!("no such device '{serial}'")))
    }
}

fn transport_matches_target(info: &TransportInfo, target: &str) -> bool {
    info.serial == target
        || info.devpath.as_deref() == Some(target)
        || transport_local_target_matches(info, target)
        || qualified_target_matches(target, "product:", info.product.as_deref(), false)
        || qualified_target_matches(target, "model:", info.model.as_deref(), true)
        || qualified_target_matches(target, "device:", info.device.as_deref(), false)
}

fn transport_local_target_matches(info: &TransportInfo, target: &str) -> bool {
    if !info.is_local_transport() {
        return false;
    }
    let target = target
        .strip_prefix("tcp:")
        .or_else(|| target.strip_prefix("udp:"))
        .unwrap_or(target);
    match transport::normalize_tcp_serial(target) {
        Ok(serial) => serial == info.serial,
        Err(_) => false,
    }
}

fn qualified_target_matches(
    target: &str,
    prefix: &str,
    value: Option<&str>,
    sanitize: bool,
) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(wanted) = target.strip_prefix(prefix) else {
        return false;
    };
    if sanitize {
        sanitize_qualifier_value(value) == wanted
    } else {
        value == wanted
    }
}

fn sanitize_qualifier_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn parse_disconnect_target_serial(target: &str) -> Result<String> {
    if target.starts_with("vsock:") || target.starts_with("localfilesystem:") {
        return Ok(target.to_string());
    }
    let target = target
        .strip_prefix("tcp:")
        .or_else(|| target.strip_prefix("udp:"))
        .unwrap_or(target);
    if target.trim().is_empty() {
        return Err(AdbError::Server(
            "couldn't parse '': empty address".to_string(),
        ));
    }
    if target.contains("://") {
        return Err(AdbError::Server(format!(
            "couldn't parse '{target}': unsupported scheme"
        )));
    }
    transport::normalize_tcp_serial(target)
        .map_err(|err| AdbError::Server(format!("couldn't parse '{target}': {err}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitTransport {
    Any,
    Usb,
    Local,
}

impl WaitTransport {
    fn matches(self, info: &TransportInfo) -> bool {
        match self {
            Self::Any => true,
            Self::Usb => info.is_usb_transport(),
            Self::Local => info.is_local_transport(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitState {
    Device,
    Recovery,
    Rescue,
    Sideload,
    Bootloader,
    Any,
    Disconnect,
}

impl WaitState {
    fn matches(self, state: ConnectionState) -> bool {
        match self {
            WaitState::Device => state == ConnectionState::Device,
            WaitState::Recovery => state == ConnectionState::Recovery,
            WaitState::Rescue => state == ConnectionState::Rescue,
            WaitState::Sideload => state == ConnectionState::Sideload,
            WaitState::Bootloader => state == ConnectionState::Bootloader,
            WaitState::Any => true,
            WaitState::Disconnect => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WaitSpec {
    transport: WaitTransport,
    states: Vec<WaitState>,
}

impl WaitSpec {
    fn parse(spec: &str) -> Result<Self> {
        let rest = spec
            .strip_prefix("wait-for-")
            .ok_or_else(|| AdbError::Server(format!("short wait-for-: {spec}")))?;
        let parts: Vec<_> = rest.split('-').collect();
        if parts.len() < 2 {
            return Err(AdbError::Server(format!("short wait-for-: {rest}")));
        }

        let transport = match parts[0] {
            "any" => WaitTransport::Any,
            "usb" => WaitTransport::Usb,
            "local" => WaitTransport::Local,
            _ => return Err(AdbError::Server(format!("bad wait-for- transport: {rest}"))),
        };

        let mut states = Vec::new();
        for part in parts.into_iter().skip(1) {
            states.push(match part {
                "device" => WaitState::Device,
                "recovery" => WaitState::Recovery,
                "rescue" => WaitState::Rescue,
                "sideload" => WaitState::Sideload,
                "bootloader" => WaitState::Bootloader,
                "any" => WaitState::Any,
                "disconnect" => WaitState::Disconnect,
                _ => return Err(AdbError::Server(format!("bad wait-for- state: {rest}"))),
            });
        }

        Ok(Self { transport, states })
    }
}

#[derive(Clone)]
struct ForwardRule {
    serial: String,
    local: String,
    remote: String,
    shutdown: Arc<AtomicBool>,
    target: Arc<Mutex<ForwardTarget>>,
}

struct ForwardTarget {
    transport: Transport,
    remote: String,
}

enum ForwardListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    UnixFilesystem {
        listener: std::os::unix::net::UnixListener,
        path: PathBuf,
    },
    #[cfg(target_os = "linux")]
    UnixAbstract(std::os::unix::net::UnixListener),
    #[cfg(target_os = "linux")]
    Vsock(VsockListener),
    #[cfg(unix)]
    Inherited(RawSocketListener),
}

impl ForwardListener {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::UnixFilesystem { listener, .. } => listener.set_nonblocking(nonblocking),
            #[cfg(target_os = "linux")]
            Self::UnixAbstract(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::Inherited(listener) => listener.set_nonblocking(nonblocking),
        }
    }
}

#[cfg(unix)]
struct RawSocketListener {
    fd: OwnedFd,
}

#[cfg(unix)]
impl RawSocketListener {
    fn duplicate_inherited(fd: u32) -> Result<Self> {
        let fd = i32::try_from(fd).map_err(|_| AdbError::Server("invalid fd".to_string()))?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(AdbError::Server(format!(
                "could not get flags of inherited fd {fd}: '{}'",
                io::Error::last_os_error()
            )));
        }
        if flags & libc::FD_CLOEXEC != 0 {
            return Err(AdbError::Server(format!(
                "fd {fd} was not inherited from parent"
            )));
        }

        let mut socket_type = 0_i32;
        let mut socket_type_size = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut socket_type_size,
            )
        } != 0
        {
            return Err(AdbError::Server(format!(
                "fd {fd} does not refer to a socket"
            )));
        }

        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(AdbError::Server(format!(
                "could not dup inherited fd {fd}: '{}'",
                io::Error::last_os_error()
            )));
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(duplicate) },
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn accept(&self) -> io::Result<ServerStream> {
        let fd = accept_inherited_socket(self.fd.as_raw_fd())?;
        Ok(ServerStream::from_raw_file(unsafe {
            std::fs::File::from_raw_fd(fd)
        }))
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn accept_inherited_socket(listener: i32) -> io::Result<i32> {
    let fd = unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn accept_inherited_socket(listener: i32) -> io::Result<i32> {
    let fd = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
struct VsockListener {
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl VsockListener {
    fn bind(port: u32) -> io::Result<(Self, u32)> {
        const VMADDR_CID_ANY: u32 = u32::MAX;
        const VMADDR_PORT_ANY: u32 = u32::MAX;

        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_port = if port == 0 { VMADDR_PORT_ANY } else { port };
        addr.svm_cid = VMADDR_CID_ANY;
        let len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;

        let bind_result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                len,
            )
        };
        if bind_result != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::listen(fd.as_raw_fd(), 4) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut resolved_addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut resolved_len = len;
        let getsockname_result = unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                &mut resolved_addr as *mut libc::sockaddr_vm as *mut libc::sockaddr,
                &mut resolved_len,
            )
        };
        if getsockname_result != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok((Self { fd }, resolved_addr.svm_port))
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, new_flags) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn accept(&self) -> io::Result<ServerStream> {
        let fd = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ServerStream::from_raw_file(unsafe {
            std::fs::File::from_raw_fd(fd)
        }))
    }
}

enum SmartSocketListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    UnixFilesystem(std::os::unix::net::UnixListener),
    #[cfg(target_os = "linux")]
    UnixAbstract(std::os::unix::net::UnixListener),
    #[cfg(target_os = "linux")]
    Vsock(VsockListener),
    #[cfg(unix)]
    Inherited(RawSocketListener),
}

impl SmartSocketListener {
    fn bind(endpoint: &ServerEndpoint) -> Result<Self> {
        match endpoint.socket_kind() {
            ServerSocketKind::Tcp => TcpListener::bind(endpoint.bind_address())
                .map(Self::Tcp)
                .map_err(Into::into),
            ServerSocketKind::LocalFilesystem { name, .. } => {
                #[cfg(unix)]
                {
                    match fs::remove_file(name) {
                        Ok(()) => {}
                        Err(err) if err.kind() == ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                    std::os::unix::net::UnixListener::bind(name)
                        .map(Self::UnixFilesystem)
                        .map_err(Into::into)
                }
                #[cfg(not(unix))]
                {
                    let _ = name;
                    Err(AdbError::Server(
                        "attempted to listen on unavailable socket type: localfilesystem"
                            .to_string(),
                    ))
                }
            }
            ServerSocketKind::LocalAbstract { name } => {
                #[cfg(target_os = "linux")]
                {
                    use std::os::linux::net::SocketAddrExt;

                    let address =
                        std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
                    std::os::unix::net::UnixListener::bind_addr(&address)
                        .map(Self::UnixAbstract)
                        .map_err(Into::into)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = name;
                    Err(AdbError::Server(
                        "attempted to listen on unavailable socket type: localabstract".to_string(),
                    ))
                }
            }
            ServerSocketKind::LocalReserved { .. } => Err(AdbError::Server(
                "attempted to listen on unavailable socket type: localreserved".to_string(),
            )),
            ServerSocketKind::Vsock { first, second } => {
                if second.is_some() {
                    return Err(AdbError::Server(
                        "given vsock server socket string was invalid".to_string(),
                    ));
                }
                #[cfg(target_os = "linux")]
                {
                    VsockListener::bind(*first)
                        .map(|(listener, _)| Self::Vsock(listener))
                        .map_err(Into::into)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = first;
                    Err(AdbError::Server(
                        "vsock is only supported on linux".to_string(),
                    ))
                }
            }
            ServerSocketKind::AcceptFd { fd } => {
                #[cfg(unix)]
                {
                    RawSocketListener::duplicate_inherited(*fd).map(Self::Inherited)
                }
                #[cfg(not(unix))]
                {
                    let _ = fd;
                    Err(AdbError::Server(
                        "socket activation not supported under Windows".to_string(),
                    ))
                }
            }
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::UnixFilesystem(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(target_os = "linux")]
            Self::UnixAbstract(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::Inherited(listener) => listener.set_nonblocking(nonblocking),
        }
    }

    fn accept(&self) -> io::Result<ServerStream> {
        match self {
            Self::Tcp(listener) => listener
                .accept()
                .map(|(stream, _)| ServerStream::Tcp(stream)),
            #[cfg(unix)]
            Self::UnixFilesystem(listener) => listener
                .accept()
                .map(|(stream, _)| ServerStream::Unix(stream)),
            #[cfg(target_os = "linux")]
            Self::UnixAbstract(listener) => listener
                .accept()
                .map(|(stream, _)| ServerStream::Unix(stream)),
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => listener.accept(),
            #[cfg(unix)]
            Self::Inherited(listener) => listener.accept(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Continue,
    Close,
}

pub fn run_foreground(config: ServerConfig) -> Result<()> {
    let socket_spec = config.endpoint.socket_spec();
    let daemon_child = config.ack_reply_fd.is_some();
    let listener = SmartSocketListener::bind(&config.endpoint)?;
    listener.set_nonblocking(true)?;
    if !daemon_child {
        eprintln!("* adb-rust server listening on {socket_spec} *");
    }

    if let Err(err) = usb::start_host_monitoring() {
        eprintln!("adb-rust USB host monitor unavailable: {err}");
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(ServerState::new_with_options(
        config.one_device.clone(),
        None,
        config.endpoint.listen_all(),
    ));
    let state_mdns = Arc::clone(&state);
    thread::spawn(move || state_mdns.start_mdns());

    // AOSP 在向 launch_server 回写 ACK 前完成一次本地 emulator/USB 扫描；这样
    // `start-server` 返回时，紧随其后的 `devices` 不会观察到尚未初始化的 registry。
    let _ = state.remove_closed_transports();
    let _ = state.scan_emulators_once();
    let _ = state.scan_usb_once();

    #[cfg(target_os = "linux")]
    if let Err(err) = write_server_executable_marker(&config.endpoint) {
        eprintln!("adb-rust 无法写入 server executable marker: {err}");
    }

    let accept_handle = spawn_accept_thread(listener, Arc::clone(&state), Arc::clone(&shutdown));
    if daemon_child {
        redirect_daemon_standard_streams()?;
    }
    transport::report_unknown_trace_flags();
    notify_server_startup(config.ack_reply_fd)?;
    spawn_transport_poll_thread(Arc::clone(&state), Arc::clone(&shutdown));
    spawn_tcp_reconnect_thread(Arc::clone(&state), Arc::clone(&shutdown));
    spawn_mdns_reconnect_thread(Arc::clone(&state), Arc::clone(&shutdown));
    while !shutdown.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
    let _ = accept_handle.join();
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_server_executable_marker(endpoint: &ServerEndpoint) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let Some(marker_path) = crate::client::server_executable_marker_path(endpoint)? else {
        return Ok(());
    };
    let executable = fs::read_link("/proc/self/exe")?;
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(marker_path, executable.as_os_str().as_bytes())?;
    Ok(())
}

fn notify_server_startup(ack_reply_fd: Option<u64>) -> Result<()> {
    if let Some(fd) = ack_reply_fd {
        write_server_startup_ack_to_fd(fd)?;
    }
    Ok(())
}

#[cfg(unix)]
fn redirect_daemon_standard_streams() -> Result<()> {
    use std::os::fd::AsRawFd;

    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(crate::server_status::log_absolute_path())?;
    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(log.as_raw_fd(), target) } < 0 {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
    }
    eprintln!("--- adb-rust starting (pid {}) ---", std::process::id());
    Ok(())
}

#[cfg(windows)]
fn redirect_daemon_standard_streams() -> Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
    };

    let stdout_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(crate::server_status::log_absolute_path())?;
    let stderr_log = stdout_log.try_clone()?;
    let stdout_handle = stdout_log.into_raw_handle() as HANDLE;
    let stderr_handle = stderr_log.into_raw_handle() as HANDLE;

    unsafe {
        let old_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        let old_stderr = GetStdHandle(STD_ERROR_HANDLE);
        if SetStdHandle(STD_OUTPUT_HANDLE, stdout_handle) == 0 {
            let err = io::Error::last_os_error();
            CloseHandle(stdout_handle);
            CloseHandle(stderr_handle);
            return Err(AdbError::Io(err));
        }
        if SetStdHandle(STD_ERROR_HANDLE, stderr_handle) == 0 {
            let err = io::Error::last_os_error();
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);
            CloseHandle(stdout_handle);
            CloseHandle(stderr_handle);
            return Err(AdbError::Io(err));
        }

        if !old_stdout.is_null()
            && old_stdout != INVALID_HANDLE_VALUE
            && old_stdout != stdout_handle
            && old_stdout != stderr_handle
        {
            CloseHandle(old_stdout);
        }
        if !old_stderr.is_null()
            && old_stderr != INVALID_HANDLE_VALUE
            && old_stderr != old_stdout
            && old_stderr != stdout_handle
            && old_stderr != stderr_handle
        {
            CloseHandle(old_stderr);
        }
        // 两个 raw handle 成为进程级标准句柄，保留到 server 退出。
    }
    eprintln!("--- adb-rust starting (pid {}) ---", std::process::id());
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn redirect_daemon_standard_streams() -> Result<()> {
    Ok(())
}

fn write_server_startup_ack<W: Write>(writer: &mut W) -> Result<()> {
    writer.write_all(b"OK\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
fn write_server_startup_ack_to_fd(fd: u64) -> Result<()> {
    use std::os::fd::FromRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
    write_server_startup_ack(&mut file)
}

#[cfg(windows)]
fn write_server_startup_ack_to_fd(raw_handle: u64) -> Result<()> {
    use std::os::windows::io::FromRawHandle;

    let handle = raw_handle as usize as std::os::windows::io::RawHandle;
    let mut file = unsafe { std::fs::File::from_raw_handle(handle) };
    write_server_startup_ack(&mut file)
}

#[cfg(not(any(unix, windows)))]
fn write_server_startup_ack_to_fd(_fd: u64) -> Result<()> {
    Err(AdbError::Unsupported(
        "fork-server --reply-fd 仅支持 Unix/Windows 平台".to_string(),
    ))
}

fn prepare_client_stream(stream: &ServerStream) -> Result<()> {
    stream.set_nonblocking(false)?;
    Ok(())
}

fn spawn_accept_thread(
    listener: SmartSocketListener,
    state: Arc<ServerState>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = accept_client_loop(listener, state, shutdown.clone()) {
            trace_server_error("accept", &err);
            shutdown.store(true, Ordering::SeqCst);
        }
    })
}

fn accept_client_loop(
    listener: SmartSocketListener,
    state: Arc<ServerState>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(stream) => {
                if let Err(err) = prepare_client_stream(&stream) {
                    trace_server_error("prepare_client_stream", &err);
                    continue;
                }
                let shutdown = Arc::clone(&shutdown);
                let state = Arc::clone(&state);
                let (first_service_tx, first_service_rx) = mpsc::channel();
                thread::spawn(move || {
                    if let Err(err) =
                        handle_client_with_gate(stream, state, shutdown, Some(first_service_tx))
                    {
                        trace_server_error("client", &err);
                    }
                });
                if matches!(
                    first_service_rx.recv_timeout(Duration::from_millis(250)),
                    Ok(FirstServiceGate::OrderedPending)
                ) {
                    let _ = first_service_rx.recv();
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => {
                // 瞬态 accept 错误（例如 Windows 上对端在 accept 完成前 RST 导致的
                // WSAECONNRESET）不得终止整个 server。accept 循环只有在 host:kill
                // 设置 shutdown 后才应退出，任何 accept 错误都只是记录并继续轮询。
                trace_server_error("accept", &AdbError::from(err));
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstServiceGate {
    Unordered,
    OrderedPending,
    OrderedDone,
}

fn first_service_requires_accept_order(service: &str) -> bool {
    split_host_prefixed_service(service).is_some_and(|(_, request)| {
        request.starts_with("forward:")
            || request.starts_with("killforward:")
            || request == "killforward-all"
    })
}

fn spawn_transport_poll_thread(state: Arc<ServerState>, shutdown: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut scan_tick = 0_u8;
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            let resumed = state.handle_usb_resume();
            let _ = state.remove_closed_transports();
            if resumed {
                scan_tick = 0;
                let _ = state.scan_usb_once();
                continue;
            }
            scan_tick = scan_tick.wrapping_add(1);
            if scan_tick == 10 {
                scan_tick = 0;
                let _ = state.scan_emulators_once();
                let _ = state.scan_usb_once();
            }
        }
    });
}

fn spawn_tcp_reconnect_thread(state: Arc<ServerState>, shutdown: Arc<AtomicBool>) {
    thread::spawn(move || {
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            state.process_tcp_reconnects();
        }
    });
}

fn spawn_mdns_reconnect_thread(state: Arc<ServerState>, shutdown: Arc<AtomicBool>) {
    thread::spawn(move || {
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            state.process_mdns_auto_connects();
        }
    });
}

fn handle_client_with_gate(
    mut stream: ServerStream,
    state: Arc<ServerState>,
    shutdown: Arc<AtomicBool>,
    first_service_gate: Option<mpsc::Sender<FirstServiceGate>>,
) -> Result<()> {
    let mut selected_transport: Option<TransportInfo> = None;
    let mut first_service_gate = first_service_gate;
    loop {
        let service = match protocol::read_protocol_string(&mut stream) {
            Ok(service) => service,
            Err(AdbError::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        trace_server_service(&service, selected_transport.as_ref());
        let ordered_first_service = first_service_gate
            .as_ref()
            .is_some_and(|_| first_service_requires_accept_order(&service));
        if let Some(gate) = first_service_gate.as_ref() {
            let state = if ordered_first_service {
                FirstServiceGate::OrderedPending
            } else {
                FirstServiceGate::Unordered
            };
            let _ = gate.send(state);
        }

        if let Some(selected) = selected_transport
            .as_ref()
            .filter(|_| !service.starts_with("host"))
        {
            trace_server_event(&format!(
                "serve device service serial={} id={} service={service:?}",
                selected.serial, selected.id
            ));
            let result = state.serve_device_service(selected, &service, stream);
            complete_first_service_gate(&mut first_service_gate, ordered_first_service);
            return result;
        }

        let action = handle_service(
            &mut stream,
            &service,
            Arc::clone(&state),
            Arc::clone(&shutdown),
            &mut selected_transport,
        );
        complete_first_service_gate(&mut first_service_gate, ordered_first_service);
        let action = action?;
        if action == ServiceAction::Close {
            return Ok(());
        }
    }
}

fn complete_first_service_gate(gate: &mut Option<mpsc::Sender<FirstServiceGate>>, ordered: bool) {
    if let Some(gate) = gate.take()
        && ordered
    {
        let _ = gate.send(FirstServiceGate::OrderedDone);
    }
}

fn trace_server_service(service: &str, selected: Option<&TransportInfo>) {
    if transport::trace_enabled("services") {
        let selected = selected
            .map(|info| format!(" selected={}#{}", info.serial, info.id))
            .unwrap_or_default();
        eprintln!("smart service {service:?}{selected}");
    }
}

fn trace_server_event(message: &str) {
    if transport::trace_enabled("adb") {
        eprintln!("smart {message}");
    }
}

fn trace_server_error(context: &str, err: &AdbError) {
    if transport::trace_enabled("adb") {
        eprintln!("smart {context} error: {err}");
    }
}

fn handle_service<W: std::io::Write>(
    stream: &mut W,
    service: &str,
    state: Arc<ServerState>,
    shutdown: Arc<AtomicBool>,
    selected_transport: &mut Option<TransportInfo>,
) -> Result<ServiceAction> {
    if selected_transport.is_some() && !service.starts_with("host") {
        protocol::write_fail(
            stream,
            "device services are not implemented in adb-rust server yet",
        )?;
        return Ok(ServiceAction::Close);
    }

    match service {
        "host:version" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(
                stream,
                &format!("{:04X}", protocol::ADB_SERVER_VERSION),
            )?;
            Ok(ServiceAction::Close)
        }
        "host:start-server" => {
            protocol::write_okay(stream)?;
            Ok(ServiceAction::Close)
        }
        "host:host-features" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &transport::host_features_string())?;
            Ok(ServiceAction::Close)
        }
        "host:features" if selected_transport.is_some() => {
            let info = selected_transport
                .as_ref()
                .expect("checked selected transport");
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &transport::transport_features(info))?;
            Ok(ServiceAction::Close)
        }
        service @ ("host:attach" | "host:detach") if selected_transport.is_some() => {
            let info = selected_transport
                .as_ref()
                .expect("checked selected transport");
            let result = if service.ends_with("attach") {
                state.attach_selected_transport(info)
            } else {
                state.detach_selected_transport(info)
            };
            write_protocol_string_result(stream, result)?;
            Ok(ServiceAction::Close)
        }
        "host:server-status" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_bytes(
                stream,
                &AdbServerStatus::current_with_mdns(state.is_mdns_enabled()).encode(),
            )?;
            Ok(ServiceAction::Close)
        }
        "host:mdns:check" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, mdns::check_message(state.is_mdns_enabled()))?;
            Ok(ServiceAction::Close)
        }
        "host:mdns:services" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(
                stream,
                &mdns::format_services(&state.mdns_services()),
            )?;
            Ok(ServiceAction::Close)
        }
        "host:kill" => {
            protocol::write_okay(stream)?;
            shutdown.store(true, Ordering::SeqCst);
            Ok(ServiceAction::Close)
        }
        "host:devices" | "host:devices-l" => {
            let long = service == "host:devices-l";
            let body = transport::format_devices(&state.list(), long);
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &body)?;
            Ok(ServiceAction::Close)
        }
        "host:track-devices" | "host:track-devices-l" => {
            let output = if service == "host:track-devices-l" {
                DeviceTrackerOutput::LongText
            } else {
                DeviceTrackerOutput::ShortText
            };
            protocol::write_okay(stream)?;
            track_devices(stream, &state, &shutdown, output)?;
            Ok(ServiceAction::Close)
        }
        "host:track-devices-proto-binary" => {
            protocol::write_okay(stream)?;
            track_devices(stream, &state, &shutdown, DeviceTrackerOutput::ProtoBinary)?;
            Ok(ServiceAction::Close)
        }
        "host:track-devices-proto-text" => {
            protocol::write_okay(stream)?;
            track_devices(stream, &state, &shutdown, DeviceTrackerOutput::ProtoText)?;
            Ok(ServiceAction::Close)
        }
        service if service.starts_with("host:tport:") => {
            let selector = service.trim_start_matches("host:tport:");
            let result = match selector {
                "any" => state.select_any(),
                "usb" => state.select_usb_rescan().map(|transport| transport.info()),
                "local" => state.select_local().map(|transport| transport.info()),
                serial if serial.starts_with("serial:") => {
                    state.select_serial(serial.trim_start_matches("serial:"))
                }
                _ => state.select_any(),
            };
            select_transport_with_id(stream, result, selected_transport)
        }
        "host:transport-any" => select_transport(stream, state.select_any(), selected_transport),
        "host:transport-usb" => select_transport(
            stream,
            state.select_usb_rescan().map(|t| t.info()),
            selected_transport,
        ),
        "host:transport-local" => select_transport(
            stream,
            state.select_local().map(|t| t.info()),
            selected_transport,
        ),
        service if service.starts_with("host:transport:") => {
            let serial = service.trim_start_matches("host:transport:");
            select_transport(stream, state.select_serial(serial), selected_transport)
        }
        service if service.starts_with("host:transport-id:") => {
            let id = parse_transport_id(service.trim_start_matches("host:transport-id:"))?;
            select_transport(stream, state.select_id(id), selected_transport)
        }
        service if service.starts_with("host:connect:") => {
            let target = service.trim_start_matches("host:connect:");
            let response = match state.connect_tcp(target) {
                Ok((info, true)) => format!("already connected to {}", info.serial),
                Ok((info, false)) => format!("connected to {}", info.serial),
                Err(err) => format!("failed to connect to {target}: {err}"),
            };
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &response)?;
            Ok(ServiceAction::Close)
        }
        service if service.starts_with("host:emulator:") => {
            // AOSP 对 `host:emulator:<port>` 不发送响应体，只返回 OKAY。
            let port_text = service.trim_start_matches("host:emulator:");
            if let Ok(adb_port) = port_text.parse::<u16>() {
                state.connect_emulator(adb_port);
            }
            protocol::write_okay(stream)?;
            Ok(ServiceAction::Close)
        }
        service if service.starts_with("host:pair:") => {
            write_pair_response(stream, service, &state)?;
            Ok(ServiceAction::Close)
        }
        service if service.starts_with("host:disconnect:") => {
            let target = service.trim_start_matches("host:disconnect:");
            write_disconnect_response(stream, state.disconnect(Some(target)))?;
            Ok(ServiceAction::Close)
        }
        "host:disconnect" => {
            write_disconnect_response(stream, state.disconnect(None))?;
            Ok(ServiceAction::Close)
        }
        "host:reconnect-offline" => {
            let response = state.reconnect_offline();
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &response)?;
            Ok(ServiceAction::Close)
        }
        "host:list-forward" => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &state.list_forwards())?;
            Ok(ServiceAction::Close)
        }
        "host:killforward-all" => {
            protocol::write_okay(stream)?;
            state.remove_all_forwards();
            protocol::write_okay(stream)?;
            Ok(ServiceAction::Close)
        }
        service => {
            match handle_host_prefixed_service(service, &state, &shutdown) {
                Ok(Some(response)) => {
                    write_host_response(stream, response)?;
                }
                Ok(None) => {
                    protocol::write_fail(stream, &format!("unknown host service: {service}"))?;
                }
                Err(AdbError::Server(reason)) => {
                    protocol::write_fail(stream, &reason)?;
                }
                Err(err) => return Err(err),
            }
            Ok(ServiceAction::Close)
        }
    }
}

fn write_host_response<W: std::io::Write>(stream: &mut W, response: HostResponse) -> Result<()> {
    protocol::write_okay(stream)?;
    match response {
        HostResponse::ProtocolString(value) => protocol::write_protocol_string(stream, &value),
        HostResponse::Status { resolved_port } => {
            protocol::write_okay(stream)?;
            if let Some(resolved_port) = resolved_port {
                protocol::write_protocol_string(stream, &resolved_port)?;
            }
            Ok(())
        }
    }
}

fn select_transport<W: std::io::Write>(
    stream: &mut W,
    result: Result<TransportInfo>,
    selected_transport: &mut Option<TransportInfo>,
) -> Result<ServiceAction> {
    match result {
        Ok(info) => {
            *selected_transport = Some(info);
            protocol::write_okay(stream)?;
            Ok(ServiceAction::Continue)
        }
        Err(AdbError::Server(reason)) => {
            protocol::write_fail(stream, &reason)?;
            Ok(ServiceAction::Close)
        }
        Err(err) => Err(err),
    }
}

fn select_transport_with_id<W: std::io::Write>(
    stream: &mut W,
    result: Result<TransportInfo>,
    selected_transport: &mut Option<TransportInfo>,
) -> Result<ServiceAction> {
    match result {
        Ok(info) => {
            let transport_id = info.id;
            *selected_transport = Some(info);
            protocol::write_okay(stream)?;
            stream.write_all(&transport_id.to_le_bytes())?;
            Ok(ServiceAction::Continue)
        }
        Err(AdbError::Server(reason)) => {
            protocol::write_fail(stream, &reason)?;
            Ok(ServiceAction::Close)
        }
        Err(err) => Err(err),
    }
}

fn track_devices<W: std::io::Write>(
    stream: &mut W,
    state: &ServerState,
    shutdown: &AtomicBool,
    output: DeviceTrackerOutput,
) -> Result<()> {
    let mut revision = state.device_revision();
    loop {
        write_device_tracker_snapshot(stream, &state.list(), output)?;
        let next_revision = state.wait_for_device_revision(revision, shutdown);
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        revision = next_revision;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceTrackerOutput {
    ShortText,
    LongText,
    ProtoBinary,
    ProtoText,
}

fn write_device_tracker_snapshot<W: std::io::Write>(
    stream: &mut W,
    devices: &[TransportInfo],
    output: DeviceTrackerOutput,
) -> Result<()> {
    match output {
        DeviceTrackerOutput::ShortText => {
            protocol::write_protocol_string(stream, &transport::format_devices(devices, false))
        }
        DeviceTrackerOutput::LongText => {
            protocol::write_protocol_string(stream, &transport::format_devices(devices, true))
        }
        DeviceTrackerOutput::ProtoBinary => {
            protocol::write_protocol_bytes(stream, &device_tracker::devices_proto_binary(devices))
        }
        DeviceTrackerOutput::ProtoText => {
            protocol::write_protocol_string(stream, &device_tracker::devices_proto_text(devices))
        }
    }
}

fn write_disconnect_response<W: std::io::Write>(
    stream: &mut W,
    result: Result<String>,
) -> Result<()> {
    write_protocol_string_result(stream, result)
}

fn write_pair_response<W: std::io::Write>(
    stream: &mut W,
    service: &str,
    state: &ServerState,
) -> Result<()> {
    let spec = service.trim_start_matches("host:pair:");
    let Some((password, host)) = spec.split_once(':') else {
        protocol::write_fail(stream, &format!("unknown host service 'pair:{spec}'"))?;
        return Ok(());
    };

    let response = pair_device_response(state, host, password);
    if response.starts_with("Successful") {
        protocol::write_okay(stream)?;
        protocol::write_protocol_string(stream, &response)?;
    } else {
        protocol::write_fail(stream, &response)?;
    }
    Ok(())
}

fn pair_device_response(state: &ServerState, host: &str, password: &str) -> String {
    let resolved_target = state.mdns_pairing_target(host);
    if resolved_target.is_none()
        && let Err(message) = validate_pair_host_port(host)
    {
        return message;
    }

    if password.is_empty() {
        return "Failed: unable to create pairing client.".to_string();
    }

    let auth_key = match AuthKey::load_default() {
        Ok(auth_key) => auth_key,
        Err(err) => {
            eprintln!("adb-rust pairing 无法加载 adbkey: {err}");
            return "Failed: unable to create pairing client.".to_string();
        }
    };
    let target = resolved_target.as_deref().unwrap_or(host);
    match pairing::pair_device(target, password, &auth_key) {
        Ok(result) => {
            if let Err(err) = pairing::record_known_host(&result.guid) {
                eprintln!("adb-rust pairing 无法写入 adb_known_hosts.pb: {err}");
            }
            if state.mdns_connect_target(&result.guid).is_some()
                && let Err(err) = state.connect_tcp(&result.guid)
            {
                eprintln!("adb-rust pairing 后自动连接失败: {err}");
            }
            format!("Successfully paired to {host} [guid={}]", result.guid)
        }
        Err(err) => {
            eprintln!("adb-rust pairing 失败: {err}");
            err.official_message().to_string()
        }
    }
}

fn validate_pair_host_port(host: &str) -> std::result::Result<(), String> {
    let port_text = pair_port_text(host).ok_or_else(|| {
        format!("Failed to parse address for pairing: missing port in address [{host}]")
    })?;
    match port_text.parse::<u32>() {
        Ok(1..=65535) => Ok(()),
        _ => Err(format!("Invalid port while parsing address [{host}]")),
    }
}

fn pair_port_text(host: &str) -> Option<&str> {
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let after_bracket = &rest[end + 1..];
        return after_bracket
            .strip_prefix(':')
            .filter(|port| !port.is_empty());
    }

    let (address, port) = host.rsplit_once(':')?;
    if address.is_empty() || port.is_empty() {
        return None;
    }
    Some(port)
}

fn write_protocol_string_result<W: std::io::Write>(
    stream: &mut W,
    result: Result<String>,
) -> Result<()> {
    match result {
        Ok(response) => {
            protocol::write_okay(stream)?;
            protocol::write_protocol_string(stream, &response)
        }
        Err(AdbError::Server(reason)) => {
            protocol::write_fail(stream, &reason)?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn handle_host_prefixed_service(
    service: &str,
    state: &ServerState,
    shutdown: &AtomicBool,
) -> Result<Option<HostResponse>> {
    let Some((selector, request)) = split_host_prefixed_service(service) else {
        return Ok(None);
    };

    let response = match request {
        "get-state" => {
            let info = state.select_info_for(selector)?;
            HostResponse::ProtocolString(info.state.as_adb().to_string())
        }
        "get-serialno" => {
            let info = state.select_info_for(selector)?;
            HostResponse::ProtocolString(info.serial)
        }
        "get-devpath" => {
            let info = state.select_info_for(selector)?;
            HostResponse::ProtocolString(info.devpath.unwrap_or_else(|| "unknown".to_string()))
        }
        "get-transport-id" => {
            let info = state.select_info_for(selector)?;
            HostResponse::ProtocolString(info.id.to_string())
        }
        "features" => {
            let info = state.select_info_for(selector)?;
            HostResponse::ProtocolString(transport::transport_features(&info))
        }
        "reconnect" => HostResponse::ProtocolString(state.reconnect_transport(selector)),
        "attach" => HostResponse::ProtocolString(state.attach_transport(selector)?),
        "detach" => HostResponse::ProtocolString(state.detach_transport(selector)?),
        request if request.starts_with("wait-for-") => {
            state.wait_for(selector, request, shutdown)?;
            HostResponse::Status {
                resolved_port: None,
            }
        }
        "list-forward" => HostResponse::ProtocolString(state.list_forwards()),
        request if request.starts_with("forward:norebind:") => {
            let spec = request.trim_start_matches("forward:norebind:");
            HostResponse::Status {
                resolved_port: state.install_forward(selector, spec, true)?,
            }
        }
        request if request.starts_with("forward:") => {
            let spec = request.trim_start_matches("forward:");
            HostResponse::Status {
                resolved_port: state.install_forward(selector, spec, false)?,
            }
        }
        request if request.starts_with("killforward:") => {
            let _transport = state.select_transport_for(selector)?;
            let local = parse_killforward_spec(request.trim_start_matches("killforward:"))?;
            state.remove_forward(None, local, true)?;
            HostResponse::Status {
                resolved_port: None,
            }
        }
        "killforward-all" => {
            state.remove_all_forwards();
            HostResponse::Status {
                resolved_port: None,
            }
        }
        _ => return Ok(None),
    };

    Ok(Some(response))
}

fn attach_detach_unsupported_message(service: &str) -> &'static str {
    if service.ends_with("detach") {
        "attach/detach not supported!"
    } else {
        "attach/detach not supported"
    }
}

fn transport_supports_detach(info: &TransportInfo) -> bool {
    info.is_usb_transport()
        && info
            .devpath
            .as_deref()
            .is_some_and(|devpath| !devpath.starts_with("usb:winapi:"))
}

fn usb_interface_supports_detach(interface: &usb::UsbAdbInterface) -> bool {
    matches!(interface.backend, usb::UsbInterfaceBackend::Libusb)
}

fn detached_usb_transport_from_interface(
    id: u64,
    interface: &usb::UsbAdbInterface,
    serial: String,
) -> Transport {
    Transport::detached(TransportInfo {
        id,
        serial,
        devpath: Some(interface.bus_address.clone()),
        connection_type: transport::TransportConnectionType::Usb,
        negotiated_speed_mbps: interface.negotiated_speed_mbps,
        max_speed_mbps: interface.max_speed_mbps,
        state: ConnectionState::Detached,
        product: None,
        model: None,
        device: None,
        features: None,
        max_payload: protocol::MAX_PAYLOAD,
        protocol_version: protocol::A_VERSION,
    })
}

fn no_permissions_usb_transport_from_interface(
    id: u64,
    interface: &usb::UsbAdbInterface,
    serial: String,
) -> Transport {
    Transport::no_permissions(TransportInfo {
        id,
        serial,
        devpath: Some(interface.bus_address.clone()),
        connection_type: transport::TransportConnectionType::Usb,
        negotiated_speed_mbps: interface.negotiated_speed_mbps,
        max_speed_mbps: interface.max_speed_mbps,
        state: ConnectionState::NoPermissions,
        product: None,
        model: None,
        device: None,
        features: None,
        max_payload: protocol::MAX_PAYLOAD,
        protocol_version: protocol::A_VERSION,
    })
}

fn no_permissions_selection_error(transports: &[Transport]) -> Option<AdbError> {
    transports
        .iter()
        .any(|transport| transport.info().state == ConnectionState::NoPermissions)
        .then(|| AdbError::Server(usb::no_permissions_long_help_text()))
}

fn validate_selected_info(info: TransportInfo, accept_any_state: bool) -> Result<TransportInfo> {
    if accept_any_state {
        return Ok(info);
    }
    if let Some(reason) = selected_transport_state_error(info.state) {
        return Err(AdbError::Server(reason));
    }
    Ok(info)
}

fn validate_selected_transport(transport: Transport, accept_any_state: bool) -> Result<Transport> {
    validate_selected_info(transport.info(), accept_any_state)?;
    Ok(transport)
}

fn selected_transport_state_error(state: ConnectionState) -> Option<String> {
    match state {
        ConnectionState::Authorizing => Some("device still authorizing".to_string()),
        ConnectionState::Unauthorized => Some(unauthorized_selection_message(
            std::env::var_os("ADB_VENDOR_KEYS").as_deref(),
        )),
        ConnectionState::Offline => Some("device offline".to_string()),
        ConnectionState::NoPermissions => Some(usb::no_permissions_long_help_text()),
        _ => None,
    }
}

fn unauthorized_selection_message(vendor_keys: Option<&std::ffi::OsStr>) -> String {
    let vendor_keys = vendor_keys
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "not set".to_string());
    format!(
        "device unauthorized.\n\
This adb server's $ADB_VENDOR_KEYS is {vendor_keys}\n\
Try 'adb kill-server' if that seems wrong.\n\
Otherwise check for a confirmation dialog on your device."
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostResponse {
    ProtocolString(String),
    Status { resolved_port: Option<String> },
}

#[derive(Debug, Clone, Copy)]
enum HostSelector<'a> {
    Any,
    Serial(&'a str),
    TransportId(u64),
    Usb,
    Local,
}

impl HostSelector<'_> {
    fn matches_wait_target(self, info: &TransportInfo) -> bool {
        match self {
            Self::Any | Self::Usb | Self::Local => true,
            Self::Serial(serial) => transport_matches_target(info, serial),
            Self::TransportId(id) => info.id == id,
        }
    }
}

fn wait_ambiguous_message(selector: HostSelector<'_>, transport: WaitTransport) -> String {
    match selector {
        HostSelector::Serial(serial) => format!("more than one device with serial {serial}"),
        HostSelector::Any
        | HostSelector::TransportId(_)
        | HostSelector::Usb
        | HostSelector::Local => match transport {
            WaitTransport::Any => "more than one device/emulator".to_string(),
            WaitTransport::Usb => "more than one USB device".to_string(),
            WaitTransport::Local => "more than one emulator".to_string(),
        },
    }
}

fn usb_selection_message() -> String {
    match usb::list_adb_interfaces() {
        Ok(interfaces) if interfaces.is_empty() => "no USB devices found".to_string(),
        Ok(interfaces) => format!(
            "USB ADB interface found but no USB transport is registered yet: {}",
            interfaces[0].short_description()
        ),
        Err(err) => format!("no USB devices found ({err})"),
    }
}

fn split_host_prefixed_service(service: &str) -> Option<(HostSelector<'_>, &str)> {
    if let Some(request) = service.strip_prefix("host:") {
        return Some((HostSelector::Any, request));
    }
    if let Some(request) = service.strip_prefix("host-usb:") {
        return Some((HostSelector::Usb, request));
    }
    if let Some(request) = service.strip_prefix("host-local:") {
        return Some((HostSelector::Local, request));
    }
    if let Some(rest) = service.strip_prefix("host-serial:") {
        let (serial, request) = split_serial_prefixed_request(rest)?;
        return Some((HostSelector::Serial(serial), request));
    }
    if let Some(rest) = service.strip_prefix("host-transport-id:") {
        let (id, request) = rest.split_once(':')?;
        return Some((
            HostSelector::TransportId(parse_transport_id(id).ok()?),
            request,
        ));
    }
    None
}

fn split_serial_prefixed_request(rest: &str) -> Option<(&str, &str)> {
    const REQUEST_MARKERS: &[&str] = &[
        ":forward:norebind:",
        ":forward:",
        ":killforward:",
        ":wait-for-",
        ":get-transport-id",
        ":get-serialno",
        ":get-devpath",
        ":get-state",
        ":list-forward",
        ":killforward-all",
        ":features",
        ":reconnect",
        ":attach",
        ":detach",
    ];

    REQUEST_MARKERS.iter().find_map(|marker| {
        let index = rest.find(marker)?;
        (index > 0).then(|| (&rest[..index], &rest[index + 1..]))
    })
}

fn emulator_scan_ports() -> Vec<u16> {
    let max_port = emulator_max_port_from_env_value(
        std::env::var("ADB_LOCAL_TRANSPORT_MAX_PORT")
            .ok()
            .as_deref(),
    );
    if max_port < DEFAULT_ADB_LOCAL_TRANSPORT_PORT {
        return Vec::new();
    }

    (DEFAULT_ADB_LOCAL_TRANSPORT_PORT..=max_port)
        .step_by(2)
        .collect()
}

fn emulator_max_port_from_env_value(value: Option<&str>) -> u16 {
    value
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_ADB_LOCAL_TRANSPORT_MAX_PORT)
}

fn emulator_serial_for_adb_port(adb_port: u16) -> String {
    format!("emulator-{}", adb_port.saturating_sub(1))
}

fn parse_transport_id(value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| AdbError::Server(format!("invalid transport id: {value}")))
}

fn parse_forward_spec(spec: &str) -> Result<(&str, &str)> {
    let mut pieces = spec.split(';');
    let local = pieces.next().unwrap_or_default();
    let remote = pieces.next().unwrap_or_default();
    let has_extra = pieces.next().is_some();

    if local.is_empty() || remote.is_empty() || remote.starts_with('*') {
        return Err(AdbError::Server(format!("bad forward: {spec}")));
    }
    if has_extra {
        return Err(AdbError::Server(format!("bad forward: {spec}")));
    }
    Ok((local, remote))
}

fn parse_killforward_spec(spec: &str) -> Result<&str> {
    let mut pieces = spec.split(';');
    let local = pieces.next().unwrap_or_default();
    if local.is_empty() || pieces.next().is_some() {
        return Err(AdbError::Server(format!("bad killforward: {spec}")));
    }
    Ok(local)
}

fn canonical_forward_local(local: &str) -> Result<String> {
    if let Some(port) = local.strip_prefix("tcp:") {
        parse_forward_port(port)?;
        return Ok(format!("tcp:{port}"));
    }

    if let Some(path) = local.strip_prefix("local:") {
        validate_forward_filesystem_path(path)?;
        return Ok(format!("local:{path}"));
    }

    if let Some(path) = local.strip_prefix("localfilesystem:") {
        validate_forward_filesystem_path(path)?;
        return Ok(format!("localfilesystem:{path}"));
    }

    if let Some(name) = local.strip_prefix("localabstract:") {
        validate_forward_abstract_name(name)?;
        return Ok(format!("localabstract:{name}"));
    }

    if let Some(port) = local.strip_prefix("vsock:") {
        let port = parse_forward_vsock_port(port)?;
        return Ok(format!("vsock:{port}"));
    }

    if let Some(fd) = local.strip_prefix("acceptfd:") {
        let fd = parse_forward_accept_fd(fd)?;
        return Ok(format!("acceptfd:{fd}"));
    }

    if local.starts_with("localreserved:") {
        return Err(AdbError::Server(format!(
            "attempted to listen on unavailable socket type: {local}"
        )));
    }

    Err(AdbError::Server(format!(
        "unknown socket specification:{local}"
    )))
}

fn bind_forward_listener(
    local: &str,
    listen_all: bool,
) -> Result<(ForwardListener, String, Option<String>)> {
    if let Some(port_text) = local.strip_prefix("tcp:") {
        let requested_port = parse_forward_port(port_text)?;
        let address = SocketAddrV4::new(
            if listen_all {
                Ipv4Addr::UNSPECIFIED
            } else {
                Ipv4Addr::LOCALHOST
            },
            requested_port,
        );
        let listener = TcpListener::bind(address)?;
        let actual_port = listener.local_addr()?.port();
        let resolved_port = (requested_port == 0).then(|| actual_port.to_string());
        return Ok((
            ForwardListener::Tcp(listener),
            format!("tcp:{actual_port}"),
            resolved_port,
        ));
    }

    if let Some(path) = local.strip_prefix("local:") {
        return bind_forward_filesystem_listener(path, true);
    }

    if let Some(path) = local.strip_prefix("localfilesystem:") {
        return bind_forward_filesystem_listener(path, false);
    }

    if let Some(name) = local.strip_prefix("localabstract:") {
        return bind_forward_abstract_listener(name);
    }

    if let Some(port) = local.strip_prefix("vsock:") {
        return bind_forward_vsock_listener(port);
    }

    if let Some(fd) = local.strip_prefix("acceptfd:") {
        return bind_forward_inherited_listener(fd);
    }

    Err(AdbError::Server(format!(
        "unknown socket specification:{local}"
    )))
}

fn parse_forward_port(value: &str) -> Result<u16> {
    value
        .parse()
        .map_err(|_| AdbError::Server(format!("bad tcp port: {value}")))
}

fn parse_forward_vsock_port(value: &str) -> Result<u32> {
    if value.contains(':') {
        return Err(AdbError::Server(
            "given vsock server socket string was invalid".to_string(),
        ));
    }
    let port: i32 = value
        .parse()
        .map_err(|_| AdbError::Server("could not parse vsock port".to_string()))?;
    if port < 0 {
        return Err(AdbError::Server("vsock port was negative.".to_string()));
    }
    Ok(port as u32)
}

fn parse_forward_accept_fd(value: &str) -> Result<u32> {
    let fd: u32 = value
        .parse()
        .map_err(|_| AdbError::Server("invalid fd".to_string()))?;
    if fd > i32::MAX as u32 {
        return Err(AdbError::Server("invalid fd".to_string()));
    }
    Ok(fd)
}

fn validate_forward_filesystem_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(AdbError::Server("bad localfilesystem path".to_string()));
    }
    if path.as_bytes().contains(&0) {
        return Err(AdbError::Server(
            "bad localfilesystem path: contains NUL".to_string(),
        ));
    }
    Ok(())
}

fn validate_forward_abstract_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(AdbError::Server("bad localabstract name".to_string()));
    }
    if name.as_bytes().contains(&0) {
        return Err(AdbError::Server(
            "bad localabstract name: contains NUL".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn bind_forward_filesystem_listener(
    path: &str,
    alias: bool,
) -> Result<(ForwardListener, String, Option<String>)> {
    validate_forward_filesystem_path(path)?;
    let path = PathBuf::from(path);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    Ok((
        ForwardListener::UnixFilesystem {
            listener,
            path: path.clone(),
        },
        format!(
            "{}:{}",
            if alias { "local" } else { "localfilesystem" },
            path.display()
        ),
        None,
    ))
}

#[cfg(not(unix))]
fn bind_forward_filesystem_listener(
    path: &str,
    alias: bool,
) -> Result<(ForwardListener, String, Option<String>)> {
    Err(AdbError::Server(format!(
        "attempted to listen on unavailable socket type: {}:{path}",
        if alias { "local" } else { "localfilesystem" }
    )))
}

#[cfg(unix)]
fn bind_forward_inherited_listener(fd: &str) -> Result<(ForwardListener, String, Option<String>)> {
    let fd = parse_forward_accept_fd(fd)?;
    let listener = RawSocketListener::duplicate_inherited(fd)?;
    Ok((
        ForwardListener::Inherited(listener),
        format!("acceptfd:{fd}"),
        None,
    ))
}

#[cfg(not(unix))]
fn bind_forward_inherited_listener(fd: &str) -> Result<(ForwardListener, String, Option<String>)> {
    let _ = parse_forward_accept_fd(fd)?;
    Err(AdbError::Server(
        "socket activation not supported under Windows".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn bind_forward_abstract_listener(name: &str) -> Result<(ForwardListener, String, Option<String>)> {
    use std::os::linux::net::SocketAddrExt;

    validate_forward_abstract_name(name)?;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    Ok((
        ForwardListener::UnixAbstract(listener),
        format!("localabstract:{name}"),
        None,
    ))
}

#[cfg(not(target_os = "linux"))]
fn bind_forward_abstract_listener(name: &str) -> Result<(ForwardListener, String, Option<String>)> {
    Err(AdbError::Server(format!(
        "attempted to listen on unavailable socket type: localabstract:{name}"
    )))
}

#[cfg(target_os = "linux")]
fn bind_forward_vsock_listener(
    port_text: &str,
) -> Result<(ForwardListener, String, Option<String>)> {
    let requested_port = parse_forward_vsock_port(port_text)?;
    let (listener, actual_port) = VsockListener::bind(requested_port)?;
    let resolved_port = (requested_port == 0).then(|| actual_port.to_string());
    Ok((
        ForwardListener::Vsock(listener),
        format!("vsock:{actual_port}"),
        resolved_port,
    ))
}

#[cfg(not(target_os = "linux"))]
fn bind_forward_vsock_listener(
    port_text: &str,
) -> Result<(ForwardListener, String, Option<String>)> {
    let _ = parse_forward_vsock_port(port_text)?;
    Err(AdbError::Server(
        "vsock is only supported on linux".to_string(),
    ))
}

fn spawn_forward_listener(
    listener: ForwardListener,
    shutdown: Arc<AtomicBool>,
    target: Arc<Mutex<ForwardTarget>>,
) {
    thread::spawn(move || match listener {
        ForwardListener::Tcp(listener) => {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _peer)) => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        if prepare_forward_tcp_client(&client).is_err() {
                            continue;
                        }
                        serve_forward_client_from_target(&target, client);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        }
        #[cfg(unix)]
        ForwardListener::UnixFilesystem { listener, path } => {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _peer)) => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        if client.set_nonblocking(false).is_err() {
                            continue;
                        }
                        serve_forward_client_from_target(&target, client);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
            let _ = fs::remove_file(path);
        }
        #[cfg(target_os = "linux")]
        ForwardListener::UnixAbstract(listener) => {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _peer)) => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        if client.set_nonblocking(false).is_err() {
                            continue;
                        }
                        serve_forward_client_from_target(&target, client);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        }
        #[cfg(target_os = "linux")]
        ForwardListener::Vsock(listener) => {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(client) => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        if client.set_nonblocking(false).is_err() {
                            continue;
                        }
                        serve_forward_client_from_target(&target, client);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        }
        #[cfg(unix)]
        ForwardListener::Inherited(listener) => {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(client) => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        if client.set_nonblocking(false).is_err() {
                            continue;
                        }
                        serve_forward_client_from_target(&target, client);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        }
    });
}

fn prepare_forward_tcp_client(client: &TcpStream) -> io::Result<()> {
    client.set_nonblocking(false)?;
    client.set_nodelay(true)
}

fn serve_forward_client<S>(transport: Transport, remote: String, client: S)
where
    S: transport::ClientStream,
{
    thread::spawn(move || {
        let _ = transport.serve_raw_service(&remote, client);
    });
}

fn serve_forward_client_from_target<S>(target: &Arc<Mutex<ForwardTarget>>, client: S)
where
    S: transport::ClientStream,
{
    let (transport, remote) = {
        let target = target.lock().expect("forward target poisoned");
        (target.transport.clone(), target.remote.clone())
    };
    serve_forward_client(transport, remote, client);
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;

    use crate::client::{self, TransportSelector};
    use crate::protocol::AdbMessage;
    use crate::test_adbd::StubAdbd;
    use crate::test_sync_adbd::StubSyncFs;
    use crate::transport::{ConnectionState, TransportConnectionType};

    use super::*;

    fn test_state() -> Arc<ServerState> {
        test_state_with_mdns(mdns::DiscoveryState::disabled())
    }

    fn test_one_device_state(one_device: &str) -> Arc<ServerState> {
        Arc::new(ServerState::new_with_mdns(
            Some(one_device.to_string()),
            Some(mdns::DiscoveryState::disabled()),
        ))
    }

    fn test_state_with_mdns(mdns: mdns::DiscoveryState) -> Arc<ServerState> {
        Arc::new(ServerState::new_with_mdns(None, Some(mdns)))
    }

    fn spawn_test_server(
        state: Arc<ServerState>,
        connections: usize,
    ) -> (
        client::ServerEndpoint,
        thread::JoinHandle<()>,
        Arc<AtomicBool>,
        Arc<ServerState>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = client::ServerEndpoint::new("127.0.0.1", addr.port());
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            let state = Arc::clone(&state);
            thread::spawn(move || {
                let _ = listener.set_nonblocking(true);
                let mut handled = 0_usize;
                loop {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let stream = ServerStream::Tcp(stream);
                            if handled < connections
                                && prepare_client_stream(&stream).is_ok()
                                && handle_client_with_gate(
                                    stream,
                                    Arc::clone(&state),
                                    Arc::clone(&shutdown),
                                    None,
                                )
                                .is_ok()
                            {
                                handled += 1;
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => continue,
                    }
                }
            })
        };
        (endpoint, handle, shutdown, state)
    }

    fn read_stream_payload(
        stream: &mut TcpStream,
        host_id: u32,
        device_id: u32,
        min_len: usize,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        while payload.len() < min_len {
            let packet = protocol::AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(packet.command, protocol::A_WRTE);
            assert_eq!(packet.arg0, host_id);
            assert_eq!(packet.arg1, device_id);
            payload.extend_from_slice(&packet.payload);
            protocol::AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        }
        payload
    }

    #[test]
    fn accepted_client_stream_is_restored_to_blocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            thread::sleep(Duration::from_millis(50));
            protocol::write_protocol_string(&mut stream, "host:version").unwrap();
        });

        let (server_stream, _) = listener.accept().unwrap();
        server_stream.set_nonblocking(true).unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut server_stream = ServerStream::Tcp(server_stream);
        prepare_client_stream(&server_stream).unwrap();

        assert_eq!(
            protocol::read_protocol_string(&mut server_stream).unwrap(),
            "host:version"
        );
        writer.join().unwrap();
    }

    #[test]
    fn legacy_forward_is_visible_to_next_accepted_client() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let accept = spawn_accept_thread(
            SmartSocketListener::Tcp(listener),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let mut legacy = TcpStream::connect(address).unwrap();
        protocol::write_protocol_string(&mut legacy, "host-serial:serial-1:forward:tcp:0;tcp:6655")
            .unwrap();
        drop(legacy);

        let endpoint = client::ServerEndpoint::new("127.0.0.1", address.port());
        let listing = client::query(&endpoint, "host:list-forward").unwrap();
        assert!(listing.contains("tcp:6655"));

        state.remove_all_forwards();
        shutdown.store(true, Ordering::SeqCst);
        accept.join().unwrap();
    }

    #[test]
    fn legacy_forward_mutations_require_accept_order() {
        assert!(first_service_requires_accept_order(
            "host-serial:serial-1:forward:tcp:0;tcp:6655"
        ));
        assert!(first_service_requires_accept_order(
            "host-transport-id:7:killforward:tcp:6655"
        ));
        assert!(first_service_requires_accept_order(
            "host-usb:killforward-all"
        ));
        assert!(!first_service_requires_accept_order("host:list-forward"));
        assert!(!first_service_requires_accept_order("host:devices"));
    }

    #[test]
    fn accepted_forward_tcp_stream_waits_for_delayed_input() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            thread::sleep(Duration::from_millis(50));
            stream.write_all(b"forwarded").unwrap();
        });

        let (mut accepted, _) = listener.accept().unwrap();
        accepted.set_nonblocking(true).unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        prepare_forward_tcp_client(&accepted).unwrap();

        let mut received = [0_u8; 9];
        accepted.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"forwarded");
        writer.join().unwrap();
    }

    #[test]
    fn client_server_path_connects_stub_adbd_and_opens_device_service() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |stream| {
            let open = protocol::AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"shell:stub\0");
            let host_id = open.arg0;
            let device_id = 91;

            protocol::AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            protocol::AdbMessage::new(protocol::A_WRTE, device_id, host_id, b"stub\n".to_vec())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            let ack = protocol::AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);
            assert_eq!(ack.arg0, host_id);
            assert_eq!(ack.arg1, device_id);
            protocol::AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            // Keep the underlying TCP connection alive briefly so the client
            // side of `shell:stub` can finish reading after `A_CLSE`.
            thread::sleep(Duration::from_millis(50));
        });
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("already connected to {target}"));

        let mut stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target),
            "shell:stub",
        )
        .unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(out, b"stub\n");
    }

    #[test]
    fn connect_service_resolves_mdns_instance_name() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |_stream| {
            // 保持连接短暂存活，让 host:connect 完成注册。
            thread::sleep(Duration::from_millis(100));
        });
        let target = adbd.target();
        let (address, port) = target.rsplit_once(':').unwrap();
        let port = port.parse::<u16>().unwrap();

        let mdns = mdns::DiscoveryState::disabled();
        mdns.replace_services_for_test(vec![mdns::ServiceInfo::new(
            "fake-mdns-device",
            "_adb-tls-connect._tcp",
            address,
            port,
        )]);

        let (endpoint, server, shutdown, state) = spawn_test_server(test_state_with_mdns(mdns), 1);

        let response = client::query(&endpoint, "host:connect:fake-mdns-device").unwrap();
        assert_eq!(
            response,
            "connected to fake-mdns-device._adb-tls-connect._tcp"
        );
        let transports = state.list();
        assert_eq!(transports.len(), 1, "expected one registered transport");
        assert_eq!(
            transports[0].serial,
            "fake-mdns-device._adb-tls-connect._tcp"
        );

        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        adbd.join();
    }

    #[test]
    fn emulator_service_registers_emulator_transport_without_response_body() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |_stream| {
            thread::sleep(Duration::from_millis(100));
        });
        let target = adbd.target();
        let adb_port = target.rsplit_once(':').unwrap().1.parse::<u16>().unwrap();
        let expected_serial = emulator_serial_for_adb_port(adb_port);

        let (endpoint, server, shutdown, state) = spawn_test_server(test_state(), 1);

        // `host:emulator:<port>` 只返回 OKAY，没有协议字符串响应体。
        let mut stream = client::connect(&endpoint).unwrap();
        protocol::write_protocol_string(&mut stream, &format!("host:emulator:{adb_port}")).unwrap();
        protocol::read_status(&mut stream).unwrap();

        // 稍等 transport 注册完成。
        for _ in 0..30 {
            if state
                .list()
                .iter()
                .any(|info| info.serial == expected_serial)
            {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let list = state.list();
        assert_eq!(list.len(), 1, "expected one registered transport");
        assert_eq!(list[0].serial, expected_serial);

        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        adbd.join();
    }

    #[test]
    fn client_server_sync_path_sends_quit_to_stub_adbd() {
        let adbd = StubAdbd::spawn(b"device::features=;".to_vec(), |stream| {
            let open = protocol::AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"sync:\0");
            let host_id = open.arg0;
            let device_id = 91;

            protocol::AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

            let list = read_stream_payload(stream, host_id, device_id, 8 + "/data/local/tmp".len());
            assert_eq!(&list[..4], b"LIST");
            assert_eq!(&list[8..], b"/data/local/tmp");

            let mut response = Vec::new();
            response.extend_from_slice(b"DENT");
            response.extend_from_slice(&(0o100644_u32).to_le_bytes());
            response.extend_from_slice(&4_u32.to_le_bytes());
            response.extend_from_slice(&123_u32.to_le_bytes());
            response.extend_from_slice(&8_u32.to_le_bytes());
            response.extend_from_slice(b"stub.txt");
            response.extend_from_slice(b"DONE");
            response.extend_from_slice(&0_u32.to_le_bytes());
            response.extend_from_slice(&0_u32.to_le_bytes());
            response.extend_from_slice(&0_u32.to_le_bytes());
            response.extend_from_slice(&0_u32.to_le_bytes());
            protocol::AdbMessage::new(protocol::A_WRTE, device_id, host_id, response)
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            let ack = protocol::AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(ack.command, protocol::A_OKAY);

            let quit = read_stream_payload(stream, host_id, device_id, 8);
            assert_eq!(&quit[..8], b"QUIT\0\0\0\0");
            protocol::AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        });
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let entries = crate::sync::ls(
            &endpoint,
            &TransportSelector::Serial(target),
            "/data/local/tmp",
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("stub.txt"));
    }

    #[test]
    fn client_server_sync_stub_lists_directory_v1() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/a.txt", b"a", 0o644)
            .file("/data/local/tmp/b.txt", b"bb", 0o600)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let entries = crate::sync::ls(
            &endpoint,
            &TransportSelector::Serial(target),
            "/data/local/tmp",
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_deref(), Some("a.txt"));
        assert_eq!(entries[0].size, 1);
        assert_eq!(entries[1].name.as_deref(), Some("b.txt"));
        assert_eq!(entries[1].size, 2);
    }

    #[test]
    fn client_server_sync_stub_stat_and_recv_v1() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/stub.txt", b"hello sync", 0o644)
            .with_mtime("/data/local/tmp/stub.txt", 1_700_000_001)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let selector = TransportSelector::Serial(target);
        let mut sync = crate::sync::SyncClient::connect(&endpoint, &selector).unwrap();
        let entry = sync
            .stat("/data/local/tmp/stub.txt")
            .unwrap()
            .expect("stat 应返回文件");
        assert_eq!(entry.size, 10);
        assert_eq!(entry.mtime, 1_700_000_001);

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_recv_v1_{}_{}",
            std::process::id(),
            stamp
        ));
        let summary = sync
            .recv_file(
                "/data/local/tmp/stub.txt",
                &local,
                &entry,
                crate::sync::PullOptions::default(),
                &mut crate::sync::NoProgress,
            )
            .unwrap();
        drop(sync);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 10);
        assert_eq!(std::fs::read(&local).unwrap(), b"hello sync");
        let _ = std::fs::remove_file(&local);
    }

    #[test]
    fn client_server_sync_stub_lists_directory_v2() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/x.txt", b"xxx", 0o644)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let entries = crate::sync::ls(
            &endpoint,
            &TransportSelector::Serial(target),
            "/data/local/tmp",
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("x.txt"));
        assert_eq!(entries[0].size, 3);
        assert!(entries[0].attrs.is_some());
    }

    #[test]
    fn client_server_sync_stub_pull_v1() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/pull.txt", b"pulled content", 0o644)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_v1_{}_{}",
            std::process::id(),
            stamp
        ));
        let summary = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/pull.txt".to_string()],
            &local,
            crate::sync::PullOptions::default(),
            None,
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 14);
        assert_eq!(std::fs::read(&local).unwrap(), b"pulled content");
        let _ = std::fs::remove_file(&local);
    }

    #[test]
    fn client_server_sync_stub_push_v1() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_v1_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local_dir).unwrap();
        let local = local_dir.join("push.txt");
        std::fs::write(&local, b"pushed content").unwrap();

        let adbd = StubSyncFs::new().dir("/data/local/tmp", 0o755).spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let selector = TransportSelector::Serial(target);
        let mut sync = crate::sync::SyncClient::connect(&endpoint, &selector).unwrap();
        let summary = sync
            .send_file(
                &local,
                "/data/local/tmp/push.txt",
                crate::sync::PushOptions::default(),
                &mut crate::sync::NoProgress,
            )
            .unwrap();
        let entry = sync
            .stat("/data/local/tmp/push.txt")
            .unwrap()
            .expect("push 后应能 stat 到文件");
        drop(sync);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 14);
        assert_eq!(entry.size, 14);
        let _ = std::fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn client_server_sync_stub_pull_v2() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/pull2.txt", b"v2 pulled", 0o644)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_v2_{}_{}",
            std::process::id(),
            stamp
        ));
        let summary = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/pull2.txt".to_string()],
            &local,
            crate::sync::PullOptions::default(),
            None,
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 9);
        assert_eq!(std::fs::read(&local).unwrap(), b"v2 pulled");
        let _ = std::fs::remove_file(&local);
    }

    #[test]
    fn client_server_sync_stub_push_v2() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_v2_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local_dir).unwrap();
        let local = local_dir.join("push2.txt");
        std::fs::write(&local, b"v2 pushed").unwrap();

        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let selector = TransportSelector::Serial(target);
        let mut sync = crate::sync::SyncClient::connect(&endpoint, &selector).unwrap();
        let summary = sync
            .send_file(
                &local,
                "/data/local/tmp/push2.txt",
                crate::sync::PushOptions::default(),
                &mut crate::sync::NoProgress,
            )
            .unwrap();
        let entry = sync
            .stat("/data/local/tmp/push2.txt")
            .unwrap()
            .expect("push 后应能 stat 到文件");
        drop(sync);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 9);
        assert_eq!(entry.size, 9);
        assert!(entry.attrs.is_some());
        let _ = std::fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn client_server_sync_stub_push_sync_skips_when_mtime_matches() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_sync_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local_dir).unwrap();
        let local = local_dir.join("sync.txt");
        std::fs::write(&local, b"sync content").unwrap();

        let metadata = std::fs::metadata(&local).unwrap();
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as u32)
            .unwrap_or(0);

        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/sync.txt", b"old", 0o644)
            .with_mtime("/data/local/tmp/sync.txt", mtime)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let selector = TransportSelector::Serial(target);
        let mut sync = crate::sync::SyncClient::connect(&endpoint, &selector).unwrap();
        let summary = sync
            .send_file(
                &local,
                "/data/local/tmp/sync.txt",
                crate::sync::PushOptions {
                    sync: true,
                    ..crate::sync::PushOptions::default()
                },
                &mut crate::sync::NoProgress,
            )
            .unwrap();
        drop(sync);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 0);
        assert_eq!(summary.bytes, 0);
        assert_eq!(summary.skipped, 1);
        let _ = std::fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn client_server_sync_stub_stat_missing_returns_none() {
        let adbd = StubSyncFs::new().dir("/data/local/tmp", 0o755).spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let selector = TransportSelector::Serial(target);
        let mut sync = crate::sync::SyncClient::connect(&endpoint, &selector).unwrap();
        let entry = sync.stat("/data/local/tmp/missing.txt").unwrap();
        drop(sync);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn client_server_sync_stub_list_missing_directory_returns_error() {
        let adbd = StubSyncFs::new().dir("/data/local/tmp", 0o755).spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let err = crate::sync::ls(
            &endpoint,
            &TransportSelector::Serial(target),
            "/data/local/tmp/missing",
        )
        .unwrap_err();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(err.to_string().contains("remote sync failed"));
    }

    #[test]
    fn client_server_sync_stub_pull_missing_file_returns_error() {
        let adbd = StubSyncFs::new().dir("/data/local/tmp", 0o755).spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_missing_{}_{}",
            std::process::id(),
            stamp
        ));
        let err = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/missing.txt".to_string()],
            &local,
            crate::sync::PullOptions::default(),
            None,
        )
        .unwrap_err();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn client_server_sync_stub_pull_directory() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .dir("/data/local/tmp/dir", 0o755)
            .file("/data/local/tmp/dir/a.txt", b"a", 0o644)
            .file("/data/local/tmp/dir/b.txt", b"bb", 0o600)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_dir_{}_{}",
            std::process::id(),
            stamp
        ));
        let summary = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/dir".to_string()],
            &local,
            crate::sync::PullOptions::default(),
            None,
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 2);
        assert_eq!(summary.bytes, 3);
        assert_eq!(std::fs::read(local.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(local.join("b.txt")).unwrap(), b"bb");
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_push_directory() {
        let adbd = StubSyncFs::new().dir("/data/local/tmp", 0o755).spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 7);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_dir_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(local.join("pushed/sub")).unwrap();
        std::fs::write(local.join("pushed/sub/file.txt"), b"pushed dir content").unwrap();

        let summary = crate::sync::push(
            &endpoint,
            &TransportSelector::Serial(target),
            &[local.join("pushed")],
            "/data/local/tmp",
            crate::sync::PushOptions::default(),
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert!(fs.contains("/data/local/tmp/pushed"));
        assert!(fs.contains("/data/local/tmp/pushed/sub"));
        assert!(fs.contains("/data/local/tmp/pushed/sub/file.txt"));
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 18);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_sync_list_only() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_list_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(local.join("dir")).unwrap();
        std::fs::write(local.join("dir/a.txt"), b"aa").unwrap();
        std::fs::write(local.join("b.txt"), b"b").unwrap();

        let result = crate::sync::sync_dir(
            &endpoint,
            &TransportSelector::Serial(target),
            &local,
            "/data/local/tmp/synced",
            crate::sync::DirectorySyncOptions {
                list_only: true,
                ..crate::sync::DirectorySyncOptions::default()
            },
            None,
        )
        .unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        let remotes: Vec<&str> = result
            .would_push
            .iter()
            .map(|p| p.remote.as_str())
            .collect();
        assert!(remotes.contains(&"/data/local/tmp/synced/b.txt"));
        assert!(remotes.contains(&"/data/local/tmp/synced/dir/a.txt"));
        assert_eq!(result.summary.skipped, 0);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_push_dry_run() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .spawn("stat_v2,ls_v2,sendrecv_v2,sendrecv_v2_dry_run_send");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_dry_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();
        let file = local.join("file.txt");
        std::fs::write(&file, b"dry run content").unwrap();

        let summary = crate::sync::push(
            &endpoint,
            &TransportSelector::Serial(target),
            &[file],
            "/data/local/tmp",
            crate::sync::PushOptions {
                dry_run: true,
                ..crate::sync::PushOptions::default()
            },
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert!(!fs.contains("/data/local/tmp/file.txt"));
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 15);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_pull_preserve_attrs() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/preserve.txt", b"preserve me", 0o644)
            .with_mtime("/data/local/tmp/preserve.txt", 1_700_000_001)
            .spawn("");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_attr_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();

        let summary = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/preserve.txt".to_string()],
            &local,
            crate::sync::PullOptions {
                preserve_attrs: true,
                ..crate::sync::PullOptions::default()
            },
            None,
        )
        .unwrap();

        let pulled = local.join("preserve.txt");
        let content = std::fs::read(&pulled).unwrap();
        let mtime = std::fs::metadata(&pulled)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 11);
        assert_eq!(content, b"preserve me");
        assert_eq!(mtime, 1_700_000_001);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_sync_full() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 5);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_full_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("x.txt"), b"xyz").unwrap();

        let result = crate::sync::sync_dir(
            &endpoint,
            &TransportSelector::Serial(target),
            &local,
            "/data/local/tmp/synced",
            crate::sync::DirectorySyncOptions::default(),
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert!(fs.contains("/data/local/tmp/synced"));
        assert!(fs.contains("/data/local/tmp/synced/x.txt"));
        assert_eq!(
            fs.file_content("/data/local/tmp/synced/x.txt"),
            Some(b"xyz".to_vec())
        );
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(result.summary.files, 1);
        assert_eq!(result.summary.bytes, 3);
        assert!(result.would_push.is_empty());
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_sync_skip_when_unchanged() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .dir("/data/local/tmp/synced", 0o755)
            .file("/data/local/tmp/synced/x.txt", b"unchanged", 0o644)
            .with_mtime("/data/local/tmp/synced/x.txt", 1_700_000_005)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 5);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_skip_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();
        let file = local.join("x.txt");
        std::fs::write(&file, b"unchanged").unwrap();
        filetime::set_file_mtime(&file, filetime::FileTime::from_unix_time(1_700_000_005, 0))
            .unwrap();

        let result = crate::sync::sync_dir(
            &endpoint,
            &TransportSelector::Serial(target),
            &local,
            "/data/local/tmp/synced",
            crate::sync::DirectorySyncOptions::default(),
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert_eq!(
            fs.file_content("/data/local/tmp/synced/x.txt"),
            Some(b"unchanged".to_vec())
        );
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(result.summary.files, 0);
        assert_eq!(result.summary.bytes, 0);
        assert_eq!(result.summary.skipped, 1);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_push_compressed_zstd() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .spawn("stat_v2,ls_v2,sendrecv_v2,sendrecv_v2_zstd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_push_zstd_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();
        let file = local.join("compressed.txt");
        let content = b"compress me ".repeat(64);
        std::fs::write(&file, &content).unwrap();

        let summary = crate::sync::push(
            &endpoint,
            &TransportSelector::Serial(target),
            &[file],
            "/data/local/tmp",
            crate::sync::PushOptions::default(),
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert!(fs.contains("/data/local/tmp/compressed.txt"));
        assert_eq!(
            fs.file_content("/data/local/tmp/compressed.txt"),
            Some(content.to_vec())
        );
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, content.len() as u64);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_pull_compressed_zstd() {
        let content = b"pull compressed ".repeat(64);
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .file("/data/local/tmp/compressed.txt", content.as_slice(), 0o644)
            .spawn("stat_v2,ls_v2,sendrecv_v2,sendrecv_v2_zstd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_pull_zstd_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();

        let summary = crate::sync::pull(
            &endpoint,
            &TransportSelector::Serial(target),
            &["/data/local/tmp/compressed.txt".to_string()],
            &local,
            crate::sync::PullOptions::default(),
            None,
        )
        .unwrap();

        let pulled = local.join("compressed.txt");
        let pulled_content = std::fs::read(&pulled).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, content.len() as u64);
        assert_eq!(pulled_content, content.as_slice());
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_sync_skip_partial() {
        let adbd = StubSyncFs::new()
            .dir("/data/local/tmp", 0o755)
            .dir("/data/local/tmp/synced", 0o755)
            .file("/data/local/tmp/synced/keep.txt", b"keep", 0o644)
            .with_mtime("/data/local/tmp/synced/keep.txt", 1_700_000_005)
            .file("/data/local/tmp/synced/changed.txt", b"old", 0o644)
            .with_mtime("/data/local/tmp/synced/changed.txt", 1_700_000_001)
            .spawn("stat_v2,ls_v2,sendrecv_v2");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 5);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_sync_partial_{}_{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&local).unwrap();
        let keep = local.join("keep.txt");
        std::fs::write(&keep, b"keep").unwrap();
        filetime::set_file_mtime(&keep, filetime::FileTime::from_unix_time(1_700_000_005, 0))
            .unwrap();
        let changed = local.join("changed.txt");
        std::fs::write(&changed, b"newer content").unwrap();
        filetime::set_file_mtime(
            &changed,
            filetime::FileTime::from_unix_time(1_700_000_002, 0),
        )
        .unwrap();

        let result = crate::sync::sync_dir(
            &endpoint,
            &TransportSelector::Serial(target),
            &local,
            "/data/local/tmp/synced",
            crate::sync::DirectorySyncOptions::default(),
            None,
        )
        .unwrap();

        let fs = adbd.fs().lock().unwrap();
        assert_eq!(
            fs.file_content("/data/local/tmp/synced/keep.txt"),
            Some(b"keep".to_vec())
        );
        assert_eq!(
            fs.file_content("/data/local/tmp/synced/changed.txt"),
            Some(b"newer content".to_vec())
        );
        drop(fs);

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(result.summary.files, 1);
        assert_eq!(result.summary.bytes, 13);
        assert_eq!(result.summary.skipped, 1);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn client_server_sync_stub_features_service() {
        let adbd = StubSyncFs::new().spawn("shell_v2,cmd,abb_exec");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 2);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let features = client::query(&endpoint, &format!("host-serial:{target}:features")).unwrap();
        assert!(features.contains("cmd"));
        assert!(features.contains("abb_exec"));

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    #[test]
    fn client_server_sync_stub_uninstall_legacy_shell() {
        let adbd = StubSyncFs::new().spawn("shell_v2,cmd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 2);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let mut stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target),
            "shell:cmd package uninstall com.example.app",
        )
        .unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(out, b"Success\n");
    }

    #[test]
    fn client_server_sync_stub_install_multiple_session() {
        let apk_size: u64 = 11;
        let adbd = StubSyncFs::new().spawn("abb_exec,cmd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 4);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let create_service = format!("abb_exec:package\0install-create\0-S\0{apk_size}\0");
        let mut create_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &create_service,
        )
        .unwrap();
        let mut create_out = Vec::new();
        create_stream.read_to_end(&mut create_out).unwrap();
        let create_text = String::from_utf8_lossy(&create_out);
        assert!(create_text.contains("Success: created install session [1]"));

        let write_service = format!(
            "abb_exec:package\0install-write\0-S\0{apk_size}\0{}\0base.apk\0-\0",
            1
        );
        let mut write_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &write_service,
        )
        .unwrap();
        write_stream.write_all(b"fake apk\0\0\0").unwrap();
        write_stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut write_out = Vec::new();
        write_stream.read_to_end(&mut write_out).unwrap();
        assert!(write_out.starts_with(b"Success"));

        let commit_service = format!("abb_exec:package\0install-commit\0{}\0", 1);
        let mut commit_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &commit_service,
        )
        .unwrap();
        let mut commit_out = Vec::new();
        commit_stream.read_to_end(&mut commit_out).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(commit_out.starts_with(b"Success"));
    }

    #[test]
    fn client_server_sync_stub_install_multi_package_session() {
        let apk_size: u64 = 11;
        let adbd = StubSyncFs::new().spawn("abb_exec,cmd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 6);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        // 父 session
        let parent_create = format!("abb_exec:package\0install-create\0-S\0{apk_size}\0");
        let mut parent_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &parent_create,
        )
        .unwrap();
        let mut parent_out = Vec::new();
        parent_stream.read_to_end(&mut parent_out).unwrap();
        let parent_text = String::from_utf8_lossy(&parent_out);
        assert!(
            parent_text.contains("Success: created install session [1]"),
            "unexpected parent create output: {parent_text:?}"
        );

        // 子 session
        let child_create = format!("abb_exec:package\0install-create\0-S\0{apk_size}\0");
        let mut child_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &child_create,
        )
        .unwrap();
        let mut child_out = Vec::new();
        child_stream.read_to_end(&mut child_out).unwrap();
        let child_text = String::from_utf8_lossy(&child_out);
        assert!(
            child_text.contains("Success: created install session [2]"),
            "unexpected child create output: {child_text:?}"
        );

        // 写入子 session
        let write_service = format!(
            "abb_exec:package\0install-write\0-S\0{apk_size}\0{}\0base.apk\0-\0",
            2
        );
        let mut write_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            &write_service,
        )
        .unwrap();
        write_stream.write_all(b"fake apk\0\0\0").unwrap();
        write_stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut write_out = Vec::new();
        write_stream.read_to_end(&mut write_out).unwrap();
        assert!(write_out.starts_with(b"Success"));

        // 关联子 session 到父 session
        let add_service = "abb_exec:package\x00install-add-session\x001\x0002\x00";
        let mut add_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            add_service,
        )
        .unwrap();
        let mut add_out = Vec::new();
        add_stream.read_to_end(&mut add_out).unwrap();
        assert!(add_out.starts_with(b"Success"));

        // 提交父 session
        let commit_service = "abb_exec:package\x00install-commit\x001\x00";
        let mut commit_stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target.clone()),
            commit_service,
        )
        .unwrap();
        let mut commit_out = Vec::new();
        commit_stream.read_to_end(&mut commit_out).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(commit_out.starts_with(b"Success"));
    }

    #[test]
    fn client_server_sync_stub_shell_v2_echo() {
        let adbd = StubSyncFs::new().spawn("shell_v2,cmd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 2);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let stream = client::open_device_service(
            &endpoint,
            &TransportSelector::Serial(target),
            "shell,v2,raw:echo hello",
        )
        .unwrap();
        let output = client::stream_shell_v2_to_buffers(stream).unwrap();

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(output.stdout, b"hello\n");
        assert_eq!(output.stderr, b"");
        assert_eq!(output.exit_code, 0);
    }

    #[test]
    fn client_server_sync_stub_forward_tcp_to_shell() {
        let adbd = StubSyncFs::new().spawn("shell_v2,cmd");
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 3);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));

        let forward_response = client::request_forward_status(
            &endpoint,
            &format!("host-serial:{target}:forward:tcp:0;shell:echo forwarded"),
        )
        .unwrap();
        let local_port: u16 = forward_response.unwrap().parse().unwrap();

        let mut local = std::net::TcpStream::connect(("127.0.0.1", local_port)).unwrap();
        let mut out = Vec::new();
        local.read_to_end(&mut out).unwrap();

        // AOSP 重绑定会保留原 listener；同一个已解析端口应立即接收新的 remote。
        client::request_forward_status(
            &endpoint,
            &format!("host-serial:{target}:forward:tcp:{local_port};shell:echo rebound"),
        )
        .unwrap();
        let mut rebound = std::net::TcpStream::connect(("127.0.0.1", local_port)).unwrap();
        let mut rebound_out = Vec::new();
        rebound.read_to_end(&mut rebound_out).unwrap();

        let _ = client::request_ok(
            &endpoint,
            &format!("host-serial:{target}:killforward:tcp:{local_port}"),
        );

        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(out, b"forwarded\n");
        assert_eq!(rebound_out, b"rebound\n");
    }

    #[test]
    fn client_server_forward_jdwp_service_bridges_raw_handshake() {
        let adbd = StubAdbd::spawn(b"device::features=shell_v2;".to_vec(), |stream| {
            let open = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(open.command, protocol::A_OPEN);
            assert_eq!(open.payload, b"jdwp:12345\0");
            AdbMessage::new(protocol::A_OKAY, 77, open.arg0, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();

            let request = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(request.command, protocol::A_WRTE);
            assert_eq!(request.payload, b"JDWP-Handshake");
            AdbMessage::new(protocol::A_OKAY, 77, request.arg0, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
            AdbMessage::new(
                protocol::A_WRTE,
                77,
                request.arg0,
                b"JDWP-Handshake".to_vec(),
            )
            .unwrap()
            .write_to(stream, protocol::A_VERSION)
            .unwrap();
            let _ = AdbMessage::read_from(stream, protocol::MAX_PAYLOAD);
            AdbMessage::new(protocol::A_CLSE, 77, request.arg0, Vec::new())
                .unwrap()
                .write_to(stream, protocol::A_VERSION)
                .unwrap();
        });
        let target = adbd.target();
        let (endpoint, server, shutdown, _state) = spawn_test_server(test_state(), 2);

        let response = client::query(&endpoint, &format!("host:connect:{target}")).unwrap();
        assert_eq!(response, format!("connected to {target}"));
        let local_port = client::request_forward_status(
            &endpoint,
            &format!("host-serial:{target}:forward:tcp:0;jdwp:12345"),
        )
        .unwrap()
        .unwrap()
        .parse::<u16>()
        .unwrap();

        let mut local = std::net::TcpStream::connect(("127.0.0.1", local_port)).unwrap();
        local.write_all(b"JDWP-Handshake").unwrap();
        let mut output = Vec::new();
        local.read_to_end(&mut output).unwrap();

        let _ = client::request_ok(
            &endpoint,
            &format!("host-serial:{target}:killforward:tcp:{local_port}"),
        );
        adbd.join();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(output, b"JDWP-Handshake");
    }

    fn add_fake_transport(state: &Arc<ServerState>, id: u64, serial: &str) {
        add_fake_transport_with_state(state, id, serial, ConnectionState::Device, None);
    }

    fn add_fake_transport_with_state(
        state: &Arc<ServerState>,
        id: u64,
        serial: &str,
        connection_state: ConnectionState,
        features: Option<&str>,
    ) {
        add_fake_transport_with_type(
            state,
            id,
            serial,
            transport::TransportConnectionType::Socket,
            connection_state,
            features,
        );
    }

    fn add_fake_transport_with_type(
        state: &Arc<ServerState>,
        id: u64,
        serial: &str,
        connection_type: transport::TransportConnectionType,
        connection_state: ConnectionState,
        features: Option<&str>,
    ) {
        add_fake_transport_with_type_and_devpath(
            state,
            id,
            serial,
            connection_type,
            connection_state,
            features,
            None,
        );
    }

    fn add_fake_transport_with_type_and_devpath(
        state: &Arc<ServerState>,
        id: u64,
        serial: &str,
        connection_type: transport::TransportConnectionType,
        connection_state: ConnectionState,
        features: Option<&str>,
        devpath: Option<&str>,
    ) {
        add_fake_transport_full(
            state,
            TransportInfo {
                id,
                serial: serial.to_string(),
                devpath: devpath.map(str::to_string),
                connection_type,
                negotiated_speed_mbps: 0,
                max_speed_mbps: 0,
                state: connection_state,
                product: None,
                model: None,
                device: None,
                features: features.map(str::to_string),
                max_payload: protocol::MAX_PAYLOAD,
                protocol_version: protocol::A_VERSION,
            },
        );
    }

    fn add_fake_transport_full(state: &Arc<ServerState>, info: TransportInfo) {
        state.transports.lock().unwrap().push(Transport::fake(info));
    }

    fn fake_detachable_usb_info(id: u64, serial: &str, state: ConnectionState) -> TransportInfo {
        TransportInfo {
            id,
            serial: serial.to_string(),
            devpath: Some(format!("usb:001:{id:03}:18d1:4ee7:3")),
            connection_type: transport::TransportConnectionType::Usb,
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            state,
            product: Some("sdk".to_string()),
            model: Some("Pixel".to_string()),
            device: Some("emu".to_string()),
            features: Some("shell_v2,cmd".to_string()),
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        }
    }

    fn add_fake_detachable_usb_transport(
        state: &Arc<ServerState>,
        id: u64,
        serial: &str,
        connection_state: ConnectionState,
    ) {
        add_fake_transport_full(
            state,
            fake_detachable_usb_info(id, serial, connection_state),
        );
    }

    fn assert_tcp_port_released(port: &str) {
        let port = port.parse::<u16>().unwrap();
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("forward tcp:{port} listener was not released");
    }

    #[test]
    fn host_version_matches_official_wire_shape() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:version",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(out, b"OKAY00040029");
    }

    #[test]
    fn fork_server_startup_ack_uses_official_bytes() {
        let mut out = Vec::new();

        write_server_startup_ack(&mut out).unwrap();

        assert_eq!(out, b"OK\n");
    }

    #[test]
    fn devices_returns_empty_length_prefixed_payload() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:devices-l",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(out, b"OKAY0000");
    }

    #[test]
    fn disconnect_without_target_only_removes_tcp_transports_like_official() {
        let state = test_state();
        add_fake_transport(&state, 1, "127.0.0.1:5555");
        add_fake_transport_with_type(
            &state,
            2,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            "host:disconnect:",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        protocol::write_protocol_string(&mut expected, "disconnected everything").unwrap();
        assert_eq!(out, expected);
        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "usb-1");
    }

    #[test]
    fn disconnect_target_returns_official_success_and_fail_messages() {
        let state = test_state();
        add_fake_transport(&state, 1, "192.0.2.10:5555");
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            "host:disconnect:tcp:192.0.2.10",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        protocol::write_protocol_string(&mut expected, "disconnected tcp:192.0.2.10").unwrap();
        assert_eq!(out, expected);
        assert!(state.list().is_empty());

        let mut out = Vec::new();
        handle_service(
            &mut out,
            "host:disconnect:192.0.2.10",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"FAIL".to_vec();
        protocol::write_protocol_string(&mut expected, "no such device '192.0.2.10:5555'").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn disconnect_target_matches_devpath_and_qualified_properties() {
        let state = test_state();
        add_fake_transport_full(
            &state,
            TransportInfo {
                id: 1,
                serial: "usb-serial".to_string(),
                devpath: Some("usb:1:2:18d1:4ee7:3".to_string()),
                connection_type: transport::TransportConnectionType::Usb,
                negotiated_speed_mbps: 480,
                max_speed_mbps: 5_000,
                state: ConnectionState::Device,
                product: Some("sdk_gphone64_x86_64".to_string()),
                model: Some("Pixel 8 Pro".to_string()),
                device: Some("husky".to_string()),
                features: None,
                max_payload: protocol::MAX_PAYLOAD,
                protocol_version: protocol::A_VERSION,
            },
        );

        assert_eq!(
            disconnect_target_serial(&state.transports.lock().unwrap(), "usb:1:2:18d1:4ee7:3")
                .unwrap(),
            "usb-serial"
        );
        assert_eq!(
            disconnect_target_serial(
                &state.transports.lock().unwrap(),
                "product:sdk_gphone64_x86_64"
            )
            .unwrap(),
            "usb-serial"
        );
        assert_eq!(
            disconnect_target_serial(&state.transports.lock().unwrap(), "model:Pixel_8_Pro")
                .unwrap(),
            "usb-serial"
        );
        assert_eq!(
            disconnect_target_serial(&state.transports.lock().unwrap(), "device:husky").unwrap(),
            "usb-serial"
        );
    }

    #[test]
    fn host_features_returns_protocol_string() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:host-features",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(&out[..4], b"OKAY");
        let body = protocol::read_protocol_string(&mut &out[4..]).unwrap();
        let features: Vec<_> = body.split(',').collect();
        assert!(features.contains(&"shell_v2"));
        assert!(features.contains(&"server_status"));
        assert!(features.contains(&"push_sync"));
        assert_eq!(
            features.contains(&"libusb"),
            crate::usb::selected_usb_backend() == crate::usb::UsbHostBackend::Libusb
        );
    }

    #[test]
    fn server_status_returns_binary_protocol_string() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:server-status",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(&out[..4], b"OKAY");
        let body = protocol::read_protocol_bytes(&mut &out[4..]).unwrap();
        let status = AdbServerStatus::decode(&body).unwrap();
        assert_eq!(
            status.usb_backend,
            match crate::usb::selected_usb_backend() {
                crate::usb::UsbHostBackend::Libusb => crate::server_status::UsbBackend::Libusb,
            }
        );
        assert_eq!(
            status.mdns_backend,
            crate::server_status::MdnsBackend::Libadbmdns
        );
    }

    #[test]
    fn emulator_scan_ports_match_official_default_range() {
        let max_port = emulator_max_port_from_env_value(None);
        let ports: Vec<_> = (DEFAULT_ADB_LOCAL_TRANSPORT_PORT..=max_port)
            .step_by(2)
            .collect();

        assert_eq!(ports.first(), Some(&5555));
        assert_eq!(ports.last(), Some(&5585));
        assert_eq!(ports.len(), 16);
        assert!(ports.iter().all(|port| port % 2 == 1));
    }

    #[test]
    fn emulator_scan_ports_honor_max_port_env() {
        assert_eq!(emulator_max_port_from_env_value(Some("5559")), 5559);
        assert_eq!(emulator_max_port_from_env_value(Some("5554")), 5554);
        assert_eq!(
            emulator_max_port_from_env_value(Some("invalid")),
            DEFAULT_ADB_LOCAL_TRANSPORT_MAX_PORT
        );
    }

    #[test]
    fn emulator_serial_uses_adjacent_console_port() {
        assert_eq!(emulator_serial_for_adb_port(5555), "emulator-5554");
        assert_eq!(emulator_serial_for_adb_port(5557), "emulator-5556");
    }

    #[test]
    fn emulator_scan_skips_existing_emulator_or_loopback_serial() {
        let state = test_state();
        add_fake_transport(&state, 1, "emulator-5554");
        assert!(state.has_emulator_transport_for_port(5555));

        let state = test_state();
        add_fake_transport(&state, 2, "127.0.0.1:5557");
        assert!(state.has_emulator_transport_for_port(5557));
    }

    fn fake_usb_interface(serial_number: Option<&str>) -> usb::UsbAdbInterface {
        usb::UsbAdbInterface {
            backend: usb::UsbInterfaceBackend::Libusb,
            bus_number: 1,
            device_address: 2,
            bus_address: "usb:1-2".to_string(),
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            vendor_id: 0x18d1,
            product_id: 0x4ee7,
            interface_number: 3,
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
    fn one_device_filter_matches_transport_serial_only() {
        let unrestricted = test_state();
        assert!(unrestricted.owns_transport_serial("serial-1"));

        let state = test_one_device_state("serial-1");
        assert!(state.owns_transport_serial("serial-1"));
        assert!(!state.owns_transport_serial("serial-2"));
    }

    #[test]
    fn one_device_filter_matches_usb_serial_or_fallback() {
        let interface = fake_usb_interface(Some("usb-serial"));
        let fallback = interface.usb_serial_fallback();

        assert!(test_state().owns_usb_interface(&interface, "usb-serial"));
        assert!(test_one_device_state("usb-serial").owns_usb_interface(&interface, "usb-serial"));
        assert!(test_one_device_state(&fallback).owns_usb_interface(&interface, "usb-serial"));
        assert!(
            !test_one_device_state("other-serial").owns_usb_interface(&interface, "usb-serial")
        );
    }

    #[test]
    fn usb_start_detached_env_matches_aosp_attached_registry() {
        let state = test_state();
        let interface = fake_usb_interface(Some("usb-serial"));

        assert!(!state.should_start_usb_detached_for_env(&interface, "usb-serial", None));
        assert!(!state.should_start_usb_detached_for_env(&interface, "usb-serial", Some("0")));
        assert!(state.should_start_usb_detached_for_env(&interface, "usb-serial", Some("1")));

        state.register_usb_attach("usb-serial");
        assert!(!state.should_start_usb_detached_for_env(&interface, "usb-serial", Some("1")));

        state.register_usb_detach("usb-serial");
        assert!(state.should_start_usb_detached_for_env(&interface, "usb-serial", Some("1")));
    }

    #[test]
    fn usb_start_detached_placeholder_uses_detached_transport_shape() {
        let interface = fake_usb_interface(Some("usb-serial"));
        let transport = detached_usb_transport_from_interface(9, &interface, "usb-serial".into());
        let info = transport.info();

        assert_eq!(info.id, 9);
        assert_eq!(info.serial, "usb-serial");
        assert_eq!(info.state, ConnectionState::Detached);
        assert_eq!(info.devpath, Some(interface.bus_address));
        assert_eq!(
            info.connection_type,
            transport::TransportConnectionType::Usb
        );
    }

    #[test]
    fn usb_no_permissions_placeholder_uses_aosp_transport_shape() {
        let interface = fake_usb_interface(Some("usb-serial"));
        let transport =
            no_permissions_usb_transport_from_interface(9, &interface, "usb-serial".into());
        let info = transport.info();

        assert_eq!(info.id, 9);
        assert_eq!(info.serial, "usb-serial");
        assert_eq!(info.state, ConnectionState::NoPermissions);
        assert_eq!(info.devpath, Some(interface.bus_address));
        assert_eq!(
            info.connection_type,
            transport::TransportConnectionType::Usb
        );
    }

    #[test]
    fn usb_permission_recovery_reuses_devpath_when_serial_becomes_available() {
        let state = test_state();
        let mut interface = fake_usb_interface(None);
        let fallback = interface.serial_or_fallback();
        state.register_transport(no_permissions_usb_transport_from_interface(
            9, &interface, fallback,
        ));

        interface.serial_number = Some("real-serial".to_string());
        let existing = state
            .find_usb_transport_info(&interface, "real-serial")
            .unwrap();
        assert_eq!(existing.id, 9);
        assert_eq!(existing.state, ConnectionState::NoPermissions);

        let mut recovered = existing;
        recovered.serial = "real-serial".to_string();
        recovered.state = ConnectionState::Device;
        state.register_transport(Transport::fake(recovered));

        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, 9);
        assert_eq!(devices[0].serial, "real-serial");
        assert_eq!(devices[0].state, ConnectionState::Device);
    }

    #[test]
    fn usb_resume_kicks_usb_transports_and_preserves_attach_policy() {
        let state = test_state();
        add_fake_transport_with_type_and_devpath(
            &state,
            1,
            "usb-serial",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
            Some("usb:1-2"),
        );
        add_fake_transport(&state, 2, "tcp-serial");
        state.register_usb_attach("usb-serial");
        let local_port = state
            .install_forward(HostSelector::Serial("usb-serial"), "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let generation = state.usb_resume_generation.load(Ordering::SeqCst);

        assert!(!state.handle_usb_resume_generation(generation));
        assert!(state.handle_usb_resume_generation(generation.wrapping_add(1)));
        assert_eq!(
            state
                .usb_resume_serials
                .lock()
                .unwrap()
                .get("usb:1-2")
                .map(|identity| identity.serial.as_str()),
            Some("usb-serial")
        );

        let transports = state.list();
        assert_eq!(transports.len(), 1);
        assert_eq!(transports[0].serial, "tcp-serial");
        assert!(state.is_usb_attached("usb-serial"));
        assert_eq!(state.list_forwards(), "");
        assert_tcp_port_released(&local_port);
        assert!(!state.handle_usb_resume_generation(generation.wrapping_add(1)));
    }

    #[test]
    fn usb_resume_preserves_serial_when_descriptor_temporarily_missing() {
        let state = test_state();
        add_fake_transport_with_type_and_devpath(
            &state,
            1,
            "usb-serial",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
            Some("usb:1-2"),
        );
        let generation = state.usb_resume_generation.load(Ordering::SeqCst);
        assert!(state.handle_usb_resume_generation(generation.wrapping_add(1)));

        let interface = fake_usb_interface(None);
        state.expire_usb_resume_serials();
        assert_eq!(state.usb_serial_for_scan(&interface), "usb-serial");

        state
            .usb_resume_serials
            .lock()
            .unwrap()
            .get_mut("usb:1-2")
            .unwrap()
            .expires_at = Instant::now() - Duration::from_millis(1);
        state.expire_usb_resume_serials();
        assert_eq!(
            state.usb_serial_for_scan(&interface),
            interface.usb_serial_fallback()
        );
    }

    #[test]
    fn usb_scan_removes_only_missing_inactive_placeholders() {
        let state = test_state();
        let present = fake_usb_interface(Some("present-usb"));
        add_fake_transport_with_type_and_devpath(
            &state,
            1,
            "present-usb",
            transport::TransportConnectionType::Usb,
            ConnectionState::Detached,
            None,
            Some("old-address-that-can-change"),
        );
        add_fake_transport_with_type_and_devpath(
            &state,
            2,
            "missing-usb",
            transport::TransportConnectionType::Usb,
            ConnectionState::Detached,
            None,
            Some("usb:001:099:18d1:4ee7:3"),
        );
        add_fake_transport_with_type_and_devpath(
            &state,
            4,
            "missing-no-permission",
            transport::TransportConnectionType::Usb,
            ConnectionState::NoPermissions,
            None,
            Some("usb:001:100:18d1:4ee7:3"),
        );
        add_fake_transport_with_type(
            &state,
            3,
            "active-usb",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        let revision = state.device_revision();

        assert_eq!(state.reconcile_inactive_usb_transports(&[present]), 2);

        let serials: HashSet<String> = state.list().into_iter().map(|info| info.serial).collect();
        assert_eq!(
            serials,
            HashSet::from(["present-usb".to_string(), "active-usb".to_string()])
        );
        assert_ne!(state.device_revision(), revision);
    }

    #[test]
    fn usb_selection_message_reports_last_scan_error() {
        let state = test_state();
        *state.usb_scan_errors.lock().unwrap() =
            vec!["bus 001 device 002: Access denied".to_string()];

        assert_eq!(
            state.usb_selection_message(),
            "no USB devices registered (bus 001 device 002: Access denied)"
        );
    }

    #[test]
    fn no_permissions_transport_is_visible_but_not_selectable() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "denied-usb",
            transport::TransportConnectionType::Usb,
            ConnectionState::NoPermissions,
            None,
        );

        let listed = state.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, ConnectionState::NoPermissions);

        let err = state.select_any().unwrap_err();
        assert!(matches!(
            err,
            AdbError::Server(reason)
                if reason.starts_with("insufficient permissions for device")
                    && reason.ends_with(
                        "See [http://developer.android.com/tools/device.html] for more information"
                    )
        ));
        assert!(state.wait_spec_is_satisfied(
            HostSelector::Any,
            &WaitSpec::parse("wait-for-any-disconnect").unwrap()
        ));
    }

    #[test]
    fn no_permissions_transport_does_not_create_false_ambiguity() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "denied-usb",
            transport::TransportConnectionType::Usb,
            ConnectionState::NoPermissions,
            None,
        );
        add_fake_transport(&state, 2, "available-device");

        assert_eq!(state.select_any().unwrap().serial, "available-device");
        assert_eq!(
            state
                .select_transport_for(HostSelector::Any)
                .unwrap()
                .info()
                .serial,
            "available-device"
        );

        let err = state.select_usb_registered_with_state(false).err().unwrap();
        assert!(matches!(
            err,
            AdbError::Server(reason) if reason.starts_with("insufficient permissions for device")
        ));

        add_fake_transport(&state, 3, "second-available-device");
        assert!(matches!(
            state.select_any(),
            Err(AdbError::Server(reason)) if reason == "more than one device/emulator"
        ));
    }

    #[test]
    fn unauthorized_selection_message_matches_aosp() {
        assert_eq!(
            unauthorized_selection_message(None),
            concat!(
                "device unauthorized.\n",
                "This adb server's $ADB_VENDOR_KEYS is not set\n",
                "Try 'adb kill-server' if that seems wrong.\n",
                "Otherwise check for a confirmation dialog on your device."
            )
        );
        assert_eq!(
            unauthorized_selection_message(Some(std::ffi::OsStr::new("vendor-keys"))),
            concat!(
                "device unauthorized.\n",
                "This adb server's $ADB_VENDOR_KEYS is vendor-keys\n",
                "Try 'adb kill-server' if that seems wrong.\n",
                "Otherwise check for a confirmation dialog on your device."
            )
        );
    }

    #[test]
    fn normal_selection_rejects_inactive_transport_but_management_accepts_it() {
        let state = test_state();
        add_fake_transport_with_state(
            &state,
            1,
            "unauthorized",
            ConnectionState::Unauthorized,
            None,
        );

        let err = state.select_any().unwrap_err();
        assert!(matches!(
            err,
            AdbError::Server(reason)
                if reason.starts_with("device unauthorized.\n")
                    && reason.ends_with(
                        "Otherwise check for a confirmation dialog on your device."
                    )
        ));
        assert_eq!(
            state
                .select_info_for_with_state(HostSelector::Any, true)
                .unwrap()
                .state,
            ConnectionState::Unauthorized
        );

        let state = test_state();
        add_fake_transport_with_state(&state, 2, "offline", ConnectionState::Offline, None);
        assert!(matches!(
            state.select_serial("offline"),
            Err(AdbError::Server(reason)) if reason == "device offline"
        ));
        assert_eq!(
            state
                .select_info_for_with_state(HostSelector::Serial("offline"), true)
                .unwrap()
                .state,
            ConnectionState::Offline
        );

        let state = test_state();
        add_fake_transport_with_state(&state, 3, "authorizing", ConnectionState::Authorizing, None);
        assert!(matches!(
            state.select_serial("authorizing"),
            Err(AdbError::Server(reason)) if reason == "device still authorizing"
        ));
        assert_eq!(
            state
                .select_info_for_with_state(HostSelector::Serial("authorizing"), true)
                .unwrap()
                .state,
            ConnectionState::Authorizing
        );
    }

    #[test]
    fn pending_tcp_transport_is_visible_as_authorizing_until_cnxn() {
        let state = test_state();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let serial = addr.to_string();
        let (release_tx, release_rx) = mpsc::channel();
        let (online_tx, online_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let adbd = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);
            AdbMessage::new(
                protocol::A_AUTH,
                protocol::ADB_AUTH_TOKEN,
                0,
                vec![3_u8; 20],
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
            online_tx.send(()).unwrap();
            done_rx.recv().unwrap();
        });

        let connecting_state = Arc::clone(&state);
        let connecting_serial = serial.clone();
        let connector = thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let pending =
                transport::prepare_tcp_stream_with_serial(41, connecting_serial, stream).unwrap();
            connecting_state.complete_pending_transport(pending)
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while state
            .list()
            .first()
            .is_none_or(|info| info.state != ConnectionState::Authorizing)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let authorizing = state.list();
        assert_eq!(authorizing.len(), 1);
        assert_eq!(authorizing[0].id, 41);
        assert_eq!(authorizing[0].state, ConnectionState::Authorizing);
        assert!(matches!(
            state.select_serial(&serial),
            Err(AdbError::Server(reason)) if reason == "device still authorizing"
        ));

        release_tx.send(()).unwrap();
        online_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let transport = connector.join().unwrap().unwrap();
        assert_eq!(transport.info().id, 41);
        assert_eq!(transport.info().state, ConnectionState::Device);
        let online = state.list();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].id, 41);
        assert_eq!(online[0].state, ConnectionState::Device);

        done_tx.send(()).unwrap();
        adbd.join().unwrap();
    }

    #[test]
    fn closed_transport_is_removed_and_notifies_trackers() {
        let state = test_state();
        add_fake_transport_with_state(&state, 7, "serial-1", ConnectionState::Device, None);
        let resolved = state
            .install_forward(HostSelector::Any, "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let transport = state.transports.lock().unwrap()[0].clone();
        let before_revision = state.device_revision();

        transport.mark_closed_for_test();
        let removed = state.remove_closed_transports();

        assert_eq!(removed, 1);
        assert!(state.list().is_empty());
        assert_eq!(state.list_forwards(), "");
        assert_ne!(state.device_revision(), before_revision);
        assert_tcp_port_released(&resolved);
    }

    #[test]
    fn tracked_tcp_natural_disconnect_becomes_offline_after_initial_delay() {
        let state = test_state();
        add_fake_transport(&state, 7, "127.0.0.1:5555");
        let info = state.list()[0].clone();
        state.record_tcp_connected(info.serial.clone(), info);
        let transport = state.transports.lock().unwrap()[0].clone();
        let before_revision = state.device_revision();

        transport.mark_closed_for_test();
        assert_eq!(state.remove_closed_transports(), 1);

        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, 7);
        assert_eq!(devices[0].state, ConnectionState::Offline);
        assert_ne!(state.device_revision(), before_revision);

        let next_attempt = state
            .tcp_reconnects
            .lock()
            .unwrap()
            .get("127.0.0.1:5555")
            .unwrap()
            .next_attempt
            .unwrap();
        let attempts = AtomicUsize::new(0);
        state.process_tcp_reconnects_with(
            next_attempt - Duration::from_millis(1),
            |_| -> Result<Transport> {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(AdbError::Server("unexpected early retry".to_string()))
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        state.process_tcp_reconnects_with(next_attempt, |_| -> Result<Transport> {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(AdbError::Server("device not ready".to_string()))
        });
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let retry_at = state
            .tcp_reconnects
            .lock()
            .unwrap()
            .get("127.0.0.1:5555")
            .unwrap()
            .next_attempt
            .unwrap();
        assert_eq!(retry_at, next_attempt + TCP_RECONNECT_RETRY_DELAY);

        state.process_tcp_reconnects_with(
            retry_at - Duration::from_millis(1),
            |_| -> Result<Transport> {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(AdbError::Server("unexpected early retry".to_string()))
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tracked_tcp_reconnect_reuses_transport_id() {
        let state = test_state();
        add_fake_transport(&state, 7, "127.0.0.1:5555");
        let info = state.list()[0].clone();
        state.record_tcp_connected(info.serial.clone(), info);
        state.transports.lock().unwrap()[0].mark_closed_for_test();
        state.remove_closed_transports();
        let next_attempt = state
            .tcp_reconnects
            .lock()
            .unwrap()
            .get("127.0.0.1:5555")
            .unwrap()
            .next_attempt
            .unwrap();

        state.process_tcp_reconnects_with(next_attempt, |attempt| {
            assert_eq!(attempt.serial, "127.0.0.1:5555");
            assert_eq!(attempt.target, "127.0.0.1:5555");
            assert_eq!(attempt.transport_id, 7);
            Ok(Transport::fake(fake_socket_info(
                attempt.transport_id,
                &attempt.serial,
            )))
        });

        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, 7);
        assert_eq!(devices[0].state, ConnectionState::Device);
        let reconnects = state.tcp_reconnects.lock().unwrap();
        let entry = reconnects.get("127.0.0.1:5555").unwrap();
        assert!(entry.next_attempt.is_none());
        assert!(!entry.in_flight);
    }

    #[test]
    fn explicit_disconnect_removes_offline_tcp_and_cancels_reconnect() {
        let state = test_state();
        add_fake_transport(&state, 7, "127.0.0.1:5555");
        let info = state.list()[0].clone();
        state.record_tcp_connected(info.serial.clone(), info);
        state.transports.lock().unwrap()[0].mark_closed_for_test();
        state.remove_closed_transports();

        assert_eq!(
            state.disconnect(Some("127.0.0.1:5555")).unwrap(),
            "disconnected 127.0.0.1:5555"
        );
        assert!(state.list().is_empty());
        assert!(state.tcp_reconnects.lock().unwrap().is_empty());
    }

    #[test]
    fn mdns_services_returns_discovery_table_protocol_string() {
        let mdns = mdns::DiscoveryState::disabled();
        mdns.replace_services_for_test(vec![
            mdns::ServiceInfo::new("tls", "_adb-tls-connect._tcp", "192.0.2.10", 37099),
            mdns::ServiceInfo::new("legacy", "_adb._tcp", "192.0.2.20", 5555),
        ]);
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:mdns:services",
            test_state_with_mdns(mdns),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        protocol::write_protocol_string(
            &mut expected,
            "legacy\t_adb._tcp\t192.0.2.20:5555\ntls\t_adb-tls-connect._tcp\t192.0.2.10:37099\n",
        )
        .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn mdns_auto_connect_deduplicates_events_and_obeys_retry_delay() {
        let mdns = mdns::DiscoveryState::disabled();
        let service = mdns::ServiceInfo::new("device", "_adb._tcp", "192.0.2.10", 5555);
        mdns.replace_services_for_test(vec![service.clone()]);
        let state = test_state_with_mdns(mdns);
        state.handle_mdns_service_resolved_with(service.clone(), Some("adb"), |_| true);
        state.handle_mdns_service_resolved_with(service, Some("adb"), |_| true);

        let attempts = AtomicUsize::new(0);
        let now = Instant::now();
        state.process_mdns_auto_connects_with(
            now,
            Some("adb"),
            |_| true,
            |_| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(AdbError::Server("device not ready".to_string()))
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        state.process_mdns_auto_connects_with(
            now + MDNS_RECONNECT_RETRY_DELAY - Duration::from_millis(1),
            Some("adb"),
            |_| true,
            |_| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(AdbError::Server("unexpected early retry".to_string()))
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        state.process_mdns_auto_connects_with(
            now + MDNS_RECONNECT_RETRY_DELAY,
            Some("adb"),
            |_| true,
            |_| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok((fake_socket_info(7, "device._adb._tcp"), false))
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let entries = state.mdns_auto_connects.lock().unwrap();
        let entry = entries.get("device._adb._tcp").unwrap();
        assert_eq!(entry.serial.as_deref(), Some("device._adb._tcp"));
        assert!(entry.next_attempt.is_none());
    }

    #[test]
    fn known_secure_mdns_service_auto_connects_on_fresh_server_state() {
        let mdns = mdns::DiscoveryState::disabled();
        let service =
            mdns::ServiceInfo::new("paired-guid", "_adb-tls-connect._tcp", "192.0.2.10", 37101);
        mdns.replace_services_for_test(vec![service.clone()]);
        let state = test_state_with_mdns(mdns);

        state
            .handle_mdns_service_resolved_with(service.clone(), None, |guid| guid == "paired-guid");
        assert!(
            state
                .mdns_auto_connects
                .lock()
                .unwrap()
                .contains_key("paired-guid._adb-tls-connect._tcp")
        );
        let now = Instant::now();
        state.process_mdns_auto_connects_with(
            now,
            None,
            |guid| guid == "paired-guid",
            |target| {
                let transport = Transport::fake(fake_socket_info(23, target));
                let info = state.register_transport(transport);
                Ok((info, false))
            },
        );

        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "paired-guid._adb-tls-connect._tcp");
        assert_eq!(devices[0].id, 23);
        let entries = state.mdns_auto_connects.lock().unwrap();
        let entry = entries.get("paired-guid._adb-tls-connect._tcp").unwrap();
        assert!(entry.next_attempt.is_none());
        assert_eq!(
            entry.serial.as_deref(),
            Some("paired-guid._adb-tls-connect._tcp")
        );
    }

    #[test]
    fn mdns_auto_connected_transport_recovers_after_natural_disconnect() {
        let (release_first, wait_first) = mpsc::channel();
        let first = StubAdbd::spawn("device::features=shell_v2", move |_| {
            wait_first.recv().unwrap();
        });
        let first_target = first.target();
        let first_port = first_target.rsplit_once(':').unwrap().1.parse().unwrap();
        let mdns = mdns::DiscoveryState::disabled();
        let service = mdns::ServiceInfo::new("device", "_adb._tcp", "127.0.0.1", first_port);
        mdns.replace_services_for_test(vec![service.clone()]);
        let state = test_state_with_mdns(mdns);
        state.handle_mdns_service_resolved_with(service, Some("adb"), |_| true);
        state.process_mdns_auto_connects_with(
            Instant::now(),
            Some("adb"),
            |_| true,
            |target| state.connect_tcp_untracked(target),
        );
        assert_eq!(state.list()[0].serial, "device._adb._tcp");

        release_first.send(()).unwrap();
        first.join();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !state.transports.lock().unwrap()[0].is_closed() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(state.remove_closed_transports(), 1);

        let (release_second, wait_second) = mpsc::channel();
        let second = StubAdbd::spawn("device::features=shell_v2", move |_| {
            wait_second.recv().unwrap();
        });
        let second_target = second.target();
        let second_port = second_target.rsplit_once(':').unwrap().1.parse().unwrap();
        state
            .mdns
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .replace_services_for_test(vec![mdns::ServiceInfo::new(
                "device",
                "_adb._tcp",
                "127.0.0.1",
                second_port,
            )]);
        state.process_mdns_auto_connects_with(
            Instant::now() + MDNS_RECONNECT_INITIAL_DELAY,
            Some("adb"),
            |_| true,
            |target| state.connect_tcp_untracked(target),
        );
        assert_eq!(state.list()[0].serial, "device._adb._tcp");

        state.disconnect(Some("device")).unwrap();
        assert!(state.mdns_auto_connects.lock().unwrap().is_empty());
        release_second.send(()).unwrap();
        second.join();
    }

    fn fake_socket_info(id: u64, serial: &str) -> TransportInfo {
        TransportInfo {
            id,
            serial: serial.to_string(),
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
        }
    }

    #[test]
    fn mdns_check_reports_disabled_when_backend_is_disabled() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:mdns:check",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        protocol::write_protocol_string(&mut expected, "ERROR: mdns discovery disabled").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn pair_service_validates_address_then_returns_official_failure_shape() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        drop(listener);
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            &format!("host:pair:123456:{target}"),
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert!(out.starts_with(b"FAIL"));
        let reason = protocol::read_protocol_string(&mut &out[4..]).unwrap();
        assert_eq!(reason, "Failed: Unable to start pairing client.");
    }

    #[test]
    fn pair_service_rejects_malformed_pair_request_like_unknown_host_service() {
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:pair:123456",
            test_state(),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert!(out.starts_with(b"FAIL"));
        let reason = protocol::read_protocol_string(&mut &out[4..]).unwrap();
        assert_eq!(reason, "unknown host service 'pair:123456'");
    }

    #[test]
    fn pair_service_validates_explicit_port_like_aosp() {
        for host in ["192.0.2.10:0", "192.0.2.10:65536", "[::1]:bad"] {
            let mut out = Vec::new();
            let mut selected = None;
            handle_service(
                &mut out,
                &format!("host:pair:123456:{host}"),
                test_state(),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap();

            assert!(out.starts_with(b"FAIL"));
            let reason = protocol::read_protocol_string(&mut &out[4..]).unwrap();
            assert_eq!(
                reason,
                format!("Invalid port while parsing address [{host}]")
            );
        }
    }

    #[test]
    fn pair_service_accepts_mdns_pairing_instance_before_tls_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mdns = mdns::DiscoveryState::disabled();
        mdns.replace_services_for_test(vec![mdns::ServiceInfo::new(
            "pair-device",
            "_adb-tls-pairing._tcp",
            &address.ip().to_string(),
            address.port(),
        )]);
        let mut out = Vec::new();
        let mut selected = None;
        handle_service(
            &mut out,
            "host:pair:123456:pair-device",
            test_state_with_mdns(mdns),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert!(out.starts_with(b"FAIL"));
        let reason = protocol::read_protocol_string(&mut &out[4..]).unwrap();
        assert_eq!(reason, "Failed: Unable to start pairing client.");
    }

    #[test]
    fn attach_detach_return_official_unsupported_error() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            7,
            "serial-1",
            transport::TransportConnectionType::Socket,
            ConnectionState::Device,
            None,
        );

        let mut out = Vec::new();
        let mut selected = None;
        assert_eq!(
            handle_service(
                &mut out,
                "host:tport:any",
                Arc::clone(&state),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap(),
            ServiceAction::Continue
        );
        let action = handle_service(
            &mut out,
            "host:detach",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();
        assert_eq!(action, ServiceAction::Close);
        assert!(out[12..].starts_with(b"FAIL"));
        assert_eq!(
            protocol::read_protocol_string(&mut &out[16..]).unwrap(),
            "attach/detach not supported!"
        );

        let mut out = Vec::new();
        let mut selected = None;
        assert_eq!(
            handle_service(
                &mut out,
                "host:tport:any",
                Arc::clone(&state),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap(),
            ServiceAction::Continue
        );
        let action = handle_service(
            &mut out,
            "host:attach",
            state,
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();
        assert_eq!(action, ServiceAction::Close);
        assert!(out[12..].starts_with(b"FAIL"));
        assert_eq!(
            protocol::read_protocol_string(&mut &out[16..]).unwrap(),
            "attach/detach not supported"
        );
    }

    #[test]
    fn detach_usb_transport_registers_detached_placeholder() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        state.register_usb_attach("usb-serial");
        let selected = state.select_serial("usb-serial").unwrap();
        let before_revision = state.device_revision();

        assert_eq!(
            state.detach_selected_transport(&selected).unwrap(),
            "usb-serial detached"
        );

        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, 7);
        assert_eq!(devices[0].serial, "usb-serial");
        assert_eq!(devices[0].state, ConnectionState::Detached);
        assert_eq!(
            transport::format_devices(&devices, true),
            concat!(
                "usb-serial             detached usb:001:007:18d1:4ee7:3 ",
                "product:sdk model:Pixel device:emu transport_id:7\n"
            )
        );
        assert!(!state.is_usb_attached("usb-serial"));
        assert_ne!(state.device_revision(), before_revision);
    }

    #[test]
    fn detach_usb_transport_removes_associated_forwards() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        let resolved = state
            .install_forward(HostSelector::Serial("usb-serial"), "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let selected = state.select_serial("usb-serial").unwrap();

        state.detach_selected_transport(&selected).unwrap();

        assert_eq!(state.list_forwards(), "");
        assert_tcp_port_released(&resolved);
    }

    #[test]
    fn attach_detach_usb_state_errors_match_aosp() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        let selected = state.select_serial("usb-serial").unwrap();

        let err = state.attach_selected_transport(&selected).unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "transport usb-serial is not detached")
        );

        state.detach_selected_transport(&selected).unwrap();
        let detached = state.select_serial("usb-serial").unwrap();
        let err = state.detach_selected_transport(&detached).unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "transport usb-serial is already detached")
        );
    }

    #[test]
    fn attach_detached_usb_transport_can_reconnect_via_stub() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        let selected = state.select_serial("usb-serial").unwrap();
        state.detach_selected_transport(&selected).unwrap();
        let detached = state.select_serial("usb-serial").unwrap();

        let response = state
            .attach_selected_transport_with(&detached, |_state, info| {
                let mut attached = info.clone();
                attached.state = ConnectionState::Device;
                Ok(Transport::fake(attached))
            })
            .unwrap();

        assert_eq!(response, "usb-serial attached");
        assert!(state.is_usb_attached("usb-serial"));
        let devices = state.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, 7);
        assert_eq!(devices[0].serial, "usb-serial");
        assert_eq!(devices[0].state, ConnectionState::Device);
    }

    #[test]
    fn attach_failure_restores_detached_policy_state() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        let selected = state.select_serial("usb-serial").unwrap();
        state.detach_selected_transport(&selected).unwrap();
        let detached = state.select_serial("usb-serial").unwrap();

        let err = state
            .attach_selected_transport_with(&detached, |_state, _info| {
                Err(AdbError::Server("claim failed".to_string()))
            })
            .unwrap_err();

        assert!(matches!(err, AdbError::Server(message) if message == "claim failed"));
        assert!(!state.is_usb_attached("usb-serial"));
        assert_eq!(
            state.select_serial("usb-serial").unwrap().state,
            ConnectionState::Detached
        );
    }

    #[test]
    fn winapi_usb_transport_keeps_official_unsupported_detach_message() {
        let state = test_state();
        add_fake_transport_full(
            &state,
            TransportInfo {
                id: 7,
                serial: "usb-native".to_string(),
                devpath: Some("usb:winapi:\\\\?\\usb#vid_18d1&pid_4ee7".to_string()),
                connection_type: transport::TransportConnectionType::Usb,
                negotiated_speed_mbps: 480,
                max_speed_mbps: 5_000,
                state: ConnectionState::Device,
                product: None,
                model: None,
                device: None,
                features: None,
                max_payload: protocol::MAX_PAYLOAD,
                protocol_version: protocol::A_VERSION,
            },
        );
        let selected = state.select_serial("usb-native").unwrap();

        let err = state.detach_selected_transport(&selected).unwrap_err();

        assert!(
            matches!(err, AdbError::Server(message) if message == "attach/detach not supported!")
        );
    }

    #[test]
    fn host_prefix_detach_uses_usb_lifecycle_when_supported() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:usb-serial:detach",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString(
                "usb-serial detached".to_string()
            ))
        );
        assert_eq!(
            state.select_serial("usb-serial").unwrap().state,
            ConnectionState::Detached
        );
    }

    #[test]
    fn selected_transport_detach_writes_official_protocol_string() {
        let state = test_state();
        add_fake_detachable_usb_transport(&state, 7, "usb-serial", ConnectionState::Device);
        let mut out = Vec::new();
        let mut selected = None;

        assert_eq!(
            handle_service(
                &mut out,
                "host:tport:any",
                Arc::clone(&state),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap(),
            ServiceAction::Continue
        );
        let action = handle_service(
            &mut out,
            "host:detach",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(action, ServiceAction::Close);
        assert_eq!(&out[..4], b"OKAY");
        assert_eq!(u64::from_le_bytes(out[4..12].try_into().unwrap()), 7);
        assert_eq!(&out[12..16], b"OKAY");
        assert_eq!(
            protocol::read_protocol_string(&mut &out[16..]).unwrap(),
            "usb-serial detached"
        );
        assert_eq!(
            state.select_serial("usb-serial").unwrap().state,
            ConnectionState::Detached
        );
    }

    #[test]
    fn host_prefix_attach_detach_use_official_unsupported_messages() {
        let state = test_state();
        add_fake_transport_with_state(&state, 7, "serial-1", ConnectionState::Device, None);

        let err = handle_host_prefixed_service(
            "host-serial:serial-1:detach",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "attach/detach not supported!")
        );

        let err = handle_host_prefixed_service(
            "host-serial:serial-1:attach",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "attach/detach not supported")
        );
    }

    #[test]
    fn device_tracker_proto_text_snapshot_uses_protocol_string() {
        let state = test_state();
        add_fake_transport_with_state(&state, 7, "serial-1", ConnectionState::Device, None);
        let mut out = Vec::new();

        write_device_tracker_snapshot(&mut out, &state.list(), DeviceTrackerOutput::ProtoText)
            .unwrap();

        let body = protocol::read_protocol_string(&mut &out[..]).unwrap();
        assert!(body.contains("device {"));
        assert!(body.contains("serial: \"serial-1\""));
        assert!(body.contains("state: DEVICE"));
        assert!(body.contains("transport_id: 7"));
    }

    #[test]
    fn device_tracker_proto_binary_snapshot_uses_protocol_bytes() {
        let state = test_state();
        add_fake_transport_with_state(&state, 7, "serial-1", ConnectionState::Device, None);
        let mut out = Vec::new();

        write_device_tracker_snapshot(&mut out, &state.list(), DeviceTrackerOutput::ProtoBinary)
            .unwrap();

        let body = protocol::read_protocol_bytes(&mut &out[..]).unwrap();
        assert_eq!(body[0], 0x0a);
        assert!(body.windows("serial-1".len()).any(|w| w == b"serial-1"));
    }

    #[test]
    fn device_tracker_outputs_share_aosp_transport_order() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "socket-a",
            TransportConnectionType::Socket,
            ConnectionState::Device,
            None,
        );
        add_fake_transport_with_type(
            &state,
            2,
            "usb-z",
            TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        add_fake_transport_with_type(
            &state,
            3,
            "usb-a",
            TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        let devices = state.list();

        for output in [
            DeviceTrackerOutput::ShortText,
            DeviceTrackerOutput::LongText,
            DeviceTrackerOutput::ProtoText,
        ] {
            let mut out = Vec::new();
            write_device_tracker_snapshot(&mut out, &devices, output).unwrap();
            let body = protocol::read_protocol_string(&mut &out[..]).unwrap();
            assert_serial_order(body.as_bytes());
        }

        let mut out = Vec::new();
        write_device_tracker_snapshot(&mut out, &devices, DeviceTrackerOutput::ProtoBinary)
            .unwrap();
        let body = protocol::read_protocol_bytes(&mut &out[..]).unwrap();
        assert_serial_order(&body);
    }

    fn assert_serial_order(body: &[u8]) {
        let position = |serial: &[u8]| {
            body.windows(serial.len())
                .position(|window| window == serial)
                .unwrap()
        };
        assert!(position(b"usb-a") < position(b"usb-z"));
        assert!(position(b"usb-z") < position(b"socket-a"));
    }

    #[test]
    fn host_prefixed_get_state_uses_registry() {
        let state = test_state();
        add_fake_transport(&state, 1, "127.0.0.1:5555");

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:127.0.0.1:5555:get-state",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("device".to_string()))
        );
    }

    #[test]
    fn host_serial_forward_preserves_colons_in_request() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        let response = handle_host_prefixed_service(
            "host-serial:serial-1:forward:tcp:0;tcp:9000",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap();

        let Some(HostResponse::Status {
            resolved_port: Some(port),
        }) = response
        else {
            panic!("host-serial forward did not return resolved tcp port");
        };
        assert_eq!(
            state.list_forwards(),
            format!("serial-1 tcp:{port} tcp:9000\n")
        );
        state.remove_all_forwards();
    }

    #[test]
    fn host_serial_selector_matches_local_target_variants_like_aosp() {
        let state = test_state();
        add_fake_transport(&state, 1, "192.0.2.10:5555");

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:tcp:192.0.2.10:get-state",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("device".to_string()))
        );
    }

    #[test]
    fn host_serial_selector_matches_devpath_and_qualified_properties() {
        let state = test_state();
        add_fake_transport_full(
            &state,
            TransportInfo {
                id: 1,
                serial: "usb-serial".to_string(),
                devpath: Some("usb:1:2:18d1:4ee7:3".to_string()),
                connection_type: transport::TransportConnectionType::Usb,
                negotiated_speed_mbps: 480,
                max_speed_mbps: 5_000,
                state: ConnectionState::Device,
                product: Some("sdk_gphone64_x86_64".to_string()),
                model: Some("Pixel 8 Pro".to_string()),
                device: Some("husky".to_string()),
                features: Some("shell_v2".to_string()),
                max_payload: protocol::MAX_PAYLOAD,
                protocol_version: protocol::A_VERSION,
            },
        );

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:model:Pixel_8_Pro:get-serialno",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("usb-serial".to_string()))
        );
        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:usb:1:2:18d1:4ee7:3:features",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("shell_v2".to_string()))
        );
    }

    #[test]
    fn host_serial_selector_rejects_ambiguous_targets_like_aosp() {
        let state = test_state();
        for id in [1, 2] {
            add_fake_transport_full(
                &state,
                TransportInfo {
                    id,
                    serial: format!("serial-{id}"),
                    devpath: None,
                    connection_type: transport::TransportConnectionType::Usb,
                    negotiated_speed_mbps: 480,
                    max_speed_mbps: 5_000,
                    state: ConnectionState::Device,
                    product: Some("same_product".to_string()),
                    model: None,
                    device: None,
                    features: None,
                    max_payload: protocol::MAX_PAYLOAD,
                    protocol_version: protocol::A_VERSION,
                },
            );
        }

        let err = handle_host_prefixed_service(
            "host-serial:product:same_product:get-state",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(reason) if reason == "more than one device with serial product:same_product"
        ));
    }

    #[test]
    fn host_prefixed_get_devpath_reports_unknown_when_transport_has_no_devpath() {
        let state = test_state();
        add_fake_transport(&state, 1, "127.0.0.1:5555");

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:127.0.0.1:5555:get-devpath",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("unknown".to_string()))
        );
    }

    #[test]
    fn host_prefixed_get_devpath_uses_usb_transport_devpath() {
        let state = test_state();
        add_fake_transport_with_type_and_devpath(
            &state,
            1,
            "usb-serial",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
            Some("usb:001:002:18d1:4ee7:3"),
        );

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:usb-serial:get-devpath",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString(
                "usb:001:002:18d1:4ee7:3".to_string()
            ))
        );
    }

    #[test]
    fn host_prefixed_get_transport_id_returns_selected_transport_id() {
        let state = test_state();
        add_fake_transport(&state, 42, "usb-serial");

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:usb-serial:get-transport-id",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("42".to_string()))
        );
    }

    #[test]
    fn host_prefixed_features_uses_selected_transport() {
        let state = test_state();
        add_fake_transport_with_state(
            &state,
            1,
            "serial-1",
            ConnectionState::Device,
            Some("shell_v2,cmd"),
        );

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:serial-1:features",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("shell_v2,cmd".to_string()))
        );
    }

    #[test]
    fn host_prefixed_reconnect_reports_state_and_removes_transport() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        assert_eq!(
            handle_host_prefixed_service(
                "host-serial:serial-1:reconnect",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString(
                "reconnecting serial-1 [device]\n".to_string()
            ))
        );
        assert!(state.list().is_empty());
    }

    #[test]
    fn host_transport_id_selects_registry_entry() {
        let state = test_state();
        add_fake_transport(&state, 7, "serial-7");
        add_fake_transport(&state, 9, "serial-9");

        assert_eq!(
            handle_host_prefixed_service(
                "host-transport-id:7:get-serialno",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("serial-7".to_string()))
        );
    }

    #[test]
    fn host_local_prefixed_service_selects_socket_transport() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        add_fake_transport(&state, 2, "127.0.0.1:5555");

        assert_eq!(
            handle_host_prefixed_service(
                "host-local:get-serialno",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap(),
            Some(HostResponse::ProtocolString("127.0.0.1:5555".to_string()))
        );
    }

    #[test]
    fn host_local_prefixed_service_uses_official_no_emulators_error() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );

        assert_eq!(
            handle_host_prefixed_service("host-local:get-state", &state, &AtomicBool::new(false))
                .unwrap_err()
                .to_string(),
            "no emulators found"
        );
    }

    #[test]
    fn transport_id_service_selects_registry_entry() {
        let state = test_state();
        add_fake_transport(&state, 7, "serial-7");
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:transport-id:7",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(action, ServiceAction::Continue);
        assert_eq!(out, b"OKAY");
        assert_eq!(selected.unwrap().id, 7);
    }

    #[test]
    fn tport_any_returns_selected_transport_id_after_okay() {
        let state = test_state();
        add_fake_transport(&state, 7, "serial-7");
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:tport:any",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        expected.extend_from_slice(&7_u64.to_le_bytes());
        assert_eq!(action, ServiceAction::Continue);
        assert_eq!(out, expected);
        assert_eq!(selected.unwrap().serial, "serial-7");
    }

    #[test]
    fn host_features_after_tport_returns_selected_transport_features() {
        let state = test_state();
        add_fake_transport_with_state(
            &state,
            7,
            "serial-7",
            ConnectionState::Device,
            Some("shell_v2,cmd"),
        );
        let mut out = Vec::new();
        let mut selected = None;

        assert_eq!(
            handle_service(
                &mut out,
                "host:tport:any",
                Arc::clone(&state),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap(),
            ServiceAction::Continue
        );
        assert_eq!(
            handle_service(
                &mut out,
                "host:features",
                Arc::clone(&state),
                Arc::new(AtomicBool::new(false)),
                &mut selected,
            )
            .unwrap(),
            ServiceAction::Close
        );

        let mut expected = b"OKAY".to_vec();
        expected.extend_from_slice(&7_u64.to_le_bytes());
        expected.extend_from_slice(b"OKAY");
        protocol::write_protocol_string(&mut expected, "shell_v2,cmd").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn tport_serial_selects_registry_entry() {
        let state = test_state();
        add_fake_transport(&state, 7, "serial-7");
        add_fake_transport(&state, 9, "serial-9");
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:tport:serial:serial-9",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        expected.extend_from_slice(&9_u64.to_le_bytes());
        assert_eq!(action, ServiceAction::Continue);
        assert_eq!(out, expected);
        assert_eq!(selected.unwrap().id, 9);
    }

    #[test]
    fn tport_serial_matches_local_target_variant() {
        let state = test_state();
        add_fake_transport(&state, 7, "192.0.2.10:5555");
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:tport:serial:udp:192.0.2.10",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        expected.extend_from_slice(&7_u64.to_le_bytes());
        assert_eq!(action, ServiceAction::Continue);
        assert_eq!(out, expected);
        assert_eq!(selected.unwrap().serial, "192.0.2.10:5555");
    }

    #[test]
    fn tport_failure_uses_fail_without_transport_id() {
        let state = test_state();
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:tport:any",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(action, ServiceAction::Close);
        assert_eq!(out, b"FAIL001Ano devices/emulators found");
        assert!(selected.is_none());
    }

    #[test]
    fn transport_local_service_selects_socket_transport() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        add_fake_transport(&state, 2, "127.0.0.1:5555");
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:transport-local",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(action, ServiceAction::Continue);
        assert_eq!(out, b"OKAY");
        assert_eq!(selected.unwrap().serial, "127.0.0.1:5555");
    }

    #[test]
    fn transport_local_service_rejects_usb_only_registry() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        let mut out = Vec::new();
        let mut selected = None;

        let action = handle_service(
            &mut out,
            "host:transport-local",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        assert_eq!(action, ServiceAction::Close);
        assert_eq!(out, b"FAIL0012no emulators found");
        assert!(selected.is_none());
    }

    #[test]
    fn reconnect_offline_removes_offline_and_unauthorized_transports() {
        let state = test_state();
        add_fake_transport_with_state(&state, 1, "online", ConnectionState::Device, None);
        add_fake_transport_with_state(&state, 2, "offline", ConnectionState::Offline, None);
        add_fake_transport_with_state(
            &state,
            3,
            "unauthorized",
            ConnectionState::Unauthorized,
            None,
        );

        assert_eq!(
            state.reconnect_offline(),
            "reconnecting offline\nreconnecting unauthorized"
        );
        assert_eq!(state.list().len(), 1);
        assert_eq!(state.list()[0].serial, "online");
    }

    #[test]
    fn reconnect_offline_host_service_uses_official_protocol_string() {
        let state = test_state();
        add_fake_transport_with_state(&state, 1, "offline", ConnectionState::Offline, None);
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            "host:reconnect-offline",
            Arc::clone(&state),
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let mut expected = b"OKAY".to_vec();
        protocol::write_protocol_string(&mut expected, "reconnecting offline").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn wait_spec_parses_transport_and_states() {
        assert_eq!(
            WaitSpec::parse("wait-for-any-device-recovery").unwrap(),
            WaitSpec {
                transport: WaitTransport::Any,
                states: vec![WaitState::Device, WaitState::Recovery],
            }
        );
        assert!(matches!(
            WaitSpec::parse("wait-for-device"),
            Err(AdbError::Server(reason)) if reason == "short wait-for-: device"
        ));
        assert!(matches!(
            WaitSpec::parse("wait-for-any-unknown"),
            Err(AdbError::Server(reason)) if reason == "bad wait-for- state: any-unknown"
        ));
    }

    #[test]
    fn wait_for_device_returns_immediately_when_state_matches() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        assert!(
            handle_host_prefixed_service(
                "host:wait-for-any-device",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn wait_for_any_device_fails_when_target_is_ambiguous() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        add_fake_transport(&state, 2, "serial-2");

        let err = handle_host_prefixed_service(
            "host:wait-for-any-device",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(reason) if reason == "more than one device/emulator"
        ));
    }

    #[test]
    fn wait_for_local_device_uses_socket_transports() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        add_fake_transport(&state, 2, "127.0.0.1:5555");

        assert!(state.wait_spec_is_satisfied(
            HostSelector::Any,
            &WaitSpec::parse("wait-for-local-device").unwrap()
        ));
        assert!(!state.wait_spec_is_satisfied(
            HostSelector::Any,
            &WaitSpec::parse("wait-for-usb-recovery").unwrap()
        ));
    }

    #[test]
    fn wait_for_disconnect_succeeds_when_single_target_is_offline() {
        let state = test_state();
        add_fake_transport_with_state(&state, 1, "serial-1", ConnectionState::Offline, None);

        assert!(
            handle_host_prefixed_service(
                "host:wait-for-any-disconnect",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn wait_for_usb_device_matches_usb_transport() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );

        assert!(state.wait_spec_is_satisfied(
            HostSelector::Any,
            &WaitSpec::parse("wait-for-usb-device").unwrap()
        ));
        assert!(!state.wait_spec_is_satisfied(
            HostSelector::Any,
            &WaitSpec::parse("wait-for-local-device").unwrap()
        ));
    }

    #[test]
    fn wait_for_explicit_any_is_not_narrowed_by_host_usb_prefix() {
        let state = test_state();
        add_fake_transport(&state, 1, "127.0.0.1:5555");

        assert!(
            handle_host_prefixed_service(
                "host-usb:wait-for-any-device",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn wait_for_serial_prefix_ignores_wait_transport_filter_like_aosp() {
        let state = test_state();
        add_fake_transport(&state, 1, "127.0.0.1:5555");

        assert!(
            handle_host_prefixed_service(
                "host-serial:127.0.0.1:5555:wait-for-usb-device",
                &state,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn wait_for_usb_device_fails_when_usb_target_is_ambiguous() {
        let state = test_state();
        add_fake_transport_with_type(
            &state,
            1,
            "usb-1",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );
        add_fake_transport_with_type(
            &state,
            2,
            "usb-2",
            transport::TransportConnectionType::Usb,
            ConnectionState::Device,
            None,
        );

        let err = handle_host_prefixed_service(
            "host:wait-for-usb-device",
            &state,
            &AtomicBool::new(false),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(reason) if reason == "more than one USB device"
        ));
    }

    #[test]
    fn parse_forward_rejects_official_bad_specs() {
        assert_eq!(
            parse_forward_spec("tcp:1234;tcp:9000").unwrap(),
            ("tcp:1234", "tcp:9000")
        );

        for spec in [
            "",
            "tcp:1234",
            ";tcp:9000",
            "tcp:1234;",
            "tcp:1234;tcp:9000;extra",
            "tcp:1234;*smartsocket",
        ] {
            let err = parse_forward_spec(spec).unwrap_err();
            assert!(
                matches!(err, AdbError::Server(message) if message == format!("bad forward: {spec}"))
            );
        }
    }

    #[test]
    fn parse_killforward_rejects_official_bad_specs() {
        assert_eq!(parse_killforward_spec("tcp:1234").unwrap(), "tcp:1234");

        for spec in ["", "tcp:1234;extra"] {
            let err = parse_killforward_spec(spec).unwrap_err();
            assert!(
                matches!(err, AdbError::Server(message) if message == format!("bad killforward: {spec}"))
            );
        }
    }

    #[test]
    fn host_forward_bad_spec_writes_fail_reason() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            "host:forward:tcp:1234;*smartsocket",
            state,
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let err = protocol::read_status(&mut &out[..]).unwrap_err();
        assert!(matches!(
            err,
            AdbError::Server(message) if message == "bad forward: tcp:1234;*smartsocket"
        ));
    }

    #[test]
    fn host_killforward_bad_spec_writes_fail_reason() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            "host:killforward:",
            state,
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let err = protocol::read_status(&mut &out[..]).unwrap_err();
        assert!(matches!(
            err,
            AdbError::Server(message) if message == "bad killforward: "
        ));
    }

    #[test]
    fn forward_bind_failure_uses_official_error_prefix() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut out = Vec::new();
        let mut selected = None;

        handle_service(
            &mut out,
            &format!("host:forward:tcp:{port};shell:echo occupied"),
            state,
            Arc::new(AtomicBool::new(false)),
            &mut selected,
        )
        .unwrap();

        let err = protocol::read_status(&mut &out[..]).unwrap_err();
        assert!(matches!(
            err,
            AdbError::Server(message) if message.starts_with("cannot bind listener: ")
        ));
    }

    #[test]
    fn forward_tcp_zero_returns_resolved_port_and_lists_rule() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        let resolved = state
            .install_forward(HostSelector::Any, "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();

        assert!(resolved.parse::<u16>().unwrap() > 0);
        assert_eq!(
            state.list_forwards(),
            format!("serial-1 tcp:{resolved} tcp:9000\n")
        );
        state.remove_all_forwards();
    }

    #[test]
    fn forward_tcp_listener_honors_listen_all() {
        let (loopback, _, _) = bind_forward_listener("tcp:0", false).unwrap();
        let loopback_address = match loopback {
            ForwardListener::Tcp(listener) => listener.local_addr().unwrap(),
            #[cfg(unix)]
            _ => panic!("tcp forward 未创建 TCP listener"),
        };
        assert!(matches!(
            loopback_address,
            SocketAddr::V4(address) if *address.ip() == Ipv4Addr::LOCALHOST
        ));

        let (all_interfaces, _, _) = bind_forward_listener("tcp:0", true).unwrap();
        let all_interfaces_address = match all_interfaces {
            ForwardListener::Tcp(listener) => listener.local_addr().unwrap(),
            #[cfg(unix)]
            _ => panic!("tcp forward 未创建 TCP listener"),
        };
        assert!(matches!(
            all_interfaces_address,
            SocketAddr::V4(address) if *address.ip() == Ipv4Addr::UNSPECIFIED
        ));
    }

    #[test]
    fn forward_vsock_local_spec_matches_official_server_shape() {
        assert_eq!(canonical_forward_local("vsock:0").unwrap(), "vsock:0");
        assert_eq!(canonical_forward_local("vsock:5555").unwrap(), "vsock:5555");
        assert!(matches!(
            canonical_forward_local("vsock:5:5555").unwrap_err(),
            AdbError::Server(message)
                if message == "given vsock server socket string was invalid"
        ));
        assert!(matches!(
            canonical_forward_local("vsock:-1").unwrap_err(),
            AdbError::Server(message) if message == "vsock port was negative."
        ));
        assert!(matches!(
            canonical_forward_local("vsock:2147483648").unwrap_err(),
            AdbError::Server(message) if message == "could not parse vsock port"
        ));
    }

    #[test]
    fn forward_unavailable_and_unknown_socket_errors_match_aosp() {
        assert!(matches!(
            canonical_forward_local("localreserved:adb-rust").unwrap_err(),
            AdbError::Server(message)
                if message
                    == "attempted to listen on unavailable socket type: localreserved:adb-rust"
        ));
        assert!(matches!(
            canonical_forward_local("unknown:value").unwrap_err(),
            AdbError::Server(message) if message == "unknown socket specification:unknown:value"
        ));
        assert!(matches!(
            canonical_forward_local("acceptfd:2147483648").unwrap_err(),
            AdbError::Server(message) if message == "invalid fd"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn forward_acceptfd_reports_plain_platform_error_on_windows() {
        match bind_forward_listener("acceptfd:42", false) {
            Err(AdbError::Server(message)) => {
                assert_eq!(message, "socket activation not supported under Windows")
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("acceptfd listener unexpectedly succeeded"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn forward_vsock_is_rejected_on_non_linux() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        let err = state
            .install_forward(HostSelector::Any, "vsock:0;tcp:9000", false)
            .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(message) if message == "vsock is only supported on linux"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn forward_localfilesystem_lists_rule_and_cleans_socket() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "adb_rust_forward_{}_{}.sock",
            std::process::id(),
            stamp
        ));
        std::fs::write(&path, b"stale").unwrap();
        let spec = format!("localfilesystem:{};tcp:9000", path.display());

        let resolved = state
            .install_forward(HostSelector::Any, &spec, false)
            .unwrap();

        assert!(resolved.is_none());
        assert!(path.exists());
        assert_eq!(
            state.list_forwards(),
            format!("serial-1 localfilesystem:{} tcp:9000\n", path.display())
        );
        state.remove_all_forwards();
        for _ in 0..50 {
            if !path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = std::fs::remove_file(&path);
        panic!("forward localfilesystem socket was not cleaned up");
    }

    #[cfg(unix)]
    #[test]
    fn forward_local_alias_uses_filesystem_namespace() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let path = std::env::temp_dir().join(format!(
            "adb_rust_forward_local_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let spec = format!("local:{};tcp:9000", path.display());

        assert!(
            state
                .install_forward(HostSelector::Any, &spec, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.list_forwards(),
            format!("serial-1 local:{} tcp:9000\n", path.display())
        );
        state.remove_all_forwards();
        for _ in 0..50 {
            if !path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = std::fs::remove_file(&path);
        panic!("forward local socket was not cleaned up");
    }

    #[cfg(unix)]
    #[test]
    fn forward_acceptfd_duplicates_inherited_listener() {
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fd = listener.as_raw_fd();
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(original_flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags & !libc::FD_CLOEXEC) },
            0
        );

        let (forward, local, resolved) =
            bind_forward_listener(&format!("acceptfd:{fd}"), false).unwrap();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags) }, 0);
        assert_eq!(local, format!("acceptfd:{fd}"));
        assert!(resolved.is_none());
        assert_eq!(
            canonical_forward_local(&format!("acceptfd:{fd}")).unwrap(),
            format!("acceptfd:{fd}")
        );

        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(b"x").unwrap();
        });
        let ForwardListener::Inherited(listener) = forward else {
            panic!("acceptfd 未创建 inherited listener");
        };
        let mut stream = listener.accept().unwrap();
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
        writer.join().unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn forward_localfilesystem_is_rejected_on_non_unix() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        let err = state
            .install_forward(
                HostSelector::Any,
                "localfilesystem:/tmp/adb-rust.sock;tcp:9000",
                false,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(message)
                if message
                    == "attempted to listen on unavailable socket type: localfilesystem:/tmp/adb-rust.sock"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forward_localabstract_lists_rule_and_binds_name() {
        use std::os::linux::net::SocketAddrExt;

        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("adb_rust_forward_{}_{}", std::process::id(), stamp);
        let spec = format!("localabstract:{name};tcp:9000");

        let resolved = state
            .install_forward(HostSelector::Any, &spec, false)
            .unwrap();

        assert!(resolved.is_none());
        assert_eq!(
            state.list_forwards(),
            format!("serial-1 localabstract:{name} tcp:9000\n")
        );
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        assert!(std::os::unix::net::UnixListener::bind_addr(&addr).is_err());
        state.remove_all_forwards();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn forward_localabstract_is_rejected_on_non_linux() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");

        let err = state
            .install_forward(HostSelector::Any, "localabstract:adb-rust;tcp:9000", false)
            .unwrap_err();

        assert!(matches!(
            err,
            AdbError::Server(message)
                if message
                    == "attempted to listen on unavailable socket type: localabstract:adb-rust"
        ));
    }

    #[test]
    fn forward_no_rebind_rejects_existing_local() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let resolved = state
            .install_forward(HostSelector::Any, "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let duplicate = format!("tcp:{resolved};tcp:9001");

        let err = state
            .install_forward(HostSelector::Any, &duplicate, true)
            .unwrap_err();

        assert!(
            matches!(err, AdbError::Server(message) if message == "cannot rebind existing socket")
        );
        state.remove_all_forwards();
    }

    #[test]
    fn forward_rebinds_existing_local_across_transports_like_official() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        add_fake_transport(&state, 2, "serial-2");
        let resolved = state
            .install_forward(HostSelector::Serial("serial-1"), "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let replacement = format!("tcp:{resolved};tcp:9001");

        let status = state
            .install_forward(HostSelector::Serial("serial-2"), &replacement, false)
            .unwrap();

        assert!(status.is_none());
        assert_eq!(
            state.list_forwards(),
            format!("serial-2 tcp:{resolved} tcp:9001\n")
        );
        state.remove_all_forwards();
    }

    #[test]
    fn disconnected_transport_removes_associated_forward_listener() {
        let state = test_state();
        add_fake_transport(&state, 1, "192.0.2.10:5555");
        let resolved = state
            .install_forward(HostSelector::Any, "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();

        assert_eq!(
            state.disconnect(Some("192.0.2.10:5555")).unwrap(),
            "disconnected 192.0.2.10:5555"
        );

        assert_eq!(state.list_forwards(), "");
        assert_tcp_port_released(&resolved);
    }

    #[test]
    fn replacement_transport_removes_old_forward_listener() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        let resolved = state
            .install_forward(HostSelector::Any, "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();

        state.register_transport(Transport::fake(TransportInfo {
            id: 2,
            serial: "serial-1".to_string(),
            devpath: None,
            connection_type: transport::TransportConnectionType::Socket,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Device,
            product: None,
            model: None,
            device: None,
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        }));

        assert_eq!(state.list_forwards(), "");
        assert_eq!(state.list()[0].id, 2);
        assert_tcp_port_released(&resolved);
    }

    #[test]
    fn killforward_removes_local_listener_regardless_of_selected_transport() {
        let state = test_state();
        add_fake_transport(&state, 1, "serial-1");
        add_fake_transport(&state, 2, "serial-2");
        let resolved = state
            .install_forward(HostSelector::Serial("serial-1"), "tcp:0;tcp:9000", false)
            .unwrap()
            .unwrap();
        let service = format!("host-serial:serial-2:killforward:tcp:{resolved}");

        let response =
            handle_host_prefixed_service(&service, &state, &AtomicBool::new(false)).unwrap();

        assert_eq!(
            response,
            Some(HostResponse::Status {
                resolved_port: None
            })
        );
        assert_eq!(state.list_forwards(), "");
    }
}
