use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub const ADB_SERVICE: &str = "_adb._tcp";
pub const TLS_CONNECT_SERVICE: &str = "_adb-tls-connect._tcp";
pub const TLS_PAIRING_SERVICE: &str = "_adb-tls-pairing._tcp";

const DEFAULT_AUTO_CONNECT: &str = "adb-tls-connect";
const ADB_SERVICE_DOMAIN: &str = "_adb._tcp.local.";
const TLS_CONNECT_SERVICE_DOMAIN: &str = "_adb-tls-connect._tcp.local.";
const TLS_PAIRING_SERVICE_DOMAIN: &str = "_adb-tls-pairing._tcp.local.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsInstance {
    pub instance_name: String,
    pub service_name: String,
    pub transport_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub instance_name: String,
    pub service_name: String,
    pub address: String,
    pub port: u16,
}

impl ServiceInfo {
    pub fn new(instance_name: &str, service_name: &str, address: &str, port: u16) -> Self {
        Self {
            instance_name: instance_name.to_string(),
            service_name: service_name.to_string(),
            address: address.to_string(),
            port,
        }
    }
}

pub struct DiscoveryState {
    enabled: bool,
    services: Arc<Mutex<Vec<ServiceInfo>>>,
    shutdown: Arc<AtomicBool>,
    daemon: Option<mdns_sd::ServiceDaemon>,
}

pub(crate) type ResolvedServiceHandler = Arc<dyn Fn(ServiceInfo) + Send + Sync + 'static>;

impl DiscoveryState {
    pub fn start() -> Self {
        Self::start_with_handler(Arc::new(|_| {}))
    }

    pub(crate) fn start_with_handler(on_resolved: ResolvedServiceHandler) -> Self {
        if !is_enabled() {
            return Self::disabled();
        }

        let daemon = match mdns_sd::ServiceDaemon::new() {
            Ok(daemon) => daemon,
            Err(err) => {
                eprintln!("adb-rust mdns discovery unavailable: {err}");
                return Self::disabled();
            }
        };

        let services = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut started_browses = 0;
        for service_type in adb_service_domains() {
            match daemon.browse(service_type) {
                Ok(receiver) => {
                    started_browses += 1;
                    spawn_browse_thread(
                        service_type,
                        receiver,
                        Arc::clone(&services),
                        Arc::clone(&shutdown),
                        Arc::clone(&on_resolved),
                    );
                }
                Err(err) => eprintln!("adb-rust mdns browse {service_type} failed: {err}"),
            }
        }

        if started_browses == 0 {
            let _ = daemon.shutdown();
            return Self::disabled();
        }

        Self {
            enabled: true,
            services,
            shutdown,
            daemon: Some(daemon),
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            services: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            daemon: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn services(&self) -> Vec<ServiceInfo> {
        sorted_services(
            &self
                .services
                .lock()
                .expect("mDNS services poisoned")
                .clone(),
        )
    }

    pub fn connect_target(&self, name: &str) -> Option<String> {
        self.connect_service(name)
            .map(|service| format!("{}:{}", service.address, service.port))
    }

    pub fn connect_service(&self, name: &str) -> Option<ServiceInfo> {
        connect_service_info(&self.services(), name)
    }

    pub fn pairing_target(&self, name: &str) -> Option<String> {
        pairing_service_info(&self.services(), name)
            .map(|service| format!("{}:{}", service.address, service.port))
    }

    #[cfg(test)]
    pub fn replace_services_for_test(&self, services: Vec<ServiceInfo>) {
        *self.services.lock().expect("mDNS services poisoned") = services;
    }
}

impl Drop for DiscoveryState {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(daemon) = &self.daemon {
            for service_type in adb_service_domains() {
                let _ = daemon.stop_browse(service_type);
            }
            if let Ok(status) = daemon.shutdown() {
                let _ = status.recv_timeout(std::time::Duration::from_millis(200));
            }
        }
    }
}

pub fn is_enabled() -> bool {
    is_enabled_for_env(std::env::var("ADB_MDNS").ok().as_deref())
}

fn is_enabled_for_env(adb_mdns: Option<&str>) -> bool {
    adb_mdns != Some("0")
}

pub fn discovery_enabled() -> bool {
    is_enabled()
}

pub fn check_message(enabled: bool) -> &'static str {
    if enabled {
        "mdns daemon version [Openscreen discovery 0.0.0]"
    } else {
        "ERROR: mdns discovery disabled"
    }
}

pub fn format_services(services: &[ServiceInfo]) -> String {
    let mut result = String::new();
    for service in services {
        let _ = writeln!(
            result,
            "{}\t{}\t{}:{}",
            service.instance_name, service.service_name, service.address, service.port
        );
    }
    result
}

pub fn connect_service_info(services: &[ServiceInfo], name: &str) -> Option<ServiceInfo> {
    let parsed = parse_instance_name(name)?;
    if !parsed.service_name.is_empty() {
        let service_name = canonical_service_name(&parsed.service_name, &parsed.transport_type)?;
        if service_name == TLS_PAIRING_SERVICE {
            return None;
        }
        return find_service(services, &parsed.instance_name, service_name).cloned();
    }

    find_service(services, &parsed.instance_name, TLS_CONNECT_SERVICE)
        .or_else(|| find_service(services, &parsed.instance_name, ADB_SERVICE))
        .cloned()
}

pub fn pairing_service_info(services: &[ServiceInfo], name: &str) -> Option<ServiceInfo> {
    let parsed = parse_instance_name(name)?;
    if !parsed.service_name.is_empty() {
        let service_name = canonical_service_name(&parsed.service_name, &parsed.transport_type)?;
        if service_name != TLS_PAIRING_SERVICE {
            return None;
        }
    }

    find_service(services, &parsed.instance_name, TLS_PAIRING_SERVICE).cloned()
}

pub fn filter_auto_connect_services<'a>(
    services: &'a [ServiceInfo],
    adb_mdns_auto_connect: Option<&str>,
) -> Vec<&'a ServiceInfo> {
    let allowed = auto_connect_service_names(adb_mdns_auto_connect);
    services
        .iter()
        .filter(|service| auto_connect_service_allowed(service, &allowed))
        .collect()
}

fn auto_connect_service_names(adb_mdns_auto_connect: Option<&str>) -> Vec<String> {
    let default = vec![DEFAULT_AUTO_CONNECT.to_string()];
    let Some(value) = adb_mdns_auto_connect else {
        return default;
    };
    match value {
        "0" => return Vec::new(),
        "all" => return vec!["adb".to_string(), DEFAULT_AUTO_CONNECT.to_string()],
        _ => {}
    }

    let allowed: Vec<String> = value
        .split(',')
        .filter(|name| matches!(*name, "adb" | "adb-tls-connect" | "adb-tls-pairing"))
        .map(str::to_string)
        .collect();
    if allowed.is_empty() { default } else { allowed }
}

fn auto_connect_service_allowed(service: &ServiceInfo, allowed: &[String]) -> bool {
    if service.instance_name.starts_with("adb-EMULATOR") {
        return false;
    }
    let name = normalize_service_name(&service.service_name);
    matches!(name.as_str(), "adb" | "adb-tls-connect")
        && allowed.iter().any(|allowed| allowed == &name)
}

pub fn should_auto_connect<F>(
    service: &ServiceInfo,
    adb_mdns_auto_connect: Option<&str>,
    is_known_host: F,
) -> bool
where
    F: FnOnce(&str) -> bool,
{
    if !auto_connect_service_allowed(service, &auto_connect_service_names(adb_mdns_auto_connect)) {
        return false;
    }
    normalize_service_name(&service.service_name) != "adb-tls-connect"
        || is_known_host(&service.instance_name)
}

pub fn connect_service_name(service: &ServiceInfo) -> String {
    format!("{}.{}", service.instance_name, service.service_name)
}

fn normalize_service_name(value: &str) -> String {
    let trimmed = value
        .trim()
        .trim_end_matches(".local")
        .trim_start_matches('_');
    let without_transport = trimmed
        .strip_suffix("._tcp")
        .or_else(|| trimmed.strip_suffix("._udp"))
        .unwrap_or(trimmed);
    without_transport.trim_start_matches('_').to_string()
}

fn canonical_service_name(service_name: &str, transport_type: &str) -> Option<&'static str> {
    if transport_type != "tcp" {
        return None;
    }
    match normalize_service_name(service_name).as_str() {
        "adb" => Some(ADB_SERVICE),
        "adb-tls-connect" => Some(TLS_CONNECT_SERVICE),
        "adb-tls-pairing" => Some(TLS_PAIRING_SERVICE),
        _ => None,
    }
}

fn find_service<'a>(
    services: &'a [ServiceInfo],
    instance_name: &str,
    service_name: &str,
) -> Option<&'a ServiceInfo> {
    services.iter().find(|service| {
        service.instance_name == instance_name
            && normalize_service_name(&service.service_name) == normalize_service_name(service_name)
    })
}

fn adb_service_domains() -> [&'static str; 3] {
    [
        ADB_SERVICE_DOMAIN,
        TLS_PAIRING_SERVICE_DOMAIN,
        TLS_CONNECT_SERVICE_DOMAIN,
    ]
}

fn spawn_browse_thread(
    service_type: &'static str,
    receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>,
    services: Arc<Mutex<Vec<ServiceInfo>>>,
    shutdown: Arc<AtomicBool>,
    on_resolved: ResolvedServiceHandler,
) {
    thread::spawn(move || {
        while !shutdown.load(Ordering::SeqCst) {
            let event = match receiver.recv_timeout(std::time::Duration::from_millis(250)) {
                Ok(event) => event,
                Err(_) => continue,
            };
            match event {
                mdns_sd::ServiceEvent::ServiceResolved(service) => {
                    if let Some(service) = service_info_from_resolved(&service) {
                        upsert_service(
                            &mut services.lock().expect("mDNS services poisoned"),
                            service.clone(),
                        );
                        on_resolved(service);
                    }
                }
                mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                    remove_service(
                        &mut services.lock().expect("mDNS services poisoned"),
                        service_type,
                        &fullname,
                    );
                }
                _ => {}
            }
        }
    });
}

fn service_info_from_resolved(service: &mdns_sd::ResolvedService) -> Option<ServiceInfo> {
    let service_name = service_name_from_domain(&service.ty_domain)?;
    let instance_name = instance_name_from_fullname(&service.fullname, service_name)?;
    let address = preferred_ipv4_address(service.get_addresses())?;
    Some(ServiceInfo::new(
        instance_name,
        service_name,
        &address.to_string(),
        service.port,
    ))
}

fn service_name_from_domain(service_type: &str) -> Option<&'static str> {
    let normalized = service_type
        .trim_end_matches(".local.")
        .trim_end_matches('.');
    match normalized {
        ADB_SERVICE => Some(ADB_SERVICE),
        TLS_CONNECT_SERVICE => Some(TLS_CONNECT_SERVICE),
        TLS_PAIRING_SERVICE => Some(TLS_PAIRING_SERVICE),
        _ => None,
    }
}

fn instance_name_from_fullname<'a>(fullname: &'a str, service_name: &str) -> Option<&'a str> {
    let without_local = fullname.trim_end_matches(".local.").trim_end_matches('.');
    let suffix = format!(".{service_name}");
    without_local.strip_suffix(&suffix)
}

fn preferred_ipv4_address(
    addresses: &std::collections::HashSet<mdns_sd::ScopedIp>,
) -> Option<IpAddr> {
    addresses
        .iter()
        .filter_map(|address| match address {
            mdns_sd::ScopedIp::V4(address) => Some(IpAddr::V4(*address.addr())),
            _ => None,
        })
        .min_by_key(|address| address.to_string())
}

fn upsert_service(services: &mut Vec<ServiceInfo>, service: ServiceInfo) {
    services.retain(|existing| {
        existing.instance_name != service.instance_name
            || normalize_service_name(&existing.service_name)
                != normalize_service_name(&service.service_name)
    });
    services.push(service);
}

fn remove_service(services: &mut Vec<ServiceInfo>, service_type: &str, fullname: &str) {
    let Some(service_name) = service_name_from_domain(service_type) else {
        return;
    };
    let Some(instance_name) = instance_name_from_fullname(fullname, service_name) else {
        return;
    };
    services.retain(|service| {
        service.instance_name != instance_name
            || normalize_service_name(&service.service_name) != normalize_service_name(service_name)
    });
}

fn sorted_services(services: &[ServiceInfo]) -> Vec<ServiceInfo> {
    let mut services = services.to_vec();
    services.sort_by(|left, right| {
        left.instance_name
            .cmp(&right.instance_name)
            .then_with(|| left.service_name.cmp(&right.service_name))
            .then_with(|| left.address.cmp(&right.address))
            .then_with(|| left.port.cmp(&right.port))
    });
    services
}

pub fn parse_instance_name(name: &str) -> Option<MdnsInstance> {
    if name.is_empty() {
        return None;
    }

    let mut remaining = name;
    let mut has_local_suffix = false;
    if let Some(stripped) = remaining.strip_suffix(".local.") {
        remaining = stripped;
        has_local_suffix = true;
    } else if let Some(stripped) = remaining.strip_suffix(".local") {
        remaining = stripped;
        has_local_suffix = true;
    }
    if has_local_suffix && remaining.is_empty() {
        return None;
    }

    let mut transport = "";
    if let Some(stripped) = strip_transport_suffix(remaining, "._tcp", has_local_suffix) {
        remaining = stripped;
        transport = "tcp";
    } else if let Some(stripped) = strip_transport_suffix(remaining, "._udp", has_local_suffix) {
        remaining = stripped;
        transport = "udp";
    } else if has_local_suffix {
        return None;
    }

    if remaining.is_empty() {
        return None;
    }

    if transport.is_empty() {
        return Some(MdnsInstance {
            instance_name: remaining.to_string(),
            service_name: String::new(),
            transport_type: String::new(),
        });
    }

    let pos = remaining.rfind('.')?;
    if pos == 0 || pos + 1 == remaining.len() {
        return None;
    }

    Some(MdnsInstance {
        instance_name: remaining[..pos].to_string(),
        service_name: remaining[pos + 1..].to_string(),
        transport_type: transport.to_string(),
    })
}

fn strip_transport_suffix<'a>(
    value: &'a str,
    suffix: &str,
    has_local_suffix: bool,
) -> Option<&'a str> {
    if !has_local_suffix && value.ends_with('.') {
        let suffix_with_dot = format!("{suffix}.");
        value.strip_suffix(&suffix_with_dot)
    } else {
        value.strip_suffix(suffix)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn mdns_enabled_matches_official_env_gate() {
        assert!(is_enabled_for_env(None));
        assert!(is_enabled_for_env(Some("1")));
        assert!(!is_enabled_for_env(Some("0")));
    }

    #[test]
    fn mdns_check_reports_enabled_or_disabled_backend_state() {
        assert_eq!(check_message(false), "ERROR: mdns discovery disabled");
        assert_eq!(
            check_message(true),
            "mdns daemon version [Openscreen discovery 0.0.0]"
        );
    }

    #[test]
    fn service_list_format_matches_adb_mdns_services_body() {
        let services = vec![
            ServiceInfo::new("adb-serial", "_adb._tcp", "192.0.2.10", 5555),
            ServiceInfo::new(
                "adb-serial-AbCd",
                "_adb-tls-connect._tcp",
                "192.0.2.10",
                37099,
            ),
        ];

        assert_eq!(
            format_services(&services),
            "adb-serial\t_adb._tcp\t192.0.2.10:5555\nadb-serial-AbCd\t_adb-tls-connect._tcp\t192.0.2.10:37099\n"
        );
    }

    #[test]
    fn auto_connect_defaults_to_tls_connect() {
        let services = vec![
            ServiceInfo::new("legacy", "_adb._tcp", "192.0.2.10", 5555),
            ServiceInfo::new("tls", "_adb-tls-connect._tcp", "192.0.2.10", 37100),
            ServiceInfo::new("pair", "_adb-tls-pairing._tcp", "192.0.2.10", 37101),
        ];

        let filtered = filter_auto_connect_services(&services, None);

        assert_eq!(filtered, vec![&services[1]]);
    }

    #[test]
    fn auto_connect_matches_aosp_allowlist_special_values_and_fallback() {
        let services = vec![
            ServiceInfo::new("legacy", "_adb._tcp", "192.0.2.10", 5555),
            ServiceInfo::new("tls", "_adb-tls-connect._tcp", "192.0.2.10", 37100),
            ServiceInfo::new("pair", "_adb-tls-pairing._tcp", "192.0.2.10", 37101),
        ];

        assert!(filter_auto_connect_services(&services, Some("0")).is_empty());
        assert_eq!(
            filter_auto_connect_services(&services, Some("all")),
            vec![&services[0], &services[1]]
        );
        assert_eq!(
            filter_auto_connect_services(&services, Some("adb,adb-tls-connect")),
            vec![&services[0], &services[1]]
        );
        assert_eq!(
            filter_auto_connect_services(&services, Some("adb-tls-pairing")),
            Vec::<&ServiceInfo>::new(),
            "pairing service 可进入 allowlist，但官方不会自动连接该 service"
        );
        assert_eq!(
            filter_auto_connect_services(&services, Some("invalid")),
            vec![&services[1]],
            "没有任何合法 service 时保留官方默认 tls-connect allowlist"
        );
    }

    #[test]
    fn auto_connect_requires_known_tls_host_and_ignores_emulators() {
        let tls = ServiceInfo::new("device-guid", "_adb-tls-connect._tcp", "192.0.2.10", 37100);
        assert!(!should_auto_connect(&tls, None, |_| false));
        assert!(should_auto_connect(&tls, None, |guid| guid == "device-guid"));

        let emulator = ServiceInfo::new(
            "adb-EMULATOR-5554",
            "_adb-tls-connect._tcp",
            "127.0.0.1",
            37100,
        );
        assert!(!should_auto_connect(&emulator, None, |_| true));

        let pairing = ServiceInfo::new("device-guid", "_adb-tls-pairing._tcp", "192.0.2.10", 37101);
        assert!(!should_auto_connect(&pairing, Some("all"), |_| true));
    }

    #[test]
    fn connect_service_prefers_tls_connect_then_legacy_adb() {
        let services = vec![
            ServiceInfo::new("device", "_adb._tcp", "192.0.2.10", 5555),
            ServiceInfo::new("device", "_adb-tls-connect._tcp", "192.0.2.10", 37100),
        ];

        assert_eq!(
            connect_service_info(&services, "device").unwrap(),
            services[1]
        );
        assert_eq!(
            connect_service_info(&services, "device._adb._tcp.local.").unwrap(),
            services[0]
        );
    }

    #[test]
    fn connect_service_rejects_pairing_service() {
        let services = vec![ServiceInfo::new(
            "device",
            "_adb-tls-pairing._tcp",
            "192.0.2.10",
            37101,
        )];

        assert!(connect_service_info(&services, "device").is_none());
        assert!(connect_service_info(&services, "device._adb-tls-pairing._tcp").is_none());
        assert_eq!(
            pairing_service_info(&services, "device._adb-tls-pairing._tcp").unwrap(),
            services[0]
        );
    }

    #[test]
    fn discovery_table_upserts_removes_and_sorts_services() {
        let mut services = vec![
            ServiceInfo::new("z", "_adb._tcp", "192.0.2.20", 5555),
            ServiceInfo::new("a", "_adb._tcp", "192.0.2.10", 5555),
        ];

        upsert_service(
            &mut services,
            ServiceInfo::new("z", "_adb._tcp", "192.0.2.21", 5556),
        );

        assert_eq!(
            sorted_services(&services),
            vec![
                ServiceInfo::new("a", "_adb._tcp", "192.0.2.10", 5555),
                ServiceInfo::new("z", "_adb._tcp", "192.0.2.21", 5556),
            ]
        );

        remove_service(&mut services, "_adb._tcp.local.", "z._adb._tcp.local.");
        assert_eq!(
            services,
            vec![ServiceInfo::new("a", "_adb._tcp", "192.0.2.10", 5555)]
        );
    }

    #[test]
    fn resolved_service_helpers_keep_official_ipv4_list_shape() {
        let mut addresses = HashSet::new();
        addresses.insert(mdns_sd::ScopedIp::V4(mdns_sd::ScopedIpV4::new(
            Ipv4Addr::new(192, 0, 2, 10),
            mdns_sd::InterfaceId::default(),
        )));

        assert_eq!(
            service_name_from_domain("_adb._tcp.local."),
            Some("_adb._tcp")
        );
        assert_eq!(
            instance_name_from_fullname("device._adb._tcp.local.", "_adb._tcp"),
            Some("device")
        );
        assert_eq!(
            preferred_ipv4_address(&addresses),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }

    #[test]
    fn parse_instance_name_matches_aosp_shapes() {
        assert_eq!(
            parse_instance_name("my.name"),
            Some(MdnsInstance {
                instance_name: "my.name".to_string(),
                service_name: String::new(),
                transport_type: String::new(),
            })
        );
        assert_eq!(
            parse_instance_name("my.name.service._tcp.local."),
            Some(MdnsInstance {
                instance_name: "my.name".to_string(),
                service_name: "service".to_string(),
                transport_type: "tcp".to_string(),
            })
        );
        assert_eq!(
            parse_instance_name("my..service._udp"),
            Some(MdnsInstance {
                instance_name: "my.".to_string(),
                service_name: "service".to_string(),
                transport_type: "udp".to_string(),
            })
        );
        assert!(parse_instance_name("_tcp").is_some());
        assert!(parse_instance_name("._tcp").is_none());
        assert!(parse_instance_name("._tcp.").is_none());
        assert!(parse_instance_name("service._tcp").is_none());
        assert!(parse_instance_name("name.local").is_none());
        assert!(parse_instance_name(".local").is_none());
        assert!(parse_instance_name(".local.").is_none());
        assert!(parse_instance_name("name.service._tcp..local.").is_none());
    }
}
