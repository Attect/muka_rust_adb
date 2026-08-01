use crate::error::{AdbError, Result};
use crate::protocol::AdbMessage;
use crate::transport::AdbConnection;

use std::fmt;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rusb::{
    Context, Device, DeviceDescriptor, DeviceHandle, Direction, Speed, TransferType, UsbContext,
    Version,
};

#[cfg(windows)]
mod win_power;

const USB_READ_TIMEOUT: Duration = Duration::from_millis(250);
const USB_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const USB_PERMISSIONS_HELP_URL: &str = "http://developer.android.com/tools/device.html";

#[derive(Debug)]
pub(crate) enum UsbOpenError {
    PermissionDenied(AdbError),
    Other(AdbError),
}

impl UsbOpenError {
    pub(crate) fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied(_))
    }

    pub(crate) fn into_adb_error(self) -> AdbError {
        match self {
            Self::PermissionDenied(err) | Self::Other(err) => err,
        }
    }
}

impl fmt::Display for UsbOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(err) | Self::Other(err) => err.fmt(formatter),
        }
    }
}

pub(crate) fn no_permissions_short_help_text() -> String {
    let mut help = "no permissions".to_string();
    let problem = usb_permissions_problem();
    if !problem.is_empty() {
        help.push_str(" (");
        help.push_str(&problem);
        help.push(')');
    }
    format!("{help}; see [{USB_PERMISSIONS_HELP_URL}]")
}

pub(crate) fn no_permissions_long_help_text() -> String {
    let mut header = "insufficient permissions for device".to_string();
    let problem = usb_permissions_problem();
    if !problem.is_empty() {
        header.push_str(": ");
        header.push_str(&problem);
    }
    format!("{header}\nSee [{USB_PERMISSIONS_HELP_URL}] for more information")
}

#[cfg(target_os = "linux")]
fn usb_permissions_problem() -> String {
    // AOSP diagnose_usb 在 Linux 上根据 plugdev 组给出进一步提示。
    unsafe {
        let group_name = c"plugdev";
        let group = libc::getgrnam(group_name.as_ptr());
        if group.is_null() {
            return String::new();
        }
        let plugdev_gid = (*group).gr_gid;

        let group_count = libc::getgroups(0, std::ptr::null_mut());
        if group_count < 0 {
            return String::new();
        }
        let mut groups = vec![0 as libc::gid_t; group_count as usize];
        let groups_ptr = if groups.is_empty() {
            std::ptr::null_mut()
        } else {
            groups.as_mut_ptr()
        };
        let actual_count = libc::getgroups(group_count, groups_ptr);
        if actual_count < 0 {
            return String::new();
        }
        groups.truncate(actual_count as usize);

        if libc::getegid() == plugdev_gid || groups.contains(&plugdev_gid) {
            return "missing udev rules? user is in the plugdev group".to_string();
        }

        let passwd = libc::getpwuid(libc::getuid());
        let user = if passwd.is_null() || (*passwd).pw_name.is_null() {
            "?".to_string()
        } else {
            std::ffi::CStr::from_ptr((*passwd).pw_name)
                .to_string_lossy()
                .into_owned()
        };
        format!("user {user} is not in the plugdev group")
    }
}

#[cfg(not(target_os = "linux"))]
fn usb_permissions_problem() -> String {
    String::new()
}

pub(crate) fn release_settle_delay() -> Duration {
    // close_connection 会让 bulk-in reader 在下一次短 timeout 后退出；
    // attach 必须等旧 DeviceHandle clone 丢弃后再重新 claim interface。
    USB_READ_TIMEOUT + Duration::from_millis(50)
}

pub fn start_host_monitoring() -> Result<()> {
    #[cfg(windows)]
    win_power::start()?;
    Ok(())
}

pub fn resume_generation() -> u64 {
    #[cfg(windows)]
    return win_power::resume_generation();

    #[cfg(not(windows))]
    return 0;
}

pub const ADB_CLASS: u8 = 0xff;
pub const ADB_SUBCLASS: u8 = 0x42;
pub const ADB_PROTOCOL: u8 = 0x01;
pub const ADB_DBC_CLASS: u8 = 0xdc;
pub const ADB_DBC_SUBCLASS: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbEndpoint {
    pub address: u8,
    pub max_packet_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbInterfaceBackend {
    Libusb,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbAdbInterface {
    pub backend: UsbInterfaceBackend,
    pub bus_number: u8,
    pub device_address: u8,
    pub bus_address: String,
    pub negotiated_speed_mbps: u64,
    pub max_speed_mbps: u64,
    pub vendor_id: u16,
    pub product_id: u16,
    pub interface_number: u8,
    pub setting_number: u8,
    pub class_code: u8,
    pub subclass_code: u8,
    pub protocol_code: u8,
    pub bulk_in: UsbEndpoint,
    pub bulk_out: UsbEndpoint,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
}

impl UsbAdbInterface {
    pub fn short_description(&self) -> String {
        let mut description = match &self.backend {
            UsbInterfaceBackend::Libusb => format!(
                "bus {:03} device {:03} {:04x}:{:04x} if {} ep-in 0x{:02x} ep-out 0x{:02x}",
                self.bus_number,
                self.device_address,
                self.vendor_id,
                self.product_id,
                self.interface_number,
                self.bulk_in.address,
                self.bulk_out.address
            ),
        };

        if let Some(serial) = &self.serial_number {
            description.push_str(" serial ");
            description.push_str(serial);
        }

        description
    }

    pub fn usb_serial_fallback(&self) -> String {
        match &self.backend {
            UsbInterfaceBackend::Libusb => format!(
                "usb:{:03}:{:03}:{:04x}:{:04x}:{}",
                self.bus_number,
                self.device_address,
                self.vendor_id,
                self.product_id,
                self.interface_number
            ),
        }
    }

    pub fn serial_or_fallback(&self) -> String {
        self.serial_number
            .clone()
            .unwrap_or_else(|| self.usb_serial_fallback())
    }
}

pub fn is_adb_interface(class_code: u8, subclass_code: u8, protocol_code: u8) -> bool {
    protocol_code == ADB_PROTOCOL
        && ((class_code == ADB_CLASS && subclass_code == ADB_SUBCLASS)
            || (class_code == ADB_DBC_CLASS && subclass_code == ADB_DBC_SUBCLASS))
}

pub fn list_adb_interfaces() -> Result<Vec<UsbAdbInterface>> {
    Ok(list_adb_interfaces_with_diagnostics()?.interfaces)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbInterfaceList {
    pub interfaces: Vec<UsbAdbInterface>,
    pub diagnostics: Vec<String>,
}

pub fn list_adb_interfaces_with_diagnostics() -> Result<UsbInterfaceList> {
    Ok(UsbInterfaceList {
        interfaces: list_libusb_adb_interfaces()?,
        diagnostics: Vec::new(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHostBackend {
    Libusb,
}

pub fn selected_usb_backend() -> UsbHostBackend {
    UsbHostBackend::Libusb
}

fn list_libusb_adb_interfaces() -> Result<Vec<UsbAdbInterface>> {
    let context = Context::new().map_err(|err| usb_error("初始化 libusb", err))?;
    let devices = context
        .devices()
        .map_err(|err| usb_error("枚举 USB 设备", err))?;

    let mut interfaces = Vec::new();
    for device in devices.iter() {
        collect_adb_interfaces(&device, &mut interfaces);
    }

    interfaces.sort_by_key(|interface| {
        (
            interface.bus_number,
            interface.device_address,
            interface.interface_number,
            interface.setting_number,
        )
    });
    Ok(interfaces)
}

#[derive(Clone)]
pub enum UsbConnection {
    Libusb(LibusbConnection),
}

impl UsbConnection {
    pub(crate) fn open(interface: &UsbAdbInterface) -> std::result::Result<Self, UsbOpenError> {
        Ok(Self::Libusb(LibusbConnection::open(interface)?))
    }
}

impl AdbConnection for UsbConnection {
    fn read_packet(&mut self, max_payload: usize) -> Result<AdbMessage> {
        match self {
            UsbConnection::Libusb(connection) => connection.read_packet(max_payload),
        }
    }

    fn write_packet(&mut self, packet: &AdbMessage, protocol_version: u32) -> Result<()> {
        match self {
            UsbConnection::Libusb(connection) => connection.write_packet(packet, protocol_version),
        }
    }

    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
        Ok(Box::new(self.clone()))
    }

    fn close_connection(&mut self) -> Result<()> {
        match self {
            UsbConnection::Libusb(connection) => connection.close_connection(),
        }
    }
}

#[derive(Clone)]
pub struct LibusbConnection {
    handle: Arc<DeviceHandle<Context>>,
    closed: Arc<AtomicBool>,
    interface_number: u8,
    read_endpoint: u8,
    write_endpoint: u8,
    out_packet_size: u16,
}

impl LibusbConnection {
    fn open(interface: &UsbAdbInterface) -> std::result::Result<Self, UsbOpenError> {
        let context = Context::new().map_err(|err| usb_open_error("初始化 libusb", err))?;
        let device = find_device(&context, interface).map_err(UsbOpenError::Other)?;
        let handle = device
            .open()
            .map_err(|err| usb_open_error("打开 USB ADB 设备", err))?;

        match handle.set_auto_detach_kernel_driver(true) {
            Ok(()) | Err(rusb::Error::NotSupported) => {}
            Err(err) => {
                return Err(usb_open_error("设置 USB kernel driver auto detach", err));
            }
        }

        handle
            .claim_interface(interface.interface_number)
            .map_err(|err| usb_open_error("claim USB ADB interface", err))?;
        handle
            .clear_halt(interface.bulk_in.address)
            .map_err(|err| usb_open_error("清理 USB bulk-in halt", err))?;
        handle
            .clear_halt(interface.bulk_out.address)
            .map_err(|err| usb_open_error("清理 USB bulk-out halt", err))?;

        Ok(Self {
            handle: Arc::new(handle),
            closed: Arc::new(AtomicBool::new(false)),
            interface_number: interface.interface_number,
            read_endpoint: interface.bulk_in.address,
            write_endpoint: interface.bulk_out.address,
            out_packet_size: interface.bulk_out.max_packet_size.max(1),
        })
    }

    fn read_exact_bulk(&self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            if self.closed.load(Ordering::SeqCst) {
                return Err(AdbError::Server("USB connection closed".to_string()));
            }
            let read = match self.handle.read_bulk(
                self.read_endpoint,
                &mut buf[offset..],
                USB_READ_TIMEOUT,
            ) {
                Ok(read) => read,
                Err(rusb::Error::Timeout) if !self.closed.load(Ordering::SeqCst) => continue,
                Err(err) => return Err(usb_error("读取 USB bulk 数据", err)),
            };
            if read == 0 {
                return Err(AdbError::Protocol("USB bulk 读取提前结束".to_string()));
            }
            offset += read;
        }
        Ok(())
    }

    fn write_all_bulk(&self, buf: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            if self.closed.load(Ordering::SeqCst) {
                return Err(AdbError::Server("USB connection closed".to_string()));
            }
            let written = self
                .handle
                .write_bulk(self.write_endpoint, &buf[offset..], USB_WRITE_TIMEOUT)
                .map_err(|err| usb_error("写入 USB bulk 数据", err))?;
            if written == 0 {
                return Err(AdbError::Protocol("USB bulk 写入提前结束".to_string()));
            }
            offset += written;
        }
        Ok(())
    }
}

impl Drop for LibusbConnection {
    fn drop(&mut self) {
        if Arc::strong_count(&self.handle) == 1 {
            let _ = self.close_connection();
        }
    }
}

impl AdbConnection for LibusbConnection {
    fn read_packet(&mut self, max_payload: usize) -> Result<AdbMessage> {
        let mut header = [0_u8; 24];
        self.read_exact_bulk(&mut header)?;

        let data_length =
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
        if data_length > max_payload {
            return Err(AdbError::Protocol(format!(
                "USB payload 过大: {data_length} > {max_payload}"
            )));
        }

        let mut payload = vec![0_u8; data_length];
        if data_length > 0 {
            self.read_exact_bulk(&mut payload)?;
        }

        let mut packet = Vec::with_capacity(header.len() + payload.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&payload);
        AdbMessage::read_from(&mut Cursor::new(packet), max_payload)
    }

    fn write_packet(&mut self, packet: &AdbMessage, protocol_version: u32) -> Result<()> {
        let mut encoded = Vec::with_capacity(24 + packet.payload.len());
        packet.write_to(&mut encoded, protocol_version)?;
        self.write_all_bulk(&encoded[..24])?;
        if !packet.payload.is_empty() {
            self.write_all_bulk(&encoded[24..])?;
            if packet
                .payload
                .len()
                .is_multiple_of(usize::from(self.out_packet_size))
            {
                let _ = self
                    .handle
                    .write_bulk(self.write_endpoint, &[], USB_WRITE_TIMEOUT);
            }
        }
        Ok(())
    }

    fn try_clone_box(&self) -> Result<Box<dyn AdbConnection>> {
        Ok(Box::new(self.clone()))
    }

    fn close_connection(&mut self) -> Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.handle.release_interface(self.interface_number);
        }
        Ok(())
    }
}

fn find_device(context: &Context, interface: &UsbAdbInterface) -> Result<Device<Context>> {
    let devices = context
        .devices()
        .map_err(|err| usb_error("枚举 USB 设备", err))?;

    for device in devices.iter() {
        if device.bus_number() != interface.bus_number
            || device.address() != interface.device_address
        {
            continue;
        }

        let Ok(descriptor) = device.device_descriptor() else {
            continue;
        };
        if descriptor.vendor_id() == interface.vendor_id
            && descriptor.product_id() == interface.product_id
        {
            return Ok(device);
        }
    }

    Err(AdbError::Server(format!(
        "USB ADB interface 已消失: {}",
        interface.short_description()
    )))
}

fn collect_adb_interfaces(device: &Device<Context>, interfaces: &mut Vec<UsbAdbInterface>) {
    let Ok(device_descriptor) = device.device_descriptor() else {
        return;
    };
    let mut strings = None;
    let bus_address = usb_bus_address(
        device.bus_number(),
        device.address(),
        device.port_numbers().as_deref().unwrap_or_default(),
    );
    let negotiated_speed_mbps = usb_speed_mbps(device.speed());
    let max_speed_mbps =
        maximum_usb_speed_mbps(device_descriptor.usb_version(), negotiated_speed_mbps);

    for config_index in 0..device_descriptor.num_configurations() {
        let Ok(config_descriptor) = device.config_descriptor(config_index) else {
            continue;
        };

        for interface in config_descriptor.interfaces() {
            for descriptor in interface.descriptors() {
                if !is_adb_interface(
                    descriptor.class_code(),
                    descriptor.sub_class_code(),
                    descriptor.protocol_code(),
                ) {
                    continue;
                }

                let Some((bulk_in, bulk_out)) = bulk_endpoint_pair(&descriptor) else {
                    continue;
                };

                let strings =
                    strings.get_or_insert_with(|| read_strings(device, &device_descriptor));
                interfaces.push(UsbAdbInterface {
                    backend: UsbInterfaceBackend::Libusb,
                    bus_number: device.bus_number(),
                    device_address: device.address(),
                    bus_address: bus_address.clone(),
                    negotiated_speed_mbps,
                    max_speed_mbps,
                    vendor_id: device_descriptor.vendor_id(),
                    product_id: device_descriptor.product_id(),
                    interface_number: descriptor.interface_number(),
                    setting_number: descriptor.setting_number(),
                    class_code: descriptor.class_code(),
                    subclass_code: descriptor.sub_class_code(),
                    protocol_code: descriptor.protocol_code(),
                    bulk_in,
                    bulk_out,
                    manufacturer: strings.manufacturer.clone(),
                    product: strings.product.clone(),
                    serial_number: strings.serial_number.clone(),
                });
            }
        }
    }
}

fn usb_bus_address(bus_number: u8, device_address: u8, ports: &[u8]) -> String {
    if ports.is_empty() {
        return format!("usb:{bus_number}:{device_address}");
    }

    let topology = ports
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".");
    format!("usb:{bus_number}-{topology}")
}

fn usb_speed_mbps(speed: Speed) -> u64 {
    match speed {
        Speed::Unknown => 0,
        Speed::Low => 1,
        Speed::Full => 12,
        Speed::High => 480,
        Speed::Super => 5_000,
        Speed::SuperPlus => 10_000,
        _ => 0,
    }
}

fn maximum_usb_speed_mbps(version: Version, negotiated_speed_mbps: u64) -> u64 {
    let descriptor_speed = match (version.major(), version.minor()) {
        (0 | 1, _) => 12,
        (2, _) => 480,
        (3, 0) => 5_000,
        (3, 1) => 10_000,
        (3, _) => 20_000,
        (4.., _) => 40_000,
    };
    descriptor_speed.max(negotiated_speed_mbps)
}

fn bulk_endpoint_pair(
    descriptor: &rusb::InterfaceDescriptor<'_>,
) -> Option<(UsbEndpoint, UsbEndpoint)> {
    let mut bulk_in = None;
    let mut bulk_out = None;

    for endpoint in descriptor.endpoint_descriptors() {
        if endpoint.transfer_type() != TransferType::Bulk {
            continue;
        }

        let usb_endpoint = UsbEndpoint {
            address: endpoint.address(),
            max_packet_size: endpoint.max_packet_size(),
        };

        match endpoint.direction() {
            Direction::In if bulk_in.is_none() => bulk_in = Some(usb_endpoint),
            Direction::Out if bulk_out.is_none() => bulk_out = Some(usb_endpoint),
            _ => {}
        }
    }

    Some((bulk_in?, bulk_out?))
}

#[derive(Default)]
struct UsbStrings {
    manufacturer: Option<String>,
    product: Option<String>,
    serial_number: Option<String>,
}

fn read_strings(device: &Device<Context>, descriptor: &DeviceDescriptor) -> UsbStrings {
    let Ok(handle) = device.open() else {
        return UsbStrings::default();
    };

    UsbStrings {
        manufacturer: handle.read_manufacturer_string_ascii(descriptor).ok(),
        product: handle.read_product_string_ascii(descriptor).ok(),
        serial_number: handle.read_serial_number_string_ascii(descriptor).ok(),
    }
}

fn usb_error(action: &str, err: rusb::Error) -> AdbError {
    AdbError::Server(format!("USB {action}失败: {err}"))
}

fn usb_open_error(action: &str, err: rusb::Error) -> UsbOpenError {
    let error = usb_error(action, err);
    if err == rusb::Error::Access {
        UsbOpenError::PermissionDenied(error)
    } else {
        UsbOpenError::Other(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_interface_matches_gadget_and_dbc() {
        assert!(is_adb_interface(ADB_CLASS, ADB_SUBCLASS, ADB_PROTOCOL));
        assert!(is_adb_interface(
            ADB_DBC_CLASS,
            ADB_DBC_SUBCLASS,
            ADB_PROTOCOL
        ));
        assert!(!is_adb_interface(ADB_CLASS, ADB_SUBCLASS, 0));
        assert!(!is_adb_interface(ADB_CLASS, 0, ADB_PROTOCOL));
        assert!(!is_adb_interface(0, ADB_SUBCLASS, ADB_PROTOCOL));
    }

    #[test]
    fn selected_backend_matches_platform_default() {
        assert_eq!(selected_usb_backend(), UsbHostBackend::Libusb);
    }

    #[test]
    fn interface_description_includes_stable_usb_identity() {
        let interface = UsbAdbInterface {
            backend: UsbInterfaceBackend::Libusb,
            bus_number: 1,
            device_address: 2,
            bus_address: "usb:1-2".to_string(),
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            vendor_id: 0x18d1,
            product_id: 0x4ee7,
            interface_number: 3,
            setting_number: 0,
            class_code: ADB_CLASS,
            subclass_code: ADB_SUBCLASS,
            protocol_code: ADB_PROTOCOL,
            bulk_in: UsbEndpoint {
                address: 0x81,
                max_packet_size: 512,
            },
            bulk_out: UsbEndpoint {
                address: 0x02,
                max_packet_size: 512,
            },
            manufacturer: None,
            product: None,
            serial_number: Some("SERIAL".to_string()),
        };

        assert_eq!(
            interface.short_description(),
            "bus 001 device 002 18d1:4ee7 if 3 ep-in 0x81 ep-out 0x02 serial SERIAL"
        );
    }

    #[test]
    fn serial_fallback_uses_usb_identity_when_descriptor_has_no_serial() {
        let interface = UsbAdbInterface {
            backend: UsbInterfaceBackend::Libusb,
            bus_number: 1,
            device_address: 2,
            bus_address: "usb:1-2".to_string(),
            negotiated_speed_mbps: 480,
            max_speed_mbps: 5_000,
            vendor_id: 0x18d1,
            product_id: 0x4ee7,
            interface_number: 3,
            setting_number: 0,
            class_code: ADB_CLASS,
            subclass_code: ADB_SUBCLASS,
            protocol_code: ADB_PROTOCOL,
            bulk_in: UsbEndpoint {
                address: 0x81,
                max_packet_size: 512,
            },
            bulk_out: UsbEndpoint {
                address: 0x02,
                max_packet_size: 512,
            },
            manufacturer: None,
            product: None,
            serial_number: None,
        };

        assert_eq!(interface.serial_or_fallback(), "usb:001:002:18d1:4ee7:3");
    }

    #[test]
    fn bus_address_uses_libusb_port_topology() {
        assert_eq!(usb_bus_address(3, 9, &[2, 4, 1]), "usb:3-2.4.1");
        assert_eq!(usb_bus_address(3, 9, &[]), "usb:3:9");
    }

    #[test]
    fn usb_speed_values_match_aosp_megabits_per_second() {
        assert_eq!(usb_speed_mbps(Speed::Low), 1);
        assert_eq!(usb_speed_mbps(Speed::Full), 12);
        assert_eq!(usb_speed_mbps(Speed::High), 480);
        assert_eq!(usb_speed_mbps(Speed::Super), 5_000);
        assert_eq!(usb_speed_mbps(Speed::SuperPlus), 10_000);
    }

    #[test]
    fn maximum_speed_uses_descriptor_capability_and_negotiated_floor() {
        assert_eq!(maximum_usb_speed_mbps(Version(2, 0, 0), 12), 480);
        assert_eq!(maximum_usb_speed_mbps(Version(3, 0, 0), 480), 5_000);
        assert_eq!(maximum_usb_speed_mbps(Version(3, 2, 0), 10_000), 20_000);
        assert_eq!(maximum_usb_speed_mbps(Version(2, 0, 0), 5_000), 5_000);
    }

    #[test]
    fn usb_open_error_preserves_permission_denied_kind() {
        assert!(usb_open_error("打开设备", rusb::Error::Access).is_permission_denied());
        assert!(!usb_open_error("打开设备", rusb::Error::Busy).is_permission_denied());
    }

    #[test]
    fn permission_help_matches_aosp_shape() {
        let short = no_permissions_short_help_text();
        assert!(short.starts_with("no permissions"));
        assert!(short.ends_with("; see [http://developer.android.com/tools/device.html]"));

        let long = no_permissions_long_help_text();
        assert!(long.starts_with("insufficient permissions for device"));
        assert!(long.ends_with(
            "\nSee [http://developer.android.com/tools/device.html] for more information"
        ));
    }
}
