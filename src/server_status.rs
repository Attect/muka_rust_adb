use crate::auth;
use crate::error::{AdbError, Result};
use crate::mdns;
use crate::transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbBackend {
    Unknown,
    Native,
    Libusb,
    // 官方 platform-tools 37.x 的 libadbusb 后端在 wire 上自报 4（跳过了 3），
    // 由 37.0.1 官方二进制 server-status 实测得出。
    Libadbusb = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsBackend {
    Unknown,
    Bonjour,
    Openscreen,
    Libadbmdns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbServerStatus {
    pub usb_backend: UsbBackend,
    pub usb_backend_forced: Option<bool>,
    pub mdns_backend: MdnsBackend,
    pub mdns_backend_forced: Option<bool>,
    pub version: String,
    pub build: String,
    pub executable_absolute_path: String,
    pub log_absolute_path: String,
    pub os: String,
    pub trace_level: Option<String>,
    pub burst_mode: Option<bool>,
    pub mdns_enabled: Option<bool>,
    pub keystore_path: Option<String>,
    pub known_hosts_path: Option<String>,
}

impl AdbServerStatus {
    pub fn current() -> Self {
        Self::current_with_mdns(mdns::discovery_enabled())
    }

    pub fn current_with_mdns(mdns_enabled: bool) -> Self {
        let android_dir = auth::android_dir().ok();
        Self {
            // 当前发行版只使用 rusb 的 vendored libusb，旧的 NATIVE 枚举值仅保留解码兼容。
            usb_backend: UsbBackend::Libusb,
            usb_backend_forced: Some(false),
            // mdns check 文案已与官方 37.x libadbmdns 对齐，server-status 同步自报 LIBADBMDNS。
            mdns_backend: MdnsBackend::Libadbmdns,
            mdns_backend_forced: Some(std::env::var_os("ADB_MDNS_OPENSCREEN").is_some()),
            version: format!("adb-rust-{}", env!("CARGO_PKG_VERSION")),
            build: "adb-rust".to_string(),
            executable_absolute_path: std::env::current_exe()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "adb".to_string()),
            os: os_version(),
            trace_level: Some(std::env::var("ADB_TRACE").unwrap_or_default()),
            burst_mode: Some(transport::burst_mode_enabled()),
            mdns_enabled: Some(mdns_enabled),
            keystore_path: android_dir
                .as_ref()
                .map(|path| path.join("adbkey").display().to_string()),
            known_hosts_path: android_dir
                .as_ref()
                .map(|path| path.join("adb_known_hosts.pb").display().to_string()),
            log_absolute_path: log_absolute_path(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint_field(&mut out, 1, self.usb_backend as u64);
        if self.usb_backend_forced == Some(true) {
            write_varint_field(&mut out, 2, 1);
        }
        write_varint_field(&mut out, 3, self.mdns_backend as u64);
        if self.mdns_backend_forced == Some(true) {
            write_varint_field(&mut out, 4, 1);
        }
        write_string_field(&mut out, 5, &self.version);
        write_string_field(&mut out, 6, &self.build);
        write_string_field(&mut out, 7, &self.executable_absolute_path);
        write_string_field(&mut out, 8, &self.log_absolute_path);
        write_string_field(&mut out, 9, &self.os);
        if let Some(trace_level) = &self.trace_level {
            write_string_field(&mut out, 10, trace_level);
        }
        if let Some(burst_mode) = self.burst_mode {
            write_varint_field(&mut out, 11, u64::from(burst_mode));
        }
        if let Some(mdns_enabled) = self.mdns_enabled {
            write_varint_field(&mut out, 12, u64::from(mdns_enabled));
        }
        if let Some(keystore_path) = &self.keystore_path {
            write_string_field(&mut out, 13, keystore_path);
        }
        if let Some(known_hosts_path) = &self.known_hosts_path {
            write_string_field(&mut out, 14, known_hosts_path);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut status = Self {
            usb_backend: UsbBackend::Unknown,
            usb_backend_forced: None,
            mdns_backend: MdnsBackend::Unknown,
            mdns_backend_forced: None,
            version: String::new(),
            build: String::new(),
            executable_absolute_path: String::new(),
            log_absolute_path: String::new(),
            os: String::new(),
            trace_level: None,
            burst_mode: None,
            mdns_enabled: None,
            keystore_path: None,
            known_hosts_path: None,
        };

        let mut index = 0;
        while index < bytes.len() {
            let key = read_varint(bytes, &mut index)?;
            let field = key >> 3;
            let wire_type = key & 0x07;
            match (field, wire_type) {
                (1, 0) => {
                    status.usb_backend = UsbBackend::from_i32(read_varint(bytes, &mut index)?)
                }
                (2, 0) => status.usb_backend_forced = Some(read_varint(bytes, &mut index)? != 0),
                (3, 0) => {
                    status.mdns_backend = MdnsBackend::from_i32(read_varint(bytes, &mut index)?)
                }
                (4, 0) => status.mdns_backend_forced = Some(read_varint(bytes, &mut index)? != 0),
                (5, 2) => status.version = read_string(bytes, &mut index)?,
                (6, 2) => status.build = read_string(bytes, &mut index)?,
                (7, 2) => status.executable_absolute_path = read_string(bytes, &mut index)?,
                (8, 2) => status.log_absolute_path = read_string(bytes, &mut index)?,
                (9, 2) => status.os = read_string(bytes, &mut index)?,
                (10, 2) => status.trace_level = Some(read_string(bytes, &mut index)?),
                (11, 0) => status.burst_mode = Some(read_varint(bytes, &mut index)? != 0),
                (12, 0) => status.mdns_enabled = Some(read_varint(bytes, &mut index)? != 0),
                (13, 2) => status.keystore_path = Some(read_string(bytes, &mut index)?),
                (14, 2) => status.known_hosts_path = Some(read_string(bytes, &mut index)?),
                (_, 0) => {
                    let _ = read_varint(bytes, &mut index)?;
                }
                (_, 1) => skip(bytes, &mut index, 8)?,
                (_, 2) => {
                    let len = read_varint(bytes, &mut index)? as usize;
                    skip(bytes, &mut index, len)?;
                }
                (_, 5) => skip(bytes, &mut index, 4)?,
                (_, other) => {
                    return Err(AdbError::Protocol(format!(
                        "server-status protobuf 不支持 wire type {other}"
                    )));
                }
            }
        }

        Ok(status)
    }

    pub fn to_text_proto(&self) -> String {
        let mut out = String::new();
        push_line(&mut out, "usb_backend", self.usb_backend.as_text());
        if self.usb_backend_forced == Some(true) {
            push_bool_line(&mut out, "usb_backend_forced", true);
        }
        push_line(&mut out, "mdns_backend", self.mdns_backend.as_text());
        if self.mdns_backend_forced == Some(true) {
            push_bool_line(&mut out, "mdns_backend_forced", true);
        }
        push_string_line(&mut out, "version", &self.version);
        push_string_line(&mut out, "build", &self.build);
        push_string_line(
            &mut out,
            "executable_absolute_path",
            &self.executable_absolute_path,
        );
        push_string_line(&mut out, "log_absolute_path", &self.log_absolute_path);
        push_string_line(&mut out, "os", &self.os);
        if let Some(trace_level) = &self.trace_level {
            push_string_line(&mut out, "trace_level", trace_level);
        }
        if let Some(burst_mode) = self.burst_mode {
            push_bool_line(&mut out, "burst_mode", burst_mode);
        }
        if let Some(mdns_enabled) = self.mdns_enabled {
            push_bool_line(&mut out, "mdns_enabled", mdns_enabled);
        }
        if let Some(keystore_path) = &self.keystore_path {
            push_string_line(&mut out, "keystore_path", keystore_path);
        }
        if let Some(known_hosts_path) = &self.known_hosts_path {
            push_string_line(&mut out, "known_hosts_path", known_hosts_path);
        }
        out
    }
}

pub(crate) fn log_absolute_path() -> String {
    if let Some(path) = std::env::var_os("ANDROID_ADB_LOG_PATH") {
        return path.to_string_lossy().into_owned();
    }

    #[cfg(windows)]
    {
        std::env::var("TEMP")
            .or_else(|_| std::env::var("TMP"))
            .map(|dir| format!("{dir}\\adb.log"))
            .unwrap_or_else(|_| "adb.log".to_string())
    }

    #[cfg(not(windows))]
    {
        let tmp_dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        format!("{tmp_dir}/adb.{}.log", unsafe { libc::getuid() })
    }
}

impl UsbBackend {
    fn from_i32(value: u64) -> Self {
        match value {
            1 => Self::Native,
            2 => Self::Libusb,
            4 => Self::Libadbusb,
            _ => Self::Unknown,
        }
    }

    fn as_text(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN_USB",
            Self::Native => "NATIVE",
            Self::Libusb => "LIBUSB",
            Self::Libadbusb => "LIBADBUSB",
        }
    }
}

impl MdnsBackend {
    fn from_i32(value: u64) -> Self {
        match value {
            1 => Self::Bonjour,
            2 => Self::Openscreen,
            3 => Self::Libadbmdns,
            _ => Self::Unknown,
        }
    }

    fn as_text(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN_MDNS",
            Self::Bonjour => "BONJOUR",
            Self::Openscreen => "OPENSCREEN",
            Self::Libadbmdns => "LIBADBMDNS",
        }
    }
}

fn os_version() -> String {
    #[cfg(windows)]
    {
        windows_os_version()
    }

    #[cfg(not(windows))]
    {
        unix_os_version()
    }
}

#[cfg(windows)]
#[repr(C)]
struct RtlOsVersionInfoW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(info: *mut RtlOsVersionInfoW) -> i32;
}

#[cfg(windows)]
fn windows_os_version() -> String {
    let mut version = RtlOsVersionInfoW {
        dw_os_version_info_size: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };

    // RtlGetVersion 不受可执行文件 manifest 兼容层影响，与 AOSP 一样返回真实系统版本。
    if unsafe { RtlGetVersion(&mut version) } == 0 {
        format!(
            "Windows {}.{}.{}",
            version.dw_major_version, version.dw_minor_version, version.dw_build_number
        )
    } else {
        "Windows".to_string()
    }
}

#[cfg(not(windows))]
fn unix_os_version() -> String {
    let mut version = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    // uname 成功时会填满结构；异常 libc 实现失败时仍返回可打印的 fallback。
    if unsafe { libc::uname(version.as_mut_ptr()) } == 0 {
        let version = unsafe { version.assume_init() };
        let sysname =
            unsafe { std::ffi::CStr::from_ptr(version.sysname.as_ptr()) }.to_string_lossy();
        let release =
            unsafe { std::ffi::CStr::from_ptr(version.release.as_ptr()) }.to_string_lossy();
        let machine =
            unsafe { std::ffi::CStr::from_ptr(version.machine.as_ptr()) }.to_string_lossy();
        format!("{sysname} {release} ({machine})")
    } else {
        std::env::consts::OS.to_string()
    }
}

fn write_varint_field(out: &mut Vec<u8>, field: u64, value: u64) {
    write_varint(out, field << 3);
    write_varint(out, value);
}

fn write_string_field(out: &mut Vec<u8>, field: u64, value: &str) {
    write_varint(out, (field << 3) | 2);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(bytes: &[u8], index: &mut usize) -> Result<u64> {
    let mut result = 0_u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes
            .get(*index)
            .ok_or_else(|| AdbError::Protocol("server-status protobuf 截断".to_string()))?;
        *index += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(AdbError::Protocol(
        "server-status protobuf varint 过长".to_string(),
    ))
}

fn read_string(bytes: &[u8], index: &mut usize) -> Result<String> {
    let len = read_varint(bytes, index)? as usize;
    let end = index
        .checked_add(len)
        .ok_or_else(|| AdbError::Protocol("server-status protobuf 长度溢出".to_string()))?;
    let slice = bytes
        .get(*index..end)
        .ok_or_else(|| AdbError::Protocol("server-status protobuf 字符串截断".to_string()))?;
    *index = end;
    String::from_utf8(slice.to_vec())
        .map_err(|err| AdbError::Protocol(format!("server-status 字符串非 UTF-8: {err}")))
}

fn skip(bytes: &[u8], index: &mut usize, len: usize) -> Result<()> {
    let end = index
        .checked_add(len)
        .ok_or_else(|| AdbError::Protocol("server-status protobuf skip 溢出".to_string()))?;
    if end > bytes.len() {
        return Err(AdbError::Protocol(
            "server-status protobuf 字段截断".to_string(),
        ));
    }
    *index = end;
    Ok(())
}

fn push_line(out: &mut String, field: &str, value: &str) {
    out.push_str(field);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn push_bool_line(out: &mut String, field: &str, value: bool) {
    push_line(out, field, if value { "true" } else { "false" });
}

fn push_string_line(out: &mut String, field: &str, value: &str) {
    out.push_str(field);
    out.push_str(": \"");
    out.push_str(&escape_text_proto(value));
    out.push_str("\"\n");
}

fn escape_text_proto(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_status_round_trips_minimal_proto() {
        let status = AdbServerStatus {
            usb_backend: UsbBackend::Libusb,
            usb_backend_forced: None,
            mdns_backend: MdnsBackend::Openscreen,
            mdns_backend_forced: Some(true),
            version: "adb-rust-test".to_string(),
            build: "local".to_string(),
            executable_absolute_path: "C:\\adb.exe".to_string(),
            log_absolute_path: String::new(),
            os: "windows".to_string(),
            trace_level: Some("adb".to_string()),
            burst_mode: Some(false),
            mdns_enabled: Some(false),
            keystore_path: Some("C:\\Users\\me\\.android\\adbkey".to_string()),
            known_hosts_path: Some("C:\\Users\\me\\.android\\adb_known_hosts.pb".to_string()),
        };

        let decoded = AdbServerStatus::decode(&status.encode()).unwrap();
        assert_eq!(decoded, status);
        let text = decoded.to_text_proto();
        assert!(text.contains("usb_backend: LIBUSB"));
        assert!(!text.contains("usb_backend_forced:"));
        assert!(text.contains("mdns_backend: OPENSCREEN"));
        assert!(text.contains("mdns_backend_forced: true"));
        assert!(text.contains("executable_absolute_path: \"C:\\\\adb.exe\""));
        assert!(text.contains("keystore_path: \"C:\\\\Users\\\\me\\\\.android\\\\adbkey\""));
        assert!(
            text.contains(
                "known_hosts_path: \"C:\\\\Users\\\\me\\\\.android\\\\adb_known_hosts.pb\""
            )
        );
    }

    #[test]
    fn server_status_omits_non_optional_false_forced_flags() {
        let status = AdbServerStatus {
            usb_backend: UsbBackend::Libusb,
            usb_backend_forced: Some(false),
            mdns_backend: MdnsBackend::Openscreen,
            mdns_backend_forced: Some(false),
            version: "test".to_string(),
            build: "test".to_string(),
            executable_absolute_path: "adb".to_string(),
            log_absolute_path: "adb.log".to_string(),
            os: "test".to_string(),
            trace_level: None,
            burst_mode: None,
            mdns_enabled: None,
            keystore_path: None,
            known_hosts_path: None,
        };

        let decoded = AdbServerStatus::decode(&status.encode()).unwrap();
        assert_eq!(decoded.usb_backend_forced, None);
        assert_eq!(decoded.mdns_backend_forced, None);
        let text = status.to_text_proto();
        assert!(!text.contains("usb_backend_forced:"));
        assert!(!text.contains("mdns_backend_forced:"));
    }

    #[test]
    fn server_status_decodes_newer_libadbmdns_enum() {
        let mut bytes = Vec::new();
        write_varint_field(&mut bytes, 3, 3);
        let status = AdbServerStatus::decode(&bytes).unwrap();
        assert_eq!(status.mdns_backend, MdnsBackend::Libadbmdns);
        assert!(status.to_text_proto().contains("mdns_backend: LIBADBMDNS"));
    }

    #[test]
    fn server_status_decodes_libadbusb_enum() {
        let mut bytes = Vec::new();
        write_varint_field(&mut bytes, 1, 4);
        let status = AdbServerStatus::decode(&bytes).unwrap();
        assert_eq!(status.usb_backend, UsbBackend::Libadbusb);
        assert!(status.to_text_proto().contains("usb_backend: LIBADBUSB"));
    }

    #[test]
    fn server_status_os_version_uses_aosp_shape() {
        let os = os_version();
        #[cfg(windows)]
        assert!(
            os.starts_with("Windows "),
            "Windows OS 字符串不符合 AOSP 形态: {os}"
        );
        #[cfg(not(windows))]
        assert!(os.contains(" ("), "Unix OS 字符串不符合 AOSP 形态: {os}");
    }
}
