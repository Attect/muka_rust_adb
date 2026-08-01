use crate::transport::{ConnectionState, TransportConnectionType, TransportInfo};

pub fn devices_proto_binary(devices: &[TransportInfo]) -> Vec<u8> {
    let mut out = Vec::new();
    for device in crate::transport::sorted_device_infos(devices) {
        let encoded = encode_device(device);
        write_varint(&mut out, (1 << 3) | 2);
        write_varint(&mut out, encoded.len() as u64);
        out.extend(encoded);
    }
    out
}

pub fn devices_proto_text(devices: &[TransportInfo]) -> String {
    let mut out = String::new();
    for device in crate::transport::sorted_device_infos(devices) {
        out.push_str("device {\n");
        push_nonempty_string_line(&mut out, 1, "serial", &device.serial);
        push_enum_line(&mut out, 1, "state", state_text(device.state));
        if let Some(bus_address) = &device.devpath {
            push_sanitized_string_line(&mut out, 1, "bus_address", bus_address, false);
        }
        if let Some(product) = &device.product {
            push_sanitized_string_line(&mut out, 1, "product", product, false);
        }
        if let Some(model) = &device.model {
            push_sanitized_string_line(&mut out, 1, "model", model, true);
        }
        if let Some(device_name) = &device.device {
            push_sanitized_string_line(&mut out, 1, "device", device_name, false);
        }
        push_enum_line(
            &mut out,
            1,
            "connection_type",
            connection_type_text(device.connection_type),
        );
        if device.negotiated_speed_mbps != 0 {
            push_i64_line(
                &mut out,
                1,
                "negotiated_speed",
                device.negotiated_speed_mbps as i64,
            );
        }
        if device.max_speed_mbps != 0 {
            push_i64_line(&mut out, 1, "max_speed", device.max_speed_mbps as i64);
        }
        push_i64_line(&mut out, 1, "transport_id", device.id as i64);
        out.push_str("}\n");
    }
    out
}

fn encode_device(device: &TransportInfo) -> Vec<u8> {
    let mut out = Vec::new();
    write_string_field(&mut out, 1, &device.serial);
    write_varint_field(&mut out, 2, state_number(device.state));
    if let Some(bus_address) = &device.devpath {
        write_sanitized_string_field(&mut out, 3, bus_address, false);
    }
    if let Some(product) = &device.product {
        write_sanitized_string_field(&mut out, 4, product, false);
    }
    if let Some(model) = &device.model {
        write_sanitized_string_field(&mut out, 5, model, true);
    }
    if let Some(device_name) = &device.device {
        write_sanitized_string_field(&mut out, 6, device_name, false);
    }
    write_varint_field(&mut out, 7, connection_type_number(device.connection_type));
    if device.negotiated_speed_mbps != 0 {
        write_varint_field(&mut out, 8, device.negotiated_speed_mbps);
    }
    if device.max_speed_mbps != 0 {
        write_varint_field(&mut out, 9, device.max_speed_mbps);
    }
    write_varint_field(&mut out, 10, device.id);
    out
}

fn state_number(state: ConnectionState) -> u64 {
    match state {
        ConnectionState::Device => 8,
        ConnectionState::Recovery => 10,
        ConnectionState::Bootloader => 7,
        ConnectionState::Sideload => 11,
        ConnectionState::Rescue => 12,
        ConnectionState::Authorizing => 2,
        ConnectionState::Unauthorized => 3,
        ConnectionState::NoPermissions => 4,
        ConnectionState::Detached => 5,
        ConnectionState::Offline => 6,
    }
}

fn state_text(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Device => "DEVICE",
        ConnectionState::Recovery => "RECOVERY",
        ConnectionState::Bootloader => "BOOTLOADER",
        ConnectionState::Sideload => "SIDELOAD",
        ConnectionState::Rescue => "RESCUE",
        ConnectionState::Authorizing => "AUTHORIZING",
        ConnectionState::Unauthorized => "UNAUTHORIZED",
        ConnectionState::NoPermissions => "NOPERMISSION",
        ConnectionState::Detached => "DETACHED",
        ConnectionState::Offline => "OFFLINE",
    }
}

fn connection_type_number(connection_type: TransportConnectionType) -> u64 {
    match connection_type {
        TransportConnectionType::Usb => 1,
        TransportConnectionType::Socket => 2,
    }
}

fn connection_type_text(connection_type: TransportConnectionType) -> &'static str {
    match connection_type {
        TransportConnectionType::Usb => "USB",
        TransportConnectionType::Socket => "SOCKET",
    }
}

fn write_varint_field(out: &mut Vec<u8>, field: u64, value: u64) {
    write_varint(out, field << 3);
    write_varint(out, value);
}

fn write_string_field(out: &mut Vec<u8>, field: u64, value: &str) {
    if value.is_empty() {
        return;
    }
    write_varint(out, (field << 3) | 2);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn write_sanitized_string_field(out: &mut Vec<u8>, field: u64, value: &str, alphanumeric: bool) {
    let sanitized = crate::transport::sanitize_device_field(value, alphanumeric);
    write_string_field(out, field, &sanitized);
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn push_nonempty_string_line(out: &mut String, indent: usize, field: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": \"");
    out.push_str(&escape_text_proto(value));
    out.push_str("\"\n");
}

fn push_sanitized_string_line(
    out: &mut String,
    indent: usize,
    field: &str,
    value: &str,
    alphanumeric: bool,
) {
    let sanitized = crate::transport::sanitize_device_field(value, alphanumeric);
    push_nonempty_string_line(out, indent, field, &sanitized);
}

fn push_enum_line(out: &mut String, indent: usize, field: &str, value: &str) {
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn push_i64_line(out: &mut String, indent: usize, field: &str, value: i64) {
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": ");
    out.push_str(&value.to_string());
    out.push('\n');
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
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
    use crate::protocol;

    use super::*;

    fn sample_device() -> TransportInfo {
        TransportInfo {
            id: 7,
            serial: "serial-1".to_string(),
            devpath: None,
            connection_type: TransportConnectionType::Socket,
            negotiated_speed_mbps: 0,
            max_speed_mbps: 0,
            state: ConnectionState::Device,
            product: Some("prod".to_string()),
            model: Some("model one".to_string()),
            device: Some("dev".to_string()),
            features: None,
            max_payload: protocol::MAX_PAYLOAD,
            protocol_version: protocol::A_VERSION,
        }
    }

    #[test]
    fn devices_proto_text_matches_adb_field_names() {
        let text = devices_proto_text(&[sample_device()]);

        assert!(text.contains("device {\n"));
        assert!(text.contains("serial: \"serial-1\""));
        assert!(text.contains("state: DEVICE"));
        assert!(text.contains("connection_type: SOCKET"));
        assert!(text.contains("transport_id: 7"));
    }

    #[test]
    fn devices_proto_binary_uses_repeated_device_field() {
        let binary = devices_proto_binary(&[sample_device()]);

        assert_eq!(binary[0], 0x0a);
        assert!(binary.windows("serial-1".len()).any(|w| w == b"serial-1"));
    }

    #[test]
    fn devices_proto_text_reports_usb_connection_type() {
        let mut device = sample_device();
        device.connection_type = TransportConnectionType::Usb;

        let text = devices_proto_text(&[device]);

        assert!(text.contains("connection_type: USB"));
    }

    #[test]
    fn devices_proto_binary_reports_usb_connection_type() {
        let mut device = sample_device();
        device.connection_type = TransportConnectionType::Usb;
        device.devpath = Some("usb:1-2.3".to_string());
        device.negotiated_speed_mbps = 480;
        device.max_speed_mbps = 5_000;

        let binary = devices_proto_binary(&[device]);

        assert!(
            binary
                .windows([0x38, 0x01].len())
                .any(|w| w == [0x38, 0x01])
        );
        assert!(
            binary
                .windows(b"usb:1-2.3".len())
                .any(|window| window == b"usb:1-2.3")
        );
        assert!(binary.windows(3).any(|window| window == [0x40, 0xe0, 0x03]));
        assert!(binary.windows(3).any(|window| window == [0x48, 0x88, 0x27]));
    }

    #[test]
    fn devices_proto_sanitizes_fields_like_aosp() {
        let mut device = sample_device();
        device.devpath = Some("usb:1-2\nextra".to_string());
        device.product = Some("prod\nuct".to_string());
        device.model = Some("Pixel 8-Pro".to_string());
        device.device = Some("dev\nice".to_string());

        let text = devices_proto_text(&[device.clone()]);
        assert!(text.contains("bus_address: \"usb:1-2_extra\""));
        assert!(text.contains("product: \"prod_uct\""));
        assert!(text.contains("model: \"Pixel_8_Pro\""));
        assert!(text.contains("device: \"dev_ice\""));

        let binary = devices_proto_binary(&[device]);
        assert!(
            binary
                .windows(b"usb:1-2_extra".len())
                .any(|w| w == b"usb:1-2_extra")
        );
        assert!(
            binary
                .windows(b"Pixel_8_Pro".len())
                .any(|w| w == b"Pixel_8_Pro")
        );
        assert!(
            !binary
                .windows(b"prod\nuct".len())
                .any(|w| w == b"prod\nuct")
        );
        assert!(!binary.windows(b"dev\nice".len()).any(|w| w == b"dev\nice"));
    }

    #[test]
    fn devices_proto_reports_detached_state_like_aosp() {
        let mut device = sample_device();
        device.state = ConnectionState::Detached;

        let text = devices_proto_text(&[device.clone()]);
        assert!(text.contains("state: DETACHED"));

        let binary = devices_proto_binary(&[device]);
        assert!(
            binary
                .windows([0x10, 0x05].len())
                .any(|w| w == [0x10, 0x05])
        );
    }

    #[test]
    fn devices_proto_reports_no_permission_state_like_aosp() {
        let mut device = sample_device();
        device.state = ConnectionState::NoPermissions;

        let text = devices_proto_text(&[device.clone()]);
        assert!(text.contains("state: NOPERMISSION"));

        let binary = devices_proto_binary(&[device]);
        assert!(
            binary
                .windows([0x10, 0x04].len())
                .any(|window| window == [0x10, 0x04])
        );
    }

    #[test]
    fn devices_proto_reports_authorizing_state_like_aosp() {
        let mut device = sample_device();
        device.state = ConnectionState::Authorizing;

        let text = devices_proto_text(&[device.clone()]);
        assert!(text.contains("state: AUTHORIZING"));

        let binary = devices_proto_binary(&[device]);
        assert!(
            binary
                .windows([0x10, 0x02].len())
                .any(|window| window == [0x10, 0x02])
        );
    }
}
