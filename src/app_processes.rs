use crate::error::{AdbError, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppProcesses {
    pub process: Vec<ProcessEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: i64,
    pub debuggable: bool,
    pub profileable: bool,
    pub architecture: String,
    pub user_id: Option<i64>,
    pub process_name: Option<String>,
    pub package_names: Vec<String>,
    pub waiting_for_debugger: Option<bool>,
    pub uid: Option<i64>,
}

impl AppProcesses {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut index = 0;
        let mut processes = AppProcesses::default();
        while index < bytes.len() {
            let tag = read_varint(bytes, &mut index)?;
            let field = tag >> 3;
            let wire_type = tag & 0x07;
            match (field, wire_type) {
                (1, 2) => {
                    let len = read_len(bytes, &mut index, "track-app process 长度溢出")?;
                    let end = checked_end(index, len, "track-app process 长度溢出")?;
                    let payload = bytes.get(index..end).ok_or_else(|| {
                        AdbError::Protocol("track-app process 字段截断".to_string())
                    })?;
                    processes.process.push(ProcessEntry::decode(payload)?);
                    index = end;
                }
                (_, other) => skip_field(bytes, &mut index, other, "track-app AppProcesses")?,
            }
        }
        Ok(processes)
    }

    pub fn to_track_app_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Process count: ");
        out.push_str(&self.process.len().to_string());
        out.push('\n');
        for process in &self.process {
            process.push_text_proto(&mut out);
        }
        out
    }
}

impl ProcessEntry {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut index = 0;
        let mut process = ProcessEntry::default();
        while index < bytes.len() {
            let tag = read_varint(bytes, &mut index)?;
            let field = tag >> 3;
            let wire_type = tag & 0x07;
            match (field, wire_type) {
                (1, 0) => process.pid = read_varint(bytes, &mut index)? as i64,
                (2, 0) => process.debuggable = read_bool(bytes, &mut index)?,
                (3, 0) => process.profileable = read_bool(bytes, &mut index)?,
                (4, 2) => process.architecture = read_string(bytes, &mut index, "architecture")?,
                (5, 0) => process.user_id = Some(read_varint(bytes, &mut index)? as i64),
                (6, 2) => {
                    process.process_name = Some(read_string(bytes, &mut index, "process_name")?)
                }
                (7, 2) => {
                    process
                        .package_names
                        .push(read_string(bytes, &mut index, "package_names")?)
                }
                (8, 0) => process.waiting_for_debugger = Some(read_bool(bytes, &mut index)?),
                (9, 0) => process.uid = Some(read_varint(bytes, &mut index)? as i64),
                (_, other) => skip_field(bytes, &mut index, other, "track-app ProcessEntry")?,
            }
        }
        Ok(process)
    }

    fn push_text_proto(&self, out: &mut String) {
        out.push_str("process {\n");
        if self.pid != 0 {
            push_i64_line(out, 1, "pid", self.pid);
        }
        if self.debuggable {
            push_bool_line(out, 1, "debuggable", true);
        }
        if self.profileable {
            push_bool_line(out, 1, "profileable", true);
        }
        if !self.architecture.is_empty() {
            push_string_line(out, 1, "architecture", &self.architecture);
        }
        if let Some(user_id) = self.user_id {
            push_i64_line(out, 1, "user_id", user_id);
        }
        if let Some(process_name) = &self.process_name {
            push_string_line(out, 1, "process_name", process_name);
        }
        for package_name in &self.package_names {
            push_string_line(out, 1, "package_names", package_name);
        }
        if let Some(waiting_for_debugger) = self.waiting_for_debugger {
            push_bool_line(out, 1, "waiting_for_debugger", waiting_for_debugger);
        }
        if let Some(uid) = self.uid {
            push_i64_line(out, 1, "uid", uid);
        }
        out.push_str("}\n");
    }
}

pub fn track_app_frame_to_text(bytes: &[u8]) -> Result<String> {
    Ok(AppProcesses::decode(bytes)?.to_track_app_text())
}

fn read_varint(bytes: &[u8], index: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes
            .get(*index)
            .ok_or_else(|| AdbError::Protocol("track-app protobuf varint 截断".to_string()))?;
        *index += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(AdbError::Protocol(
        "track-app protobuf varint 溢出".to_string(),
    ))
}

fn read_bool(bytes: &[u8], index: &mut usize) -> Result<bool> {
    Ok(read_varint(bytes, index)? != 0)
}

fn read_string(bytes: &[u8], index: &mut usize, field: &str) -> Result<String> {
    let len = read_len(bytes, index, "track-app 字符串长度溢出")?;
    let end = checked_end(*index, len, "track-app 字符串长度溢出")?;
    let slice = bytes
        .get(*index..end)
        .ok_or_else(|| AdbError::Protocol(format!("track-app {field} 字符串截断")))?;
    *index = end;
    String::from_utf8(slice.to_vec())
        .map_err(|err| AdbError::Protocol(format!("track-app {field} 非 UTF-8: {err}")))
}

fn read_len(bytes: &[u8], index: &mut usize, overflow: &str) -> Result<usize> {
    let value = read_varint(bytes, index)?;
    usize::try_from(value).map_err(|_| AdbError::Protocol(overflow.to_string()))
}

fn checked_end(start: usize, len: usize, overflow: &str) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| AdbError::Protocol(overflow.to_string()))
}

fn skip_field(bytes: &[u8], index: &mut usize, wire_type: u64, context: &str) -> Result<()> {
    match wire_type {
        0 => {
            let _ = read_varint(bytes, index)?;
            Ok(())
        }
        1 => skip(bytes, index, 8),
        2 => {
            let len = read_len(bytes, index, "track-app unknown 字段长度溢出")?;
            skip(bytes, index, len)
        }
        5 => skip(bytes, index, 4),
        other => Err(AdbError::Protocol(format!(
            "{context} 不支持 wire type {other}"
        ))),
    }
}

fn skip(bytes: &[u8], index: &mut usize, len: usize) -> Result<()> {
    let end = checked_end(*index, len, "track-app skip 溢出")?;
    if end > bytes.len() {
        return Err(AdbError::Protocol(
            "track-app protobuf 字段截断".to_string(),
        ));
    }
    *index = end;
    Ok(())
}

fn push_i64_line(out: &mut String, indent: usize, field: &str, value: i64) {
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": ");
    out.push_str(&value.to_string());
    out.push('\n');
}

fn push_bool_line(out: &mut String, indent: usize, field: &str, value: bool) {
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": ");
    out.push_str(if value { "true" } else { "false" });
    out.push('\n');
}

fn push_string_line(out: &mut String, indent: usize, field: &str, value: &str) {
    push_indent(out, indent);
    out.push_str(field);
    out.push_str(": \"");
    out.push_str(&escape_text_proto(value));
    out.push_str("\"\n");
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
    use super::*;

    fn write_varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
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

    fn write_process_field(out: &mut Vec<u8>, process: &[u8]) {
        write_varint(out, (1 << 3) | 2);
        write_varint(out, process.len() as u64);
        out.extend_from_slice(process);
    }

    #[test]
    fn track_app_frame_to_text_matches_official_shape() {
        let mut first = Vec::new();
        write_varint_field(&mut first, 1, 18595);
        write_varint_field(&mut first, 2, 1);
        write_string_field(&mut first, 4, "arm64");
        write_string_field(&mut first, 6, "adb.test.process.name");
        write_string_field(&mut first, 7, "adb.test.app1");
        write_string_field(&mut first, 7, "adb.test.app2");
        write_varint_field(&mut first, 8, 1);
        write_varint_field(&mut first, 9, 10123);

        let mut second = Vec::new();
        write_varint_field(&mut second, 1, 18407);
        write_varint_field(&mut second, 2, 1);
        write_varint_field(&mut second, 3, 1);
        write_string_field(&mut second, 4, "arm64");

        let mut frame = Vec::new();
        write_process_field(&mut frame, &first);
        write_process_field(&mut frame, &second);

        let text = track_app_frame_to_text(&frame).unwrap();

        assert!(text.starts_with("Process count: 2\n"));
        assert!(text.contains("process {\n  pid: 18595\n"));
        assert!(text.contains("  debuggable: true\n"));
        assert!(text.contains("  process_name: \"adb.test.process.name\"\n"));
        assert!(text.contains("  package_names: \"adb.test.app1\"\n"));
        assert!(text.contains("  package_names: \"adb.test.app2\"\n"));
        assert!(text.contains("  waiting_for_debugger: true\n"));
        assert!(text.contains("  uid: 10123\n"));
        assert!(text.contains("  profileable: true\n"));
    }

    #[test]
    fn text_proto_escapes_strings() {
        let mut process = Vec::new();
        write_string_field(&mut process, 6, "name\\with\"quote\n");

        let mut frame = Vec::new();
        write_process_field(&mut frame, &process);

        let text = track_app_frame_to_text(&frame).unwrap();

        assert!(text.contains("process_name: \"name\\\\with\\\"quote\\n\""));
    }

    #[test]
    fn malformed_frame_reports_protocol_error() {
        assert!(matches!(
            track_app_frame_to_text(&[0x0a, 0x05, 0x08]),
            Err(AdbError::Protocol(_))
        ));
    }
}
