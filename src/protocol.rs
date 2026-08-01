use std::io::{Read, Write};

use crate::error::{AdbError, Result};

pub const A_SYNC: u32 = 0x434e_5953;
pub const A_CNXN: u32 = 0x4e58_4e43;
pub const A_AUTH: u32 = 0x4854_5541;
pub const A_OPEN: u32 = 0x4e45_504f;
pub const A_OKAY: u32 = 0x5941_4b4f;
pub const A_CLSE: u32 = 0x4553_4c43;
pub const A_WRTE: u32 = 0x4554_5257;
pub const A_STLS: u32 = 0x534c_5453;

pub const A_VERSION_MIN: u32 = 0x0100_0000;
pub const A_VERSION_SKIP_CHECKSUM: u32 = 0x0100_0001;
pub const A_VERSION: u32 = A_VERSION_SKIP_CHECKSUM;
pub const A_STLS_VERSION_MIN: u32 = 0x0100_0000;
pub const A_STLS_VERSION: u32 = A_STLS_VERSION_MIN;
pub const ADB_SERVER_VERSION: u32 = 41;
pub const ADB_AUTH_TOKEN: u32 = 1;
pub const ADB_AUTH_SIGNATURE: u32 = 2;
pub const ADB_AUTH_RSAPUBLICKEY: u32 = 3;
pub const MAX_PAYLOAD_V1: usize = 4 * 1024;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const SMART_SOCKET_MAX: usize = 0xffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbMessage {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub payload: Vec<u8>,
}

impl AdbMessage {
    pub fn new(command: u32, arg0: u32, arg1: u32, payload: impl Into<Vec<u8>>) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD {
            return Err(AdbError::Protocol(format!(
                "payload 过大: {} > {}",
                payload.len(),
                MAX_PAYLOAD
            )));
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            payload,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W, protocol_version: u32) -> Result<()> {
        let data_check = if protocol_version >= A_VERSION_SKIP_CHECKSUM {
            0
        } else {
            checksum(&self.payload)
        };

        let mut header = [0_u8; 24];
        put_u32_le(&mut header[0..4], self.command);
        put_u32_le(&mut header[4..8], self.arg0);
        put_u32_le(&mut header[8..12], self.arg1);
        put_u32_le(&mut header[12..16], self.payload.len() as u32);
        put_u32_le(&mut header[16..20], data_check);
        put_u32_le(&mut header[20..24], self.command ^ 0xffff_ffff);

        writer.write_all(&header)?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R, max_payload: usize) -> Result<Self> {
        let mut header = [0_u8; 24];
        reader.read_exact(&mut header)?;

        let command = get_u32_le(&header[0..4]);
        let arg0 = get_u32_le(&header[4..8]);
        let arg1 = get_u32_le(&header[8..12]);
        let data_length = get_u32_le(&header[12..16]) as usize;
        let data_check = get_u32_le(&header[16..20]);
        let magic = get_u32_le(&header[20..24]);

        if magic != (command ^ 0xffff_ffff) {
            return Err(AdbError::Protocol(format!(
                "bad magic for {}: {magic:#010x}",
                command_name(command)
            )));
        }
        if data_length > max_payload {
            return Err(AdbError::Protocol(format!(
                "payload 过大: {data_length} > {max_payload}"
            )));
        }

        let mut payload = vec![0_u8; data_length];
        reader.read_exact(&mut payload)?;

        let expected = checksum(&payload);
        if data_check != 0 && data_check != expected {
            return Err(AdbError::Protocol(format!(
                "bad checksum for {}: got {data_check:#010x}, expected {expected:#010x}",
                command_name(command)
            )));
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            payload,
        })
    }
}

pub fn checksum(payload: &[u8]) -> u32 {
    payload
        .iter()
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

pub fn command_name(command: u32) -> &'static str {
    match command {
        A_SYNC => "A_SYNC",
        A_CNXN => "A_CNXN",
        A_AUTH => "A_AUTH",
        A_OPEN => "A_OPEN",
        A_OKAY => "A_OKAY",
        A_CLSE => "A_CLSE",
        A_WRTE => "A_WRTE",
        A_STLS => "A_STLS",
        _ => "UNKNOWN",
    }
}

pub fn write_protocol_string<W: Write>(writer: &mut W, value: &str) -> Result<()> {
    write_protocol_bytes(writer, value.as_bytes())
}

pub fn write_protocol_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    if bytes.len() > SMART_SOCKET_MAX {
        return Err(AdbError::Protocol(format!(
            "smart-socket 字符串过长: {} > {}",
            bytes.len(),
            SMART_SOCKET_MAX
        )));
    }
    write!(writer, "{:04X}", bytes.len())?;
    writer.write_all(bytes)?;
    Ok(())
}

pub fn read_protocol_string<R: Read>(reader: &mut R) -> Result<String> {
    let bytes = read_protocol_bytes(reader)?;
    String::from_utf8(bytes).map_err(|err| AdbError::Protocol(format!("非 UTF-8 响应: {err}")))
}

pub fn read_protocol_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = read_hex_len(reader)?;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

pub fn write_okay<W: Write>(writer: &mut W) -> Result<()> {
    writer.write_all(b"OKAY")?;
    Ok(())
}

pub fn write_fail<W: Write>(writer: &mut W, reason: &str) -> Result<()> {
    writer.write_all(b"FAIL")?;
    write_protocol_string(writer, reason)?;
    Ok(())
}

pub fn read_status<R: Read>(reader: &mut R) -> Result<()> {
    let mut status = [0_u8; 4];
    reader.read_exact(&mut status)?;

    match &status {
        b"OKAY" => Ok(()),
        b"FAIL" => Err(AdbError::Server(read_protocol_string(reader)?)),
        _ => Err(AdbError::Protocol(format!(
            "未知状态: {:02x} {:02x} {:02x} {:02x}",
            status[0], status[1], status[2], status[3]
        ))),
    }
}

fn read_hex_len<R: Read>(reader: &mut R) -> Result<usize> {
    let mut raw = [0_u8; 4];
    reader.read_exact(&mut raw)?;

    let text = std::str::from_utf8(&raw)
        .map_err(|err| AdbError::Protocol(format!("长度字段不是 ASCII: {err}")))?;
    usize::from_str_radix(text, 16)
        .map_err(|err| AdbError::Protocol(format!("非法长度字段 {text:?}: {err}")))
}

fn put_u32_le(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn get_u32_le(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn protocol_string_round_trip() {
        let mut out = Vec::new();
        write_protocol_string(&mut out, "host:version").unwrap();
        assert_eq!(out, b"000Chost:version");

        let mut cursor = Cursor::new(out);
        assert_eq!(read_protocol_string(&mut cursor).unwrap(), "host:version");
    }

    #[test]
    fn status_fail_reads_reason() {
        let mut wire = Vec::new();
        write_fail(&mut wire, "no devices").unwrap();

        let err = read_status(&mut Cursor::new(wire)).unwrap_err();
        assert!(matches!(err, AdbError::Server(reason) if reason == "no devices"));
    }

    #[test]
    fn message_round_trip_uses_little_endian_header() {
        let msg = AdbMessage::new(
            A_CNXN,
            A_VERSION,
            MAX_PAYLOAD as u32,
            b"host::rust".to_vec(),
        )
        .unwrap();
        let mut wire = Vec::new();
        msg.write_to(&mut wire, A_VERSION_MIN).unwrap();

        assert_eq!(&wire[0..4], &A_CNXN.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(wire[16..20].try_into().unwrap()),
            checksum(b"host::rust")
        );
        assert_eq!(
            AdbMessage::read_from(&mut Cursor::new(wire), MAX_PAYLOAD).unwrap(),
            msg
        );
    }

    #[test]
    fn message_allows_skip_checksum_protocol() {
        let msg = AdbMessage::new(A_WRTE, 1, 2, b"abc".to_vec()).unwrap();
        let mut wire = Vec::new();
        msg.write_to(&mut wire, A_VERSION).unwrap();

        assert_eq!(u32::from_le_bytes(wire[16..20].try_into().unwrap()), 0);
        assert_eq!(
            AdbMessage::read_from(&mut Cursor::new(wire), MAX_PAYLOAD).unwrap(),
            msg
        );
    }
}
