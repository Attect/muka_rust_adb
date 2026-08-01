//! AOSP fastdeploy 的主机端实现。
//!
//! 该模块负责解析 APK 元数据、生成 `FASTDEPLOY` patch，并管理设备端
//! `deployagent`。CLI 只选择安装模式，wire format 与 ZIP 边界集中在这里测试。

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use axmldecoder::Node;
use md5::{Digest, Md5};
use prost::Message;
use tempfile::NamedTempFile;
use zip::ZipArchive;

use crate::client::{self, ServerEndpoint, TransportSelector};
use crate::error::{AdbError, Result};
use crate::sync as file_sync;

pub const MIN_API_LEVEL: i32 = 24;

const AGENT_VERSION: i32 = 3;
const PACKAGE_MISSING: i32 = 3;
const INVALID_AGENT_VERSION: i32 = 4;
const DEVICE_AGENT_JAR: &str = "/data/local/tmp/deployagent.jar";
const DEVICE_AGENT_SCRIPT: &str = "/data/local/tmp/deployagent";
const PATCH_SIGNATURE: &[u8; 10] = b"FASTDEPLOY";
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_FILE_SIGNATURE: u32 = 0x0403_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const DATA_DESCRIPTOR_FLAG: u16 = 0x0008;
const STORED_COMPRESSION: u16 = 0;

const DEPLOY_AGENT: &[u8] = include_bytes!("../assets/fastdeploy/deployagent.jar");
const DEPLOY_AGENT_SCRIPT: &[u8] = include_bytes!("../assets/fastdeploy/deployagent.sh");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AgentUpdateStrategy {
    Always,
    NewerTimestamp,
    #[default]
    DifferentVersion,
}

#[derive(Clone, PartialEq, Message)]
struct ApkDumpProto {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(bytes = "vec", tag = "2")]
    central_directory: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    signature: Vec<u8>,
    #[prost(string, tag = "4")]
    absolute_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApkEntry {
    md5: [u8; 16],
    data_offset: u64,
    data_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkMetadata {
    absolute_path: String,
    entries: Vec<ApkEntry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatchStats {
    pub identical_entries: u64,
    pub identical_bytes: u64,
    pub total_entry_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CentralDirectoryEntry {
    md5: [u8; 16],
    local_header_offset: u64,
    compressed_data_size: u64,
}

pub fn device_api_level(endpoint: &ServerEndpoint, selector: &TransportSelector) -> Result<i32> {
    let output =
        client::run_shell_command_capture(endpoint, selector, "getprop ro.build.version.sdk")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(-1))
}

/// 提取已安装 APK 的设备端元数据。设备未安装目标包时返回 `None`，供普通安装回退。
pub fn extract_device_metadata(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    apk_path: &Path,
    strategy: AgentUpdateStrategy,
) -> Result<Option<ApkMetadata>> {
    match strategy {
        AgentUpdateStrategy::Always => deploy_agent(endpoint, selector, false)?,
        AgentUpdateStrategy::NewerTimestamp => deploy_agent(endpoint, selector, true)?,
        AgentUpdateStrategy::DifferentVersion => {}
    }

    let package_name = package_name_from_apk(apk_path)?;
    let escaped_package = escape_shell_arg(&package_name);
    let command = format!("{DEVICE_AGENT_SCRIPT} dump {AGENT_VERSION} {escaped_package}");
    let mut output = client::run_shell_command_capture(endpoint, selector, &command)?;

    if output.exit_code >= INVALID_AGENT_VERSION {
        if let Some(version) = parse_agent_version(&output.stdout) {
            println!("Device agent version is old ({version}), re-deploying");
        } else {
            println!("Could not detect agent on device, deploying");
        }
        deploy_agent(endpoint, selector, false)?;
        output = client::run_shell_command_capture(endpoint, selector, &command)?;
    }

    if output.exit_code == PACKAGE_MISSING {
        eprintln!("Package {escaped_package} not found, falling back to install");
        return Ok(None);
    }
    if output.exit_code != 0 {
        if output.exit_code == INVALID_AGENT_VERSION {
            return Err(AdbError::Server(format!(
                "After update agent version remains old: {}",
                String::from_utf8_lossy(&output.stdout)
            )));
        }
        eprintln!("Executing {command} returned {}", output.exit_code);
        if !output.stderr.is_empty() {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        }
        return Err(AdbError::Server("Aborting".to_string()));
    }

    decode_device_metadata(&output.stdout).map(Some)
}

pub fn stream_patch_for_install(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    apk_path: &Path,
    metadata: &ApkMetadata,
    pm_args: &[String],
    use_shell_v2: bool,
) -> Result<PatchStats> {
    let mut arguments = String::new();
    let mut replace_present = false;
    for argument in pm_args {
        arguments.push_str(argument);
        arguments.push(' ');
        replace_present |= argument == "-r";
    }
    if !replace_present {
        arguments.push_str("-r");
    }
    let service = format!("shell:{DEVICE_AGENT_SCRIPT} apply - -pm {arguments}");
    stream_patch(
        endpoint,
        selector,
        apk_path,
        metadata,
        &service,
        use_shell_v2,
    )
}

pub fn stream_patch_to_path(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    apk_path: &Path,
    metadata: &ApkMetadata,
    output_path: &str,
    use_shell_v2: bool,
) -> Result<PatchStats> {
    let service = format!("shell:{DEVICE_AGENT_SCRIPT} apply - -o {output_path}");
    stream_patch(
        endpoint,
        selector,
        apk_path,
        metadata,
        &service,
        use_shell_v2,
    )
}

fn stream_patch(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    apk_path: &Path,
    metadata: &ApkMetadata,
    service: &str,
    use_shell_v2: bool,
) -> Result<PatchStats> {
    let service = if use_shell_v2 {
        let command = service.strip_prefix("shell:").unwrap_or(service);
        format!("shell,v2,raw:{command}")
    } else {
        service.to_string()
    };
    let mut stream = client::open_device_service(endpoint, selector, &service)
        .map_err(|err| AdbError::Server(format!("Executing {service} returned {err}")))?;
    let stats = if use_shell_v2 {
        let mut patch = Vec::new();
        let stats = generate_patch(apk_path, metadata, &mut patch)?;
        client::write_shell_v2_stdin_data(&mut stream, &patch)?;
        stats
    } else {
        generate_patch(apk_path, metadata, &mut stream)?
    };
    stream.flush()?;
    if use_shell_v2 {
        client::close_shell_v2_stdin(&mut stream)?;
        let output = client::read_shell_v2_to_buffers_after_stdin(stream)?;
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        if output.exit_code != 0 {
            return Err(AdbError::Server(format!(
                "fastdeploy agent exited with status {}",
                output.exit_code
            )));
        }
    } else {
        let output = client::read_stream_to_bytes(stream)?;
        io::stdout().write_all(&output)?;
    }
    Ok(stats)
}

fn deploy_agent(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    check_timestamps: bool,
) -> Result<()> {
    push_agent_asset(
        endpoint,
        selector,
        DEPLOY_AGENT,
        DEVICE_AGENT_JAR,
        check_timestamps,
    )?;
    push_agent_asset(
        endpoint,
        selector,
        DEPLOY_AGENT_SCRIPT,
        DEVICE_AGENT_SCRIPT,
        check_timestamps,
    )?;

    let command = format!("chmod 777 {DEVICE_AGENT_SCRIPT}");
    let output = client::run_shell_command_capture(endpoint, selector, &command)?;
    if output.exit_code != 0 {
        return Err(AdbError::Server(format!(
            "Error executing {command} returncode: {}",
            output.exit_code
        )));
    }
    Ok(())
}

fn push_agent_asset(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    contents: &[u8],
    destination: &str,
    check_timestamps: bool,
) -> Result<()> {
    let mut temporary = NamedTempFile::new()?;
    temporary.write_all(contents)?;
    temporary.flush()?;
    let options = file_sync::PushOptions {
        sync: check_timestamps,
        ..file_sync::PushOptions::default()
    };
    file_sync::push(
        endpoint,
        selector,
        &[temporary.path().to_path_buf()],
        destination,
        options,
        None,
    )
    .map_err(|_| AdbError::Server("Failed to push fastdeploy agent to device.".to_string()))?;
    Ok(())
}

fn parse_agent_version(output: &[u8]) -> Option<i64> {
    let value = String::from_utf8_lossy(output);
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn escape_shell_arg(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn package_name_from_apk(path: &Path) -> Result<String> {
    let file = File::open(path)
        .map_err(|err| AdbError::Server(format!("Could not open {}: {err}", path.display())))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|err| AdbError::Server(format!("Could not open {}: {err}", path.display())))?;
    let mut manifest = archive.by_name("AndroidManifest.xml").map_err(|_| {
        AdbError::Server(format!(
            "Could not find AndroidManifest.xml inside {}",
            path.display()
        ))
    })?;
    let mut contents = Vec::new();
    manifest.read_to_end(&mut contents).map_err(|_| {
        AdbError::Server(format!(
            "Could not uncompress AndroidManifest.xml inside {}",
            path.display()
        ))
    })?;
    let document = match std::panic::catch_unwind(|| axmldecoder::parse(&contents)) {
        Ok(Ok(document)) => document,
        Ok(Err(_)) | Err(_) => {
            return Err(AdbError::Server(format!(
                "Could not parse AndroidManifest.xml inside {}",
                path.display()
            )));
        }
    };
    let Some(Node::Element(root)) = document.get_root().as_ref() else {
        return Err(AdbError::Server(format!(
            "Could not find package name tag in AndroidManifest.xml inside {}",
            path.display()
        )));
    };
    if root.get_tag() == "manifest"
        && let Some(package_name) = root.get_attributes().get("package")
    {
        return Ok(package_name.clone());
    }
    Err(AdbError::Server(format!(
        "Could not find package name tag in AndroidManifest.xml inside {}",
        path.display()
    )))
}

fn decode_device_metadata(encoded: &[u8]) -> Result<ApkMetadata> {
    let dump = ApkDumpProto::decode(encoded)
        .map_err(|err| AdbError::Protocol(format!("无法解析 fastdeploy APKDump: {err}")))?;
    if dump.absolute_path.is_empty() {
        return Err(AdbError::Protocol(
            "fastdeploy APKDump 缺少 absolute_path".to_string(),
        ));
    }
    let entries = parse_central_directory(&dump.central_directory)?
        .into_iter()
        .map(|entry| ApkEntry {
            md5: entry.md5,
            data_offset: entry.local_header_offset,
            data_size: entry.compressed_data_size,
        })
        .collect();
    Ok(ApkMetadata {
        absolute_path: dump.absolute_path,
        entries,
    })
}

fn host_metadata(path: &Path) -> Result<ApkMetadata> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let central_directory = read_central_directory(&mut file, file_size, path)?;
    let records = parse_central_directory(&central_directory)?;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let data_size = local_file_entry_size(&mut file, file_size, path, &record)?;
        entries.push(ApkEntry {
            md5: record.md5,
            data_offset: record.local_header_offset,
            data_size,
        });
    }
    Ok(ApkMetadata {
        absolute_path: path.to_string_lossy().into_owned(),
        entries,
    })
}

fn read_central_directory(file: &mut File, file_size: u64, path: &Path) -> Result<Vec<u8>> {
    const EOCD_MIN_SIZE: u64 = 22;
    const EOCD_MAX_SIZE: u64 = 65_535 + EOCD_MIN_SIZE;
    if file_size < EOCD_MIN_SIZE {
        return Err(archive_error(
            path,
            "找不到 End of Central Directory record",
        ));
    }
    let tail_size = file_size.min(EOCD_MAX_SIZE);
    let mut tail = vec![
        0_u8;
        usize::try_from(tail_size).map_err(|_| {
            archive_error(path, "End of Central Directory 搜索窗口超出平台限制")
        })?
    ];
    file.seek(SeekFrom::Start(file_size - tail_size))?;
    file.read_exact(&mut tail)?;
    let Some(position) = tail
        .windows(EOCD_SIGNATURE.len())
        .rposition(|window| window == EOCD_SIGNATURE)
    else {
        return Err(archive_error(
            path,
            "找不到 End of Central Directory record",
        ));
    };
    if position + EOCD_MIN_SIZE as usize > tail.len() {
        return Err(archive_error(
            path,
            "End of Central Directory record 被截断",
        ));
    }
    let size = u64::from(read_u32(&tail, position + 12)?);
    let offset = u64::from(read_u32(&tail, position + 16)?);
    if offset.checked_add(size).is_none_or(|end| end > file_size) {
        return Err(archive_error(path, "Central Directory 范围超出 APK"));
    }
    read_region(file, offset, size, path)
}

fn parse_central_directory(bytes: &[u8]) -> Result<Vec<CentralDirectoryEntry>> {
    const FIXED_SIZE: usize = 46;
    let mut cursor = 0_usize;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < FIXED_SIZE
            || read_u32(bytes, cursor)? != CENTRAL_DIRECTORY_SIGNATURE
        {
            return Err(AdbError::Protocol(
                "Invalid Central Directory Record signature".to_string(),
            ));
        }
        let compression = read_u16(bytes, cursor + 10)?;
        let compressed_size = u64::from(read_u32(bytes, cursor + 20)?);
        let uncompressed_size = u64::from(read_u32(bytes, cursor + 24)?);
        let file_name_length = usize::from(read_u16(bytes, cursor + 28)?);
        let extra_length = usize::from(read_u16(bytes, cursor + 30)?);
        let comment_length = usize::from(read_u16(bytes, cursor + 32)?);
        let record_size = FIXED_SIZE
            .checked_add(file_name_length)
            .and_then(|size| size.checked_add(extra_length))
            .and_then(|size| size.checked_add(comment_length))
            .ok_or_else(|| AdbError::Protocol("Central Directory record 长度溢出".to_string()))?;
        let end = cursor.checked_add(record_size).ok_or_else(|| {
            AdbError::Protocol("Central Directory record 结束偏移溢出".to_string())
        })?;
        let record = bytes
            .get(cursor..end)
            .ok_or_else(|| AdbError::Protocol("Central Directory record 被截断".to_string()))?;
        let digest = Md5::digest(record);
        let mut md5 = [0_u8; 16];
        md5.copy_from_slice(&digest);
        entries.push(CentralDirectoryEntry {
            md5,
            local_header_offset: u64::from(read_u32(bytes, cursor + 42)?),
            compressed_data_size: if compression == STORED_COMPRESSION {
                uncompressed_size
            } else {
                compressed_size
            },
        });
        cursor = end;
    }
    Ok(entries)
}

fn local_file_entry_size(
    file: &mut File,
    file_size: u64,
    path: &Path,
    record: &CentralDirectoryEntry,
) -> Result<u64> {
    const LOCAL_HEADER_SIZE: u64 = 30;
    let header = read_region(file, record.local_header_offset, LOCAL_HEADER_SIZE, path)?;
    if read_u32(&header, 0)? != LOCAL_FILE_SIGNATURE {
        return Err(archive_error(path, "Invalid Local File Header signature"));
    }
    let flags = read_u16(&header, 6)?;
    let compression = read_u16(&header, 8)?;
    let compressed_size = u64::from(read_u32(&header, 18)?);
    let uncompressed_size = u64::from(read_u32(&header, 22)?);
    let file_name_length = u64::from(read_u16(&header, 26)?);
    let extra_length = u64::from(read_u16(&header, 28)?);
    let descriptor_offset = record
        .local_header_offset
        .checked_add(LOCAL_HEADER_SIZE)
        .and_then(|offset| offset.checked_add(file_name_length))
        .and_then(|offset| offset.checked_add(extra_length))
        .and_then(|offset| offset.checked_add(record.compressed_data_size))
        .ok_or_else(|| archive_error(path, "Local File Header 偏移溢出"))?;

    let (local_data_size, descriptor_size) = if flags & DATA_DESCRIPTOR_FLAG != 0 {
        let descriptor = read_region(file, descriptor_offset, 16, path)?;
        let has_signature = read_u32(&descriptor, 0)? == DATA_DESCRIPTOR_SIGNATURE;
        let base = if has_signature { 4 } else { 0 };
        let compressed_size = u64::from(read_u32(&descriptor, base + 4)?);
        let uncompressed_size = u64::from(read_u32(&descriptor, base + 8)?);
        (
            if compression == STORED_COMPRESSION {
                uncompressed_size
            } else {
                compressed_size
            },
            if has_signature { 16 } else { 12 },
        )
    } else {
        (
            if compression == STORED_COMPRESSION {
                uncompressed_size
            } else {
                compressed_size
            },
            0,
        )
    };
    if local_data_size != record.compressed_data_size {
        return Err(archive_error(
            path,
            "Central Directory 与 Local File Header 大小不一致",
        ));
    }
    let size = LOCAL_HEADER_SIZE
        .checked_add(file_name_length)
        .and_then(|size| size.checked_add(extra_length))
        .and_then(|size| size.checked_add(record.compressed_data_size))
        .and_then(|size| size.checked_add(descriptor_size))
        .ok_or_else(|| archive_error(path, "Local File Entry 长度溢出"))?;
    if record
        .local_header_offset
        .checked_add(size)
        .is_none_or(|end| end > file_size)
    {
        return Err(archive_error(path, "Local File Entry 范围超出 APK"));
    }
    Ok(size)
}

fn generate_patch(
    local_apk: &Path,
    device_metadata: &ApkMetadata,
    output: &mut impl Write,
) -> Result<PatchStats> {
    let local_metadata = host_metadata(local_apk)?;
    let mut device_entries: HashMap<[u8; 16], Vec<&ApkEntry>> = HashMap::new();
    for entry in &device_metadata.entries {
        device_entries.entry(entry.md5).or_default().push(entry);
    }

    let mut identical = Vec::new();
    let mut stats = PatchStats::default();
    for local_entry in &local_metadata.entries {
        stats.total_entry_bytes = stats
            .total_entry_bytes
            .saturating_add(local_entry.data_size);
        let Some(matches) = device_entries.get(&local_entry.md5) else {
            continue;
        };
        if let Some(device_entry) = matches.iter().find(|entry| entry.md5 == local_entry.md5) {
            identical.push((local_entry, *device_entry));
            stats.identical_entries += 1;
            stats.identical_bytes = stats.identical_bytes.saturating_add(local_entry.data_size);
        }
    }
    identical.sort_by_key(|(local, _)| local.data_offset);
    let percent = if stats.total_entry_bytes == 0 {
        0.0
    } else {
        stats.identical_bytes as f64 * 100.0 / stats.total_entry_bytes as f64
    };
    eprintln!("Detected {} equal APK entries", stats.identical_entries);
    eprintln!(
        "{} bytes are equal out of {} ({percent:.2}%)",
        stats.identical_bytes, stats.total_entry_bytes
    );

    let mut input = File::open(local_apk)?;
    let new_apk_size = input.metadata()?.len();
    output.write_all(PATCH_SIGNATURE)?;
    write_all_i64(output, checked_i64(new_apk_size, "APK 大小")?)?;
    let device_path = device_metadata.absolute_path.as_bytes();
    write_all_i64(
        output,
        checked_i64(device_path.len() as u64, "设备 APK 路径长度")?,
    )?;
    output.write_all(device_path)?;

    let mut current_size = 0_u64;
    let mut real_size = 0_u64;
    let mut pending = PendingPatchEntry::default();
    for (local_entry, device_entry) in identical {
        let delta = local_entry
            .data_offset
            .checked_sub(current_size)
            .ok_or_else(|| {
                AdbError::Protocol("fastdeploy local entry 顺序或范围无效".to_string())
            })?;
        if delta > 0 {
            write_patch_entry(&mut input, output, &pending, &mut real_size)?;
            pending = PendingPatchEntry {
                new_data_length: delta,
                old_data_offset: device_entry.data_offset,
                old_data_length: local_entry.data_size,
            };
        } else {
            pending.old_data_length = pending
                .old_data_length
                .checked_add(local_entry.data_size)
                .ok_or_else(|| AdbError::Protocol("fastdeploy device data 长度溢出".to_string()))?;
        }
        current_size = current_size
            .checked_add(delta)
            .and_then(|size| size.checked_add(local_entry.data_size))
            .ok_or_else(|| AdbError::Protocol("fastdeploy 输出长度溢出".to_string()))?;
    }
    write_patch_entry(&mut input, output, &pending, &mut real_size)?;
    if real_size != current_size {
        return Err(AdbError::Protocol(format!(
            "fastdeploy size mismatch current {current_size} vs real {real_size}"
        )));
    }
    if new_apk_size > current_size {
        let tail = new_apk_size - current_size;
        write_all_i64(output, checked_i64(tail, "patch 尾部长度")?)?;
        copy_exact(&mut input, output, tail)?;
        write_all_i64(output, 0)?;
        write_all_i64(output, 0)?;
    }
    Ok(stats)
}

#[derive(Debug, Clone, Copy, Default)]
struct PendingPatchEntry {
    new_data_length: u64,
    old_data_offset: u64,
    old_data_length: u64,
}

fn write_patch_entry(
    input: &mut File,
    output: &mut impl Write,
    entry: &PendingPatchEntry,
    real_size: &mut u64,
) -> Result<()> {
    if entry.new_data_length == 0 && entry.old_data_offset == 0 && entry.old_data_length == 0 {
        return Ok(());
    }
    write_all_i64(
        output,
        checked_i64(entry.new_data_length, "patch 新数据长度")?,
    )?;
    if entry.new_data_length > 0 {
        copy_exact(input, output, entry.new_data_length)?;
    }
    input.seek(SeekFrom::Current(checked_i64(
        entry.old_data_length,
        "patch 旧数据长度",
    )?))?;
    write_all_i64(
        output,
        checked_i64(entry.old_data_offset, "patch 旧数据偏移")?,
    )?;
    write_all_i64(
        output,
        checked_i64(entry.old_data_length, "patch 旧数据长度")?,
    )?;
    *real_size = real_size
        .checked_add(entry.new_data_length)
        .and_then(|size| size.checked_add(entry.old_data_length))
        .ok_or_else(|| AdbError::Protocol("fastdeploy 实际输出长度溢出".to_string()))?;
    Ok(())
}

fn copy_exact(input: &mut impl Read, output: &mut impl Write, amount: u64) -> Result<()> {
    let mut limited = input.take(amount);
    let copied = io::copy(&mut limited, output)?;
    if copied != amount {
        return Err(AdbError::Protocol(format!(
            "fastdeploy patch 输入被截断: expected {amount}, got {copied}"
        )));
    }
    Ok(())
}

fn read_region(file: &mut File, offset: u64, size: u64, path: &Path) -> Result<Vec<u8>> {
    let size =
        usize::try_from(size).map_err(|_| archive_error(path, "APK 区域大小超出平台限制"))?;
    let mut buffer = vec![0_u8; size];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer)
        .map_err(|err| archive_error(path, &format!("读取 APK 区域失败: {err}")))?;
    Ok(buffer)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| AdbError::Protocol("fastdeploy 元数据被截断".to_string()))?;
    Ok(u16::from_le_bytes(
        value.try_into().expect("slice length checked"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| AdbError::Protocol("fastdeploy 元数据被截断".to_string()))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("slice length checked"),
    ))
}

fn write_all_i64(output: &mut impl Write, value: i64) -> Result<()> {
    output.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn checked_i64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| AdbError::Protocol(format!("{label} 超过 int64 范围")))
}

fn archive_error(path: &Path, message: &str) -> AdbError {
    AdbError::Protocol(format!("{}: {message}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn write_test_apk(entries: &[(&str, &[u8])]) -> NamedTempFile {
        let temporary = NamedTempFile::new().unwrap();
        let file = temporary.reopen().unwrap();
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(zip::DateTime::default());
        for (name, contents) in entries {
            archive.start_file(*name, options).unwrap();
            archive.write_all(contents).unwrap();
        }
        archive.finish().unwrap();
        temporary
    }

    fn device_metadata_from_apk(path: &Path) -> ApkMetadata {
        let mut metadata = host_metadata(path).unwrap();
        metadata.absolute_path = "/data/app/com.example/base.apk".to_string();
        metadata
    }

    fn read_i64(input: &mut Cursor<&[u8]>) -> i64 {
        let mut value = [0_u8; 8];
        input.read_exact(&mut value).unwrap();
        i64::from_le_bytes(value)
    }

    fn apply_test_patch(patch: &[u8], old_apk: &[u8]) -> Vec<u8> {
        let mut input = Cursor::new(patch);
        let mut signature = [0_u8; 10];
        input.read_exact(&mut signature).unwrap();
        assert_eq!(&signature, PATCH_SIGNATURE);
        let new_size = usize::try_from(read_i64(&mut input)).unwrap();
        let path_size = usize::try_from(read_i64(&mut input)).unwrap();
        input.seek(SeekFrom::Current(path_size as i64)).unwrap();
        let mut output = Vec::with_capacity(new_size);
        while output.len() < new_size {
            let new_data_size = usize::try_from(read_i64(&mut input)).unwrap();
            let start = input.position() as usize;
            output.extend_from_slice(&patch[start..start + new_data_size]);
            input.seek(SeekFrom::Current(new_data_size as i64)).unwrap();
            let old_offset = usize::try_from(read_i64(&mut input)).unwrap();
            let old_size = usize::try_from(read_i64(&mut input)).unwrap();
            output.extend_from_slice(&old_apk[old_offset..old_offset + old_size]);
        }
        assert_eq!(output.len(), new_size);
        output
    }

    #[test]
    fn protobuf_dump_uses_aosp_field_numbers() {
        let dump = ApkDumpProto {
            name: "com.example".to_string(),
            central_directory: Vec::new(),
            signature: Vec::new(),
            absolute_path: "/data/app/base.apk".to_string(),
        };
        let metadata = decode_device_metadata(&dump.encode_to_vec()).unwrap();
        assert_eq!(metadata.absolute_path, "/data/app/base.apk");
        assert!(metadata.entries.is_empty());
    }

    #[test]
    fn identical_apk_patch_reuses_all_local_entries() {
        let apk = write_test_apk(&[
            ("classes.dex", b"same dex"),
            ("resources.arsc", b"same res"),
        ]);
        let metadata = device_metadata_from_apk(apk.path());
        let mut patch = Vec::new();
        let stats = generate_patch(apk.path(), &metadata, &mut patch).unwrap();
        let original = std::fs::read(apk.path()).unwrap();
        assert_eq!(stats.identical_entries, 2);
        assert!(patch.len() < original.len());
        assert_eq!(apply_test_patch(&patch, &original), original);
    }

    #[test]
    fn changed_apk_patch_reconstructs_exact_new_bytes() {
        let old_apk = write_test_apk(&[("classes.dex", b"same dex"), ("res/raw/a", b"old")]);
        let new_apk = write_test_apk(&[("classes.dex", b"same dex"), ("res/raw/a", b"new")]);
        let metadata = device_metadata_from_apk(old_apk.path());
        let mut patch = Vec::new();
        let stats = generate_patch(new_apk.path(), &metadata, &mut patch).unwrap();
        let old_bytes = std::fs::read(old_apk.path()).unwrap();
        let new_bytes = std::fs::read(new_apk.path()).unwrap();
        assert_eq!(stats.identical_entries, 1);
        assert_eq!(apply_test_patch(&patch, &old_bytes), new_bytes);
    }

    #[test]
    fn agent_version_accepts_hex_and_decimal_output() {
        assert_eq!(parse_agent_version(b"0x00000003\n"), Some(3));
        assert_eq!(parse_agent_version(b"3\n"), Some(3));
        assert_eq!(parse_agent_version(b"missing"), None);
    }

    #[test]
    fn package_name_is_read_from_binary_android_manifest() {
        let manifest = include_bytes!("../tests/data/fastdeploy-manifest.bin");
        let apk = write_test_apk(&[("AndroidManifest.xml", manifest)]);
        assert_eq!(
            package_name_from_apk(apk.path()).unwrap(),
            "com.example.helloworld"
        );
    }

    #[test]
    fn embedded_agent_assets_match_recorded_aosp_build() {
        use sha2::Sha256;

        assert_eq!(
            format!("{:x}", Sha256::digest(DEPLOY_AGENT)),
            "12f2c3a095ece48169fde287fe35c6b0018792e4adeebe02cba6a587a873192b"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(DEPLOY_AGENT_SCRIPT)),
            "394e90c084880299d2b3e4d205241141f658f34ababea5db4fc17e3ea9e2229d"
        );
    }
}
