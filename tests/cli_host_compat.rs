use std::collections::HashMap;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use adb_rust::auth;
use adb_rust::client::{self, ServerEndpoint};
use adb_rust::error::AdbError;
use adb_rust::protocol::{self, AdbMessage};
use filetime::{FileTime, set_file_mtime};

// 为 track-app 集成测试构造最小 AppProcesses protobuf 帧的辅助函数。
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    out.push((field << 3) as u8);
    write_varint(out, value);
}

fn write_string_field(out: &mut Vec<u8>, field: u32, value: &str) {
    out.push(((field << 3) | 2) as u8);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn write_process_field(out: &mut Vec<u8>, process: &[u8]) {
    out.push(((1 << 3) | 2) as u8);
    write_varint(out, process.len() as u64);
    out.extend_from_slice(process);
}

fn track_app_sample_frame() -> Vec<u8> {
    let mut process = Vec::new();
    write_varint_field(&mut process, 1, 12345);
    write_string_field(&mut process, 6, "adb.test.process");
    write_string_field(&mut process, 7, "adb.test.app");

    let mut frame = Vec::new();
    write_process_field(&mut frame, &process);

    let mut payload = format!("{:04x}", frame.len()).into_bytes();
    payload.extend(frame);
    payload
}

fn write_fastdeploy_test_apk(path: &std::path::Path) {
    write_fastdeploy_test_apk_with_package(path, "com.example.helloworld");
}

fn write_fastdeploy_test_apk_with_package(path: &std::path::Path, package_name: &str) {
    const ORIGINAL_PACKAGE: &[u8] = b"com.example.helloworld";
    assert_eq!(package_name.len(), ORIGINAL_PACKAGE.len());
    let mut manifest = include_bytes!("data/fastdeploy-manifest.bin").to_vec();
    if package_name.as_bytes() != ORIGINAL_PACKAGE {
        let original_utf16 = String::from_utf8_lossy(ORIGINAL_PACKAGE)
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let replacement_utf16 = package_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let position = manifest
            .windows(original_utf16.len())
            .position(|window| window == original_utf16)
            .expect("fixture must contain package name");
        manifest[position..position + original_utf16.len()].copy_from_slice(&replacement_utf16);
    }

    let file = std::fs::File::create(path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    archive.start_file("AndroidManifest.xml", options).unwrap();
    archive.write_all(&manifest).unwrap();
    archive.start_file("classes.dex", options).unwrap();
    archive.write_all(b"dex\n035\0fake-fastdeploy").unwrap();
    archive.finish().unwrap();
}

fn adb_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_adb")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Fallback for running the test binary directly without cargo's env.
            let mut path = std::env::current_exe().unwrap();
            path.pop();
            path.pop();
            path.push(if cfg!(windows) { "adb.exe" } else { "adb" });
            path
        })
}

/// Windows 下并发启动 adb.exe 时偶发 ERROR_ACCESS_DENIED（拒绝访问），
/// 对 spawn/output 做少量退避重试，降低全量测试的 flaky 率。
#[cfg(windows)]
fn is_windows_access_denied(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(5)
}

#[cfg(not(windows))]
fn is_windows_access_denied(_err: &std::io::Error) -> bool {
    false
}

fn is_windows_access_denied_output(output: &std::process::Output) -> bool {
    if cfg!(not(windows)) {
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("os error 5")
}

fn spawn_adb_with_retry(cmd: &mut Command, description: &str) -> std::process::Child {
    for attempt in 0..5 {
        match cmd.spawn() {
            Ok(child) => return child,
            Err(err) if is_windows_access_denied(&err) && attempt < 4 => {
                eprintln!("spawn {description} failed with access denied, retrying...");
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => panic!("failed to spawn {description}: {err}"),
        }
    }
    unreachable!()
}

fn output_adb_with_retry(cmd: &mut Command, description: &str) -> std::process::Output {
    for attempt in 0..5 {
        match cmd.output() {
            Ok(output) => return output,
            Err(err) if is_windows_access_denied(&err) && attempt < 4 => {
                eprintln!("run {description} failed with access denied, retrying...");
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => panic!("failed to run {description}: {err}"),
        }
    }
    unreachable!()
}

fn ephemeral_port() -> u16 {
    static NEXT_SERVER_PORT: AtomicU32 = AtomicU32::new(20_000);
    for _ in 0..40_000 {
        let sequence = NEXT_SERVER_PORT.fetch_add(1, Ordering::Relaxed);
        let port = 20_000 + (sequence.saturating_sub(20_000) % 40_000) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("failed to allocate a unique integration-test port");
}

/// 集成测试并发限流器。
/// Windows 下大量同时启动 adb.exe 子进程/绑定端口时偶发“拒绝访问”，
/// 通过限制同时活跃的 server+client 进程数来降低失败率。当前限制为 2。
struct ConcurrencyLimiter {
    inner: Mutex<usize>,
    cvar: Condvar,
}

struct ConcurrencyPermit {
    limiter: &'static ConcurrencyLimiter,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        let mut count = self.limiter.inner.lock().unwrap();
        *count += 1;
        self.limiter.cvar.notify_one();
    }
}

impl ConcurrencyLimiter {
    fn new(max: usize) -> Self {
        Self {
            inner: Mutex::new(max),
            cvar: Condvar::new(),
        }
    }

    fn acquire(&'static self) -> ConcurrencyPermit {
        let mut count = self.inner.lock().unwrap();
        while *count == 0 {
            count = self.cvar.wait(count).unwrap();
        }
        *count -= 1;
        ConcurrencyPermit { limiter: self }
    }
}

static INTEGRATION_LIMITER: OnceLock<ConcurrencyLimiter> = OnceLock::new();
static FASTDEPLOY_OLD_AGENT_DUMPS: AtomicU32 = AtomicU32::new(0);

fn integration_limiter() -> &'static ConcurrencyLimiter {
    INTEGRATION_LIMITER.get_or_init(|| ConcurrencyLimiter::new(2))
}

// 最小 fake ADB device：处理 CNXN 握手，对 A_OPEN 回 A_OKAY，并在收到对端的 A_OKAY 后
// 按需返回 shell/reverse 响应，最后 A_CLSE。写操作通过 Mutex 序列化，避免报文交错。
struct FakeAdbDevice {
    port: u16,
}

#[derive(Debug, Clone)]
struct FakeFile {
    mode: u32,
    mtime: u32,
    content: Vec<u8>,
}

#[derive(Debug)]
enum SyncSession {
    Send {
        path: String,
        mode: u32,
        flags: u32,
        buffer: Vec<u8>,
    },
    Recv {
        path: String,
    },
}

type FakeFs = Arc<Mutex<HashMap<String, FakeFile>>>;
type SyncSessions = Arc<Mutex<HashMap<u32, SyncSession>>>;

#[derive(Debug, Clone)]
struct ReverseRule {
    // reverse 规则中，remote 是设备端 local，local 是主机端 remote。
    remote: String,
    local: String,
}

type ReverseRules = Arc<Mutex<Vec<ReverseRule>>>;

#[derive(Debug)]
enum PendingResponse {
    ShellV2(String),
    ShellLegacy(String),
    ReverseList(Vec<u8>),
    ReverseKillforward,
    ReverseForward(Option<u16>),
    ReverseForwardFail(String),
    Reconnect,
    SimpleService(Vec<u8>),
    SyncService,
    SideloadService {
        expected_size: u64,
        received: u64,
    },
    RestoreService,
    BackupService,
    SideloadHost {
        size: u64,
        block_size: u64,
        next_block: u64,
    },
    AbbExecPackage {
        subcommand: String,
    },
    AbbExecWrite {
        size: u64,
        received: u64,
    },
    FastDeployApply {
        buffer: Vec<u8>,
        shell_v2: bool,
    },
}

impl FakeAdbDevice {
    fn start() -> Self {
        Self::start_with_features("shell_v2")
    }

    fn start_with_features(features: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let features = features.to_string();
        let next_session = Arc::new(AtomicU32::new(1));
        thread::spawn(move || {
            let fs: FakeFs = Arc::new(Mutex::new(HashMap::from([
                (
                    "/data/local/tmp".to_string(),
                    FakeFile {
                        mode: 0o040755,
                        mtime: 1_700_000_000,
                        content: Vec::new(),
                    },
                ),
                (
                    "/data/local/tmp/hello.txt".to_string(),
                    FakeFile {
                        mode: 0o100644,
                        mtime: 1_700_000_000,
                        content: b"hello, sync\n".to_vec(),
                    },
                ),
                (
                    "/data/local/tmp/pull_dir".to_string(),
                    FakeFile {
                        mode: 0o040755,
                        mtime: 1_700_000_000,
                        content: Vec::new(),
                    },
                ),
                (
                    "/data/local/tmp/pull_dir/nested.txt".to_string(),
                    FakeFile {
                        mode: 0o100644,
                        mtime: 1_700_000_000,
                        content: b"nested content\n".to_vec(),
                    },
                ),
                (
                    "/data/local/tmp/push_dir".to_string(),
                    FakeFile {
                        mode: 0o040755,
                        mtime: 1_700_000_000,
                        content: Vec::new(),
                    },
                ),
                (
                    "/data/local/tmp/multi_push".to_string(),
                    FakeFile {
                        mode: 0o040755,
                        mtime: 1_700_000_000,
                        content: Vec::new(),
                    },
                ),
                (
                    "/data/local/tmp/bugreport.zip".to_string(),
                    FakeFile {
                        mode: 0o100644,
                        mtime: 1_700_000_000,
                        content: b"fake zipped bugreport\n".to_vec(),
                    },
                ),
            ])));
            let sync_sessions: SyncSessions = Arc::new(Mutex::new(HashMap::new()));
            let reverse_rules: ReverseRules = Arc::new(Mutex::new(Vec::new()));

            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

            let mut handshake_reader = stream.try_clone().unwrap();
            let cnxn = AdbMessage::read_from(&mut handshake_reader, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(cnxn.command, protocol::A_CNXN);

            let writer = stream.try_clone().unwrap();
            let banner = format!(
                "device::ro.product.name=adb-rust-test;ro.product.model=Fake;ro.product.device=fake-device;features={features};"
            )
            .into_bytes();
            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                banner,
            )
            .unwrap()
            .write_to(&mut writer.try_clone().unwrap(), protocol::A_VERSION)
            .unwrap();

            Self::handle_messages(
                stream,
                writer,
                fs,
                sync_sessions,
                next_session,
                reverse_rules.clone(),
            );
        });
        Self { port }
    }

    fn handle_messages(
        reader: std::net::TcpStream,
        writer: std::net::TcpStream,
        fs: FakeFs,
        sync_sessions: SyncSessions,
        next_session: Arc<AtomicU32>,
        reverse_rules: ReverseRules,
    ) {
        let writer = Arc::new(Mutex::new(writer));
        let mut reader = reader;
        let mut next_device_id: u32 = 100;
        let pending: Arc<Mutex<HashMap<u32, PendingResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sync_buffers: Arc<Mutex<HashMap<u32, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));

        loop {
            let packet = match AdbMessage::read_from(&mut reader, protocol::MAX_PAYLOAD) {
                Ok(packet) => packet,
                Err(AdbError::Io(err))
                    if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(_) => break,
            };

            match packet.command {
                protocol::A_OPEN => {
                    let host_id = packet.arg0;
                    let device_id = next_device_id;
                    next_device_id += 1;
                    let service = String::from_utf8_lossy(&packet.payload);
                    let service = service.strip_suffix('\0').unwrap_or(&service).to_string();

                    if let Some(response) = Self::classify_service(&service, &reverse_rules) {
                        match response {
                            PendingResponse::ShellV2(_)
                            | PendingResponse::SyncService
                            | PendingResponse::SideloadService { .. }
                            | PendingResponse::RestoreService
                            | PendingResponse::FastDeployApply { .. } => {
                                pending.lock().unwrap().insert(host_id, response);
                            }
                            PendingResponse::SideloadHost {
                                size,
                                block_size,
                                next_block,
                            } => {
                                pending.lock().unwrap().insert(
                                    host_id,
                                    PendingResponse::SideloadHost {
                                        size,
                                        block_size,
                                        next_block: next_block + 1,
                                    },
                                );
                                let writer = Arc::clone(&writer);
                                thread::spawn(move || {
                                    thread::sleep(Duration::from_millis(50));
                                    let offset = next_block * block_size;
                                    if offset >= size {
                                        Self::write_wrte(
                                            &writer,
                                            device_id,
                                            host_id,
                                            b"DONEDONE".to_vec(),
                                        );
                                        Self::write_clse(&writer, device_id, host_id);
                                    } else {
                                        Self::write_wrte(
                                            &writer,
                                            device_id,
                                            host_id,
                                            format!("{:08}", next_block).into_bytes(),
                                        );
                                    }
                                });
                            }
                            PendingResponse::BackupService => {
                                let writer = Arc::clone(&writer);
                                thread::spawn(move || {
                                    thread::sleep(Duration::from_millis(50));
                                    Self::write_wrte(
                                        &writer,
                                        device_id,
                                        host_id,
                                        b"ANDROID BACKUP\n1\nfake backup payload".to_vec(),
                                    );
                                    Self::write_clse(&writer, device_id, host_id);
                                });
                            }
                            PendingResponse::AbbExecPackage { subcommand } => {
                                if subcommand == "install-write" {
                                    let size = Self::parse_abb_exec_write_size(&service);
                                    pending.lock().unwrap().insert(
                                        host_id,
                                        PendingResponse::AbbExecWrite { size, received: 0 },
                                    );
                                } else {
                                    let response = if subcommand == "install-create" {
                                        let id = next_session.fetch_add(1, Ordering::SeqCst);
                                        format!("Success: created install session [{id}]\n")
                                            .into_bytes()
                                    } else {
                                        b"Success\n".to_vec()
                                    };
                                    let writer = Arc::clone(&writer);
                                    thread::spawn(move || {
                                        thread::sleep(Duration::from_millis(50));
                                        Self::write_wrte(&writer, device_id, host_id, response);
                                        Self::write_clse(&writer, device_id, host_id);
                                    });
                                }
                            }
                            _ => {
                                let writer = Arc::clone(&writer);
                                thread::spawn(move || {
                                    thread::sleep(Duration::from_millis(50));
                                    Self::send_response(&writer, device_id, host_id, &response);
                                    Self::write_clse(&writer, device_id, host_id);
                                });
                            }
                        }
                    } else {
                        Self::write_clse(&writer, device_id, host_id);
                    }

                    let mut guard = writer.lock().unwrap_or_else(|err| err.into_inner());
                    AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                        .unwrap()
                        .write_to(&mut *guard, protocol::A_VERSION)
                        .unwrap();
                }
                protocol::A_OKAY => {}
                protocol::A_WRTE if packet.arg0 != packet.arg1 => {
                    let host_id = packet.arg0;
                    let device_id = packet.arg1;
                    let mut guard = writer.lock().unwrap_or_else(|err| err.into_inner());
                    AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                        .unwrap()
                        .write_to(&mut *guard, protocol::A_VERSION)
                        .unwrap();
                    drop(guard);

                    let is_sync = pending
                        .lock()
                        .unwrap()
                        .get(&host_id)
                        .is_some_and(|r| matches!(r, PendingResponse::SyncService));
                    if is_sync {
                        let mut buffer = sync_buffers.lock().unwrap();
                        let buf = buffer.entry(host_id).or_default();
                        buf.extend_from_slice(&packet.payload);
                        let buf_clone = buf.clone();
                        drop(buffer);
                        let consumed = Self::process_sync_buffer(
                            &writer,
                            device_id,
                            host_id,
                            &buf_clone,
                            &fs,
                            &sync_sessions,
                        );
                        if consumed > 0 {
                            sync_buffers
                                .lock()
                                .unwrap()
                                .get_mut(&host_id)
                                .unwrap()
                                .drain(..consumed);
                        }
                        continue;
                    }

                    let response = { pending.lock().unwrap().remove(&host_id) };
                    if let Some(response) = response {
                        match response {
                            PendingResponse::SideloadService {
                                expected_size,
                                mut received,
                            } => {
                                received += packet.payload.len() as u64;
                                if received >= expected_size {
                                    Self::write_wrte(&writer, device_id, host_id, b"OKAY".to_vec());
                                    Self::write_clse(&writer, device_id, host_id);
                                } else {
                                    pending.lock().unwrap().insert(
                                        host_id,
                                        PendingResponse::SideloadService {
                                            expected_size,
                                            received,
                                        },
                                    );
                                }
                            }
                            PendingResponse::RestoreService => {
                                let trailing_zeros = packet.payload.len() >= 1024
                                    && packet.payload[packet.payload.len() - 1024..]
                                        .iter()
                                        .all(|&b| b == 0);
                                if trailing_zeros {
                                    Self::write_wrte(&writer, device_id, host_id, b"OKAY".to_vec());
                                    Self::write_clse(&writer, device_id, host_id);
                                } else {
                                    pending
                                        .lock()
                                        .unwrap()
                                        .insert(host_id, PendingResponse::RestoreService);
                                }
                            }
                            PendingResponse::SideloadHost {
                                size,
                                block_size,
                                next_block,
                            } => {
                                let offset = next_block * block_size;
                                if offset >= size {
                                    Self::write_wrte(
                                        &writer,
                                        device_id,
                                        host_id,
                                        b"DONEDONE".to_vec(),
                                    );
                                    Self::write_clse(&writer, device_id, host_id);
                                } else {
                                    Self::write_wrte(
                                        &writer,
                                        device_id,
                                        host_id,
                                        format!("{:08}", next_block).into_bytes(),
                                    );
                                    pending.lock().unwrap().insert(
                                        host_id,
                                        PendingResponse::SideloadHost {
                                            size,
                                            block_size,
                                            next_block: next_block + 1,
                                        },
                                    );
                                }
                            }
                            PendingResponse::AbbExecWrite { size, received } => {
                                let received = received + packet.payload.len() as u64;
                                if received >= size {
                                    Self::write_wrte(
                                        &writer,
                                        device_id,
                                        host_id,
                                        b"Success\n".to_vec(),
                                    );
                                    Self::write_clse(&writer, device_id, host_id);
                                } else {
                                    pending.lock().unwrap().insert(
                                        host_id,
                                        PendingResponse::AbbExecWrite { size, received },
                                    );
                                }
                            }
                            PendingResponse::FastDeployApply {
                                mut buffer,
                                shell_v2,
                            } => {
                                if shell_v2 {
                                    let mut cursor = 0_usize;
                                    while cursor < packet.payload.len() {
                                        let id = packet.payload[cursor];
                                        cursor += 1;
                                        if id == 4 {
                                            break;
                                        }
                                        if id != 0 || cursor + 4 > packet.payload.len() {
                                            break;
                                        }
                                        let size = u32::from_le_bytes(
                                            packet.payload[cursor..cursor + 4].try_into().unwrap(),
                                        )
                                            as usize;
                                        cursor += 4;
                                        let Some(end) = cursor.checked_add(size) else {
                                            break;
                                        };
                                        if end > packet.payload.len() {
                                            break;
                                        }
                                        buffer.extend_from_slice(&packet.payload[cursor..end]);
                                        cursor = end;
                                    }
                                } else {
                                    buffer.extend_from_slice(&packet.payload);
                                }
                                let complete = Self::fastdeploy_patch_complete(&buffer);
                                if complete {
                                    if shell_v2 {
                                        let mut payload = Vec::new();
                                        Self::write_shell_v2_packet(&mut payload, 1, &[]);
                                        Self::write_shell_v2_packet(&mut payload, 2, &[]);
                                        Self::write_shell_v2_packet(&mut payload, 3, &[0]);
                                        Self::write_wrte(&writer, device_id, host_id, payload);
                                    }
                                    Self::write_clse(&writer, device_id, host_id);
                                } else {
                                    pending.lock().unwrap().insert(
                                        host_id,
                                        PendingResponse::FastDeployApply { buffer, shell_v2 },
                                    );
                                }
                            }
                            _ => {
                                Self::send_response(&writer, device_id, host_id, &response);
                                Self::write_clse(&writer, device_id, host_id);
                            }
                        }
                    }
                }
                protocol::A_CLSE if packet.arg0 != packet.arg1 => {
                    let host_id = packet.arg0;
                    let device_id = packet.arg1;
                    if let Some(response) = pending.lock().unwrap().remove(&host_id)
                        && let PendingResponse::AbbExecWrite { .. } = response
                    {
                        Self::write_wrte(&writer, device_id, host_id, b"Success\n".to_vec());
                        Self::write_clse(&writer, device_id, host_id);
                    }
                }
                _ => {}
            }
        }
    }

    fn classify_service(service: &str, reverse_rules: &ReverseRules) -> Option<PendingResponse> {
        if let Some(rest) = service.strip_prefix("shell,v2,") {
            let command = rest.split_once(':').map(|(_, cmd)| cmd).unwrap_or(rest);
            if command.starts_with("/data/local/tmp/deployagent apply - ") {
                return Some(PendingResponse::FastDeployApply {
                    buffer: Vec::new(),
                    shell_v2: true,
                });
            }
            return Some(PendingResponse::ShellV2(command.to_string()));
        }
        if let Some(command) = service.strip_prefix("shell:") {
            if command.starts_with("/data/local/tmp/deployagent apply - ") {
                return Some(PendingResponse::FastDeployApply {
                    buffer: Vec::new(),
                    shell_v2: false,
                });
            }
            return Some(PendingResponse::ShellLegacy(command.to_string()));
        }
        if service == "reverse:list-forward" {
            let rules = reverse_rules.lock().unwrap();
            let body = rules
                .iter()
                .map(|r| format!("host {} {}\n", r.remote, r.local))
                .collect::<String>();
            let payload = format!("{:04x}{}", body.len(), body).into_bytes();
            return Some(PendingResponse::ReverseList(payload));
        }
        if service == "reverse:killforward-all" {
            reverse_rules.lock().unwrap().clear();
            return Some(PendingResponse::ReverseKillforward);
        }
        if let Some(remote) = service.strip_prefix("reverse:killforward:")
            && !remote.contains(';')
        {
            reverse_rules.lock().unwrap().retain(|r| r.remote != remote);
            return Some(PendingResponse::ReverseKillforward);
        }
        if let Some(rest) = service.strip_prefix("reverse:forward:") {
            let (norebind, rest) = if let Some(r) = rest.strip_prefix("norebind:") {
                (true, r)
            } else {
                (false, rest)
            };
            if let Some((remote, local)) = rest.split_once(';') {
                let mut rules = reverse_rules.lock().unwrap();
                if norebind && rules.iter().any(|r| r.remote == remote) {
                    return Some(PendingResponse::ReverseForwardFail(
                        "cannot rebind existing socket".to_string(),
                    ));
                }
                let resolved_remote = if remote == "tcp:0" {
                    format!("tcp:{}", ephemeral_port())
                } else {
                    remote.to_string()
                };
                rules.retain(|r| r.remote != resolved_remote);
                rules.push(ReverseRule {
                    remote: resolved_remote.clone(),
                    local: local.to_string(),
                });
                let port_to_return = if remote == "tcp:0" {
                    resolved_remote
                        .strip_prefix("tcp:")
                        .unwrap()
                        .parse::<u16>()
                        .ok()
                } else {
                    None
                };
                return Some(PendingResponse::ReverseForward(port_to_return));
            }
        }
        if service == "reconnect" {
            return Some(PendingResponse::Reconnect);
        }
        if service == "sync:" {
            return Some(PendingResponse::SyncService);
        }
        if let Some(rest) = service.strip_prefix("abb_exec:") {
            let args: Vec<&str> = rest.split('\0').collect();
            if let Some("package") = args.first().copied()
                && let Some(subcommand) = args.get(1)
            {
                return Some(PendingResponse::AbbExecPackage {
                    subcommand: subcommand.to_string(),
                });
            }
        }
        if let Some(rest) = service.strip_prefix("abb:") {
            let command = rest.split('\0').collect::<Vec<_>>().join(" ");
            return Some(PendingResponse::ShellV2(command));
        }
        if let Some(size_str) = service.strip_prefix("sideload-host:") {
            let mut parts = size_str.splitn(2, ':');
            if let Some(size) = parts.next()
                && let Some(block_size) = parts.next()
                && let Ok(size) = size.parse::<u64>()
                && let Ok(block_size) = block_size.parse::<u64>()
            {
                return Some(PendingResponse::SideloadHost {
                    size,
                    block_size,
                    next_block: 0,
                });
            }
        }
        if let Some(size_str) = service.strip_prefix("rescue-install:") {
            let mut parts = size_str.splitn(2, ':');
            if let Some(size) = parts.next()
                && let Some(block_size) = parts.next()
                && let Ok(size) = size.parse::<u64>()
                && let Ok(block_size) = block_size.parse::<u64>()
            {
                return Some(PendingResponse::SideloadHost {
                    size,
                    block_size,
                    next_block: 0,
                });
            }
        }
        if let Some(size_str) = service.strip_prefix("sideload:")
            && let Ok(expected_size) = size_str.parse::<u64>()
        {
            return Some(PendingResponse::SideloadService {
                expected_size,
                received: 0,
            });
        }
        if service.starts_with("restore:") || service == "restore" {
            return Some(PendingResponse::RestoreService);
        }
        if service.starts_with("backup:") || service == "backup" {
            return Some(PendingResponse::BackupService);
        }
        if let Some(response) = Self::classify_simple_service(service) {
            return Some(response);
        }
        None
    }

    fn parse_abb_exec_write_size(service: &str) -> u64 {
        let args: Vec<&str> = service
            .strip_prefix("abb_exec:")
            .unwrap_or("")
            .split('\0')
            .collect();
        for window in args.windows(2) {
            if window[0] == "-S" {
                return window[1].parse::<u64>().unwrap_or(0);
            }
        }
        0
    }

    fn fastdeploy_patch_complete(buffer: &[u8]) -> bool {
        if buffer.len() < 26 || &buffer[..10] != b"FASTDEPLOY" {
            return false;
        }
        let read_i64 = |offset: usize| {
            buffer
                .get(offset..offset + 8)
                .map(|bytes| i64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let Some(new_size) = read_i64(10).and_then(|value| u64::try_from(value).ok()) else {
            return false;
        };
        let Some(path_size) = read_i64(18).and_then(|value| usize::try_from(value).ok()) else {
            return false;
        };
        let Some(mut cursor) = 26_usize.checked_add(path_size) else {
            return false;
        };
        if cursor > buffer.len() {
            return false;
        }
        let mut output_size = 0_u64;
        while output_size < new_size {
            let Some(new_data_size) =
                read_i64(cursor).and_then(|value| usize::try_from(value).ok())
            else {
                return false;
            };
            let Some(next) = cursor
                .checked_add(8)
                .and_then(|value| value.checked_add(new_data_size))
            else {
                return false;
            };
            let Some(packet_end) = next.checked_add(16) else {
                return false;
            };
            if packet_end > buffer.len() {
                return false;
            }
            cursor = next;
            let Some(old_data_size) =
                read_i64(cursor + 8).and_then(|value| u64::try_from(value).ok())
            else {
                return false;
            };
            output_size = output_size
                .checked_add(new_data_size as u64)
                .and_then(|value| value.checked_add(old_data_size))
                .unwrap_or(u64::MAX);
            cursor = packet_end;
        }
        output_size == new_size
    }

    fn classify_simple_service(service: &str) -> Option<PendingResponse> {
        let payload = match service {
            "root:" | "unroot:" => b"OK\n".to_vec(),
            "usb:" => b"OK\n".to_vec(),
            "remount:" | "disable-verity:" | "enable-verity:" => b"OK\n".to_vec(),
            "reboot:" | "reboot:bootloader" | "reboot:fastboot" => b"OK\n".to_vec(),
            _ if service.starts_with("usb:") => b"OK\n".to_vec(),
            _ if service.starts_with("tcpip:") => {
                let port = service.strip_prefix("tcpip:").unwrap_or("");
                format!("restarting in TCP mode port: {port}\n").into_bytes()
            }
            _ if service.starts_with("exec:") => {
                let command = service.strip_prefix("exec:").unwrap_or("");
                Self::shell_output_and_exit(command).0
            }
            _ if service == "jdwp" => b"12345\n67890\n".to_vec(),
            _ if service == "track-jdwp" => b"11111\n22222\n".to_vec(),
            _ if service == "track-app" => track_app_sample_frame(),
            _ if service == "rescue-getprop:" || service.starts_with("rescue-getprop:") => {
                b"[ro.product.model]: [Fake]\n".to_vec()
            }
            _ if service.starts_with("rescue-wipe:") => b"DONEDONE".to_vec(),
            _ if service.starts_with("dev-raw:") => {
                let command = service.strip_prefix("dev-raw:").unwrap_or("");
                Self::shell_output_and_exit(command).0
            }
            _ => return None,
        };
        Some(PendingResponse::SimpleService(payload))
    }

    fn send_response(
        writer: &Arc<Mutex<std::net::TcpStream>>,
        device_id: u32,
        host_id: u32,
        response: &PendingResponse,
    ) {
        match response {
            PendingResponse::ShellV2(command) => {
                let (stdout, stderr, exit_code) = Self::shell_output_and_exit(command);
                let mut payload = Vec::new();
                Self::write_shell_v2_packet(&mut payload, 1, &stdout);
                Self::write_shell_v2_packet(&mut payload, 2, &stderr);
                Self::write_shell_v2_packet(&mut payload, 3, &[exit_code]);
                Self::write_wrte(writer, device_id, host_id, payload);
            }
            PendingResponse::ShellLegacy(command) => {
                const EXIT_MARKER: &str = "; echo \"\n$?: $?\"";
                let (stdout, _stderr, _exit_code) =
                    if let Some(prefix) = command.strip_suffix(EXIT_MARKER) {
                        let (out, err, code) = Self::shell_output_and_exit(prefix);
                        let mut out = out;
                        out.extend_from_slice(format!("\n$?: {code}").as_bytes());
                        (out, err, code)
                    } else {
                        Self::shell_output_and_exit(command)
                    };
                Self::write_wrte(writer, device_id, host_id, stdout);
            }
            PendingResponse::ReverseList(payload) => {
                Self::write_wrte(writer, device_id, host_id, payload.clone());
            }
            PendingResponse::ReverseKillforward => {
                Self::write_wrte(writer, device_id, host_id, b"OKAY".to_vec());
            }
            PendingResponse::ReverseForward(port) => {
                Self::write_wrte(writer, device_id, host_id, b"OKAY".to_vec());
                if let Some(port) = port {
                    let port_str = port.to_string();
                    let hex_len = format!("{:04x}", port_str.len());
                    let payload = format!("{hex_len}{port_str}").into_bytes();
                    Self::write_wrte(writer, device_id, host_id, payload);
                }
            }
            PendingResponse::ReverseForwardFail(reason) => {
                Self::write_wrte(writer, device_id, host_id, b"FAIL".to_vec());
                let hex_len = format!("{:04x}", reason.len());
                let payload = format!("{hex_len}{reason}").into_bytes();
                Self::write_wrte(writer, device_id, host_id, payload);
            }
            PendingResponse::Reconnect => {
                // 该服务不需要返回数据，只需在 open 成功后关闭 stream。
            }
            PendingResponse::SimpleService(payload) => {
                Self::write_wrte(writer, device_id, host_id, payload.clone());
            }
            PendingResponse::SyncService => {
                // sync 响应在 handle_sync_payload 中直接处理，不会走到这里。
            }
            PendingResponse::SideloadService { .. } => {
                // sideload 响应在 A_WRTE 累计数据后处理，不会走到这里。
            }
            PendingResponse::RestoreService => {
                // restore 响应在 A_WRTE 检测到末尾 1024 零块后处理，不会走到这里。
            }
            PendingResponse::BackupService => {
                // backup 响应在 A_OPEN 时直接发送并关闭，不会走到这里。
            }
            PendingResponse::SideloadHost { .. } => {
                // sideload-host 响应在 A_OPEN/A_WRTE 中按块请求协议处理，不会走到这里。
            }
            PendingResponse::AbbExecPackage { .. } | PendingResponse::AbbExecWrite { .. } => {
                // abb_exec 包管理响应在 A_OPEN/A_CLSE 中处理，不会走到这里。
            }
            PendingResponse::FastDeployApply { .. } => {
                // fastdeploy patch 在 A_WRTE 中累计到完整输出大小后关闭 stream。
            }
        }
    }

    fn write_clse(writer: &Arc<Mutex<std::net::TcpStream>>, device_id: u32, host_id: u32) {
        let mut guard = writer.lock().unwrap_or_else(|err| err.into_inner());
        AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
            .unwrap()
            .write_to(&mut *guard, protocol::A_VERSION)
            .unwrap();
    }

    fn write_wrte(
        writer: &Arc<Mutex<std::net::TcpStream>>,
        device_id: u32,
        host_id: u32,
        payload: Vec<u8>,
    ) {
        let mut guard = writer.lock().unwrap_or_else(|err| err.into_inner());
        AdbMessage::new(protocol::A_WRTE, device_id, host_id, payload)
            .unwrap()
            .write_to(&mut *guard, protocol::A_VERSION)
            .unwrap();
    }

    // sync v1 stub 常量与处理
    const ID_STAT: u32 = u32::from_le_bytes(*b"STAT");
    const ID_LIST: u32 = u32::from_le_bytes(*b"LIST");
    const ID_DENT: u32 = u32::from_le_bytes(*b"DENT");
    const ID_SEND: u32 = u32::from_le_bytes(*b"SEND");
    const ID_SEND_V2: u32 = u32::from_le_bytes(*b"SND2");
    const ID_RECV: u32 = u32::from_le_bytes(*b"RECV");
    const ID_RECV_V2: u32 = u32::from_le_bytes(*b"RCV2");
    const ID_DATA: u32 = u32::from_le_bytes(*b"DATA");
    const ID_DONE: u32 = u32::from_le_bytes(*b"DONE");
    const ID_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
    const ID_FAIL: u32 = u32::from_le_bytes(*b"FAIL");
    const ID_QUIT: u32 = u32::from_le_bytes(*b"QUIT");

    // sync v2 压缩与 dry-run flag
    const SYNC_FLAG_DRY_RUN: u32 = 0x8000_0000;
    const SYNC_FLAG_BROTLI: u32 = 1;
    const SYNC_FLAG_LZ4: u32 = 2;
    const SYNC_FLAG_ZSTD: u32 = 4;

    fn process_sync_buffer(
        writer: &Arc<Mutex<std::net::TcpStream>>,
        device_id: u32,
        host_id: u32,
        buffer: &[u8],
        fs: &FakeFs,
        sessions: &SyncSessions,
    ) -> usize {
        let mut cursor = Cursor::new(buffer);
        let mut consumed = 0usize;

        while cursor.position() as usize + 8 <= buffer.len() {
            let id = Self::read_u32_le(&mut cursor);
            let value = Self::read_u32_le(&mut cursor);

            // sync v2 的 SEND/RECV 都分两次传输：
            // SND2 第一次带路径，第二次 value 为 mode，后接 4 字节 flags；
            // RCV2 第一次带路径，第二次 value 为 flags，无额外 payload。
            let is_v2_setup = (id == Self::ID_SEND_V2 || id == Self::ID_RECV_V2)
                && sessions.lock().unwrap().contains_key(&host_id);

            let data_len = if is_v2_setup && id == Self::ID_SEND_V2 {
                4
            } else if id == Self::ID_QUIT || id == Self::ID_DONE || is_v2_setup {
                0
            } else {
                value as usize
            };
            if cursor.position() as usize + data_len > buffer.len() {
                return consumed;
            }
            let payload =
                &buffer[cursor.position() as usize..cursor.position() as usize + data_len];
            cursor.set_position((cursor.position() as usize + data_len) as u64);
            consumed = cursor.position() as usize;

            match id {
                Self::ID_STAT => {
                    let path = String::from_utf8_lossy(payload)
                        .trim_end_matches('/')
                        .to_string();
                    let mut response = Vec::new();
                    let guard = fs.lock().unwrap();
                    if let Some(file) = guard.get(&path) {
                        response.extend_from_slice(&Self::ID_STAT.to_le_bytes());
                        response.extend_from_slice(&file.mode.to_le_bytes());
                        response.extend_from_slice(&((file.content.len() as u32).to_le_bytes()));
                        response.extend_from_slice(&file.mtime.to_le_bytes());
                    } else {
                        response.extend_from_slice(&Self::ID_STAT.to_le_bytes());
                        response.extend_from_slice(&[0_u8; 12]);
                    }
                    drop(guard);
                    Self::write_wrte(writer, device_id, host_id, response);
                }
                Self::ID_LIST => {
                    let path = String::from_utf8_lossy(payload).to_string();
                    let mut response = Vec::new();
                    let guard = fs.lock().unwrap();
                    for (name, file) in guard.iter() {
                        let parent = std::path::Path::new(name)
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if parent != path {
                            continue;
                        }
                        let entry_name = std::path::Path::new(name)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if entry_name.is_empty() || entry_name == "." || entry_name == ".." {
                            continue;
                        }
                        response.extend_from_slice(&Self::ID_DENT.to_le_bytes());
                        response.extend_from_slice(&file.mode.to_le_bytes());
                        response.extend_from_slice(&((file.content.len() as u32).to_le_bytes()));
                        response.extend_from_slice(&file.mtime.to_le_bytes());
                        response.extend_from_slice(&((entry_name.len() as u32).to_le_bytes()));
                        response.extend_from_slice(entry_name.as_bytes());
                    }
                    drop(guard);
                    response.extend_from_slice(&Self::ID_DONE.to_le_bytes());
                    response.extend_from_slice(&[0_u8; 16]);
                    Self::write_wrte(writer, device_id, host_id, response);
                }
                Self::ID_RECV => {
                    Self::send_file_data(writer, device_id, host_id, fs, payload, 0);
                }
                Self::ID_RECV_V2 => {
                    if is_v2_setup {
                        let flags = value;
                        if let Some(SyncSession::Recv { path, .. }) =
                            sessions.lock().unwrap().remove(&host_id)
                        {
                            Self::send_file_data(
                                writer,
                                device_id,
                                host_id,
                                fs,
                                path.as_bytes(),
                                flags,
                            );
                        }
                    } else {
                        let path = String::from_utf8_lossy(payload).to_string();
                        sessions
                            .lock()
                            .unwrap()
                            .insert(host_id, SyncSession::Recv { path });
                    }
                }
                Self::ID_SEND | Self::ID_SEND_V2 => {
                    if is_v2_setup {
                        let mode = value;
                        let flags = u32::from_le_bytes(payload.try_into().unwrap());
                        if let Some(SyncSession::Send {
                            mode: m, flags: f, ..
                        }) = sessions.lock().unwrap().get_mut(&host_id)
                        {
                            *m = mode;
                            *f = flags;
                        }
                    } else {
                        let spec = String::from_utf8_lossy(payload).to_string();
                        let (path, mode_text) = spec.split_once(',').unwrap_or((&spec, "0"));
                        let mode = if id == Self::ID_SEND_V2 {
                            0 // 由第二次 SND2 setup 覆盖
                        } else {
                            mode_text.parse().unwrap_or(0o100644)
                        };
                        Self::ensure_parent_dirs(fs, path);
                        sessions.lock().unwrap().insert(
                            host_id,
                            SyncSession::Send {
                                path: path.to_string(),
                                mode,
                                flags: 0,
                                buffer: Vec::new(),
                            },
                        );
                    }
                }
                Self::ID_DATA => {
                    if let Some(SyncSession::Send { buffer, .. }) =
                        sessions.lock().unwrap().get_mut(&host_id)
                    {
                        buffer.extend_from_slice(payload);
                    }
                }
                Self::ID_DONE => {
                    let mut guard = sessions.lock().unwrap();
                    if let Some(SyncSession::Send {
                        path,
                        mode,
                        flags,
                        buffer,
                    }) = guard.remove(&host_id)
                    {
                        drop(guard);
                        if flags & Self::SYNC_FLAG_DRY_RUN == 0 {
                            let content = if flags & Self::SYNC_FLAG_ZSTD != 0 {
                                zstd::decode_all(buffer.as_slice()).unwrap_or(buffer)
                            } else if flags & Self::SYNC_FLAG_LZ4 != 0 {
                                let mut decoder =
                                    lz4_flex::frame::FrameDecoder::new(buffer.as_slice());
                                let mut out = Vec::new();
                                if decoder.read_to_end(&mut out).is_ok() {
                                    out
                                } else {
                                    buffer
                                }
                            } else if flags & Self::SYNC_FLAG_BROTLI != 0 {
                                let mut decoder =
                                    brotli::Decompressor::new(buffer.as_slice(), 4096);
                                let mut out = Vec::new();
                                if decoder.read_to_end(&mut out).is_ok() {
                                    out
                                } else {
                                    buffer
                                }
                            } else {
                                buffer
                            };
                            fs.lock().unwrap().insert(
                                path,
                                FakeFile {
                                    mode,
                                    mtime: value,
                                    content,
                                },
                            );
                        }
                        let mut response = Vec::new();
                        response.extend_from_slice(&Self::ID_OKAY.to_le_bytes());
                        response.extend_from_slice(&[0_u8; 4]);
                        Self::write_wrte(writer, device_id, host_id, response);
                    }
                }
                Self::ID_QUIT => {}
                _ => {}
            }
        }

        consumed
    }

    fn send_file_data(
        writer: &Arc<Mutex<std::net::TcpStream>>,
        device_id: u32,
        host_id: u32,
        fs: &FakeFs,
        path_bytes: &[u8],
        flags: u32,
    ) {
        let path = String::from_utf8_lossy(path_bytes).to_string();
        let guard = fs.lock().unwrap();
        if let Some(file) = guard.get(&path) {
            let raw = file.content.clone();
            drop(guard);
            let content = if flags & Self::SYNC_FLAG_ZSTD != 0 {
                zstd::encode_all(raw.as_slice(), 1).unwrap_or(raw)
            } else if flags & Self::SYNC_FLAG_LZ4 != 0 {
                let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
                if encoder.write_all(raw.as_slice()).is_ok() {
                    encoder.finish().unwrap_or(raw)
                } else {
                    raw
                }
            } else if flags & Self::SYNC_FLAG_BROTLI != 0 {
                let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 22);
                if encoder.write_all(raw.as_slice()).is_ok() {
                    let _ = encoder.flush();
                    encoder.into_inner()
                } else {
                    raw
                }
            } else {
                raw
            };
            let mut response = Vec::new();
            response.extend_from_slice(&Self::ID_DATA.to_le_bytes());
            response.extend_from_slice(&((content.len() as u32).to_le_bytes()));
            response.extend_from_slice(&content);
            response.extend_from_slice(&Self::ID_DONE.to_le_bytes());
            response.extend_from_slice(&[0_u8; 4]);
            Self::write_wrte(writer, device_id, host_id, response);
        } else {
            drop(guard);
            Self::write_sync_fail(
                writer,
                device_id,
                host_id,
                &format!("No such file or directory: {path}"),
            );
        }
    }

    fn ensure_parent_dirs(fs: &FakeFs, path: &str) {
        let mut guard = fs.lock().unwrap();
        let p = std::path::Path::new(path);
        for ancestor in p.ancestors().skip(1) {
            let key = ancestor.to_string_lossy().to_string();
            if key.is_empty() {
                continue;
            }
            guard.entry(key).or_insert_with(|| FakeFile {
                mode: 0o040755,
                mtime: 1_700_000_000,
                content: Vec::new(),
            });
        }
    }

    fn write_sync_fail(
        writer: &Arc<Mutex<std::net::TcpStream>>,
        device_id: u32,
        host_id: u32,
        reason: &str,
    ) {
        let mut response = Vec::new();
        response.extend_from_slice(&Self::ID_FAIL.to_le_bytes());
        response.extend_from_slice(&((reason.len() as u32).to_le_bytes()));
        response.extend_from_slice(reason.as_bytes());
        Self::write_wrte(writer, device_id, host_id, response);
    }

    fn read_u32_le(reader: &mut impl Read) -> u32 {
        let mut buf = [0_u8; 4];
        let _ = reader.read_exact(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn shell_output_and_exit(command: &str) -> (Vec<u8>, Vec<u8>, u8) {
        // CLI 会对参数做单引号 shell quote，匹配前先去掉以便 stub 识别子命令。
        let normalized = command.replace('\'', "");

        // 支持 `exit [CODE]` 形式的命令，用于验证 exit code 传播。
        if normalized == "exit" || normalized.starts_with("exit ") {
            let code = normalized
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            return (Vec::new(), Vec::new(), code);
        }

        // 支持把特定内容写到 stderr，用于验证 shell v2 stdout/stderr 分离。
        if let Some(args) = normalized.strip_prefix("echo-stderr ") {
            return (Vec::new(), format!("{args}\n").into_bytes(), 0);
        }

        // 同时输出 stdout 和 stderr，用于验证两条通道互不混淆。
        if let Some(args) = normalized.strip_prefix("echo-mixed ") {
            return (
                format!("{args}-out\n").into_bytes(),
                format!("{args}-err\n").into_bytes(),
                0,
            );
        }

        if normalized.starts_with("/data/local/tmp/deployagent dump 3 ")
            && normalized.contains("com.example.missingpkg")
        {
            return (Vec::new(), Vec::new(), 3);
        }
        if normalized.starts_with("/data/local/tmp/deployagent dump 3 ")
            && normalized.contains("com.example.oldagentxx")
            && FASTDEPLOY_OLD_AGENT_DUMPS.fetch_add(1, Ordering::SeqCst) == 0
        {
            return (b"0x00000002\n".to_vec(), Vec::new(), 4);
        }

        let stdout = if let Some(args) = normalized.strip_prefix("echo ") {
            format!("{args}\n").into_bytes()
        } else if normalized == "id" {
            b"uid=0(root) gid=0(root)\n".to_vec()
        } else if normalized == "getprop ro.build.version.sdk" {
            b"35\n".to_vec()
        } else if normalized.starts_with("/data/local/tmp/deployagent dump 3 ") {
            let mut dump = Vec::new();
            write_string_field(&mut dump, 1, "com.example.helloworld");
            write_string_field(&mut dump, 4, "/data/app/com.example.helloworld/base.apk");
            dump
        } else if normalized == "chmod 777 /data/local/tmp/deployagent" {
            Vec::new()
        } else if normalized.contains("logcat") {
            b"D/fake( 123): fake-log message\n".to_vec()
        } else if normalized.starts_with("pm install-create") {
            b"[1]\n".to_vec()
        } else if normalized.starts_with("pm install-write")
            || normalized.starts_with("pm install-commit")
            || normalized.starts_with("pm install-abandon")
            || normalized.starts_with("pm install")
            || normalized.starts_with("pm uninstall")
            || normalized.starts_with("cmd package uninstall")
            || normalized.starts_with("cmd package install")
        {
            b"Success\n".to_vec()
        } else if normalized.starts_with("bugreportz -v") {
            b"1.2\n".to_vec()
        } else if normalized.starts_with("bugreportz -s") {
            b"fake-streamed-bugreport\n".to_vec()
        } else if normalized.starts_with("bugreportz -p") || normalized == "bugreportz" {
            b"OK:/data/local/tmp/bugreport.zip\n".to_vec()
        } else if normalized.starts_with("package list packages") {
            b"package:com.example.fake\n".to_vec()
        } else {
            Vec::new()
        };
        (stdout, Vec::new(), 0)
    }

    fn write_shell_v2_packet(buf: &mut Vec<u8>, packet_id: u8, data: &[u8]) {
        buf.push(packet_id);
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }

    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

struct AdbServer {
    child: Child,
    port: u16,
    #[allow(dead_code)]
    android_home: tempfile::TempDir,
    stderr_path: std::path::PathBuf,
    #[allow(dead_code)]
    _concurrency_permit: ConcurrencyPermit,
}

impl AdbServer {
    fn start() -> Self {
        let port = ephemeral_port();
        Self::start_with_endpoint_arg("-P", &port.to_string(), port)
    }

    fn start_with_ipv6_loopback() -> Self {
        let port = ephemeral_port();
        Self::start_with_endpoint_arg("-L", &format!("tcp:[::1]:{port}"), port)
    }

    fn start_with_endpoint_arg(arg: &str, value: &str, port: u16) -> Self {
        let _concurrency_permit = integration_limiter().acquire();
        let android_home = tempfile::tempdir().unwrap();
        let stderr_path = android_home.path().join("server.stderr");

        // 预生成 adbkey，避免 server 在并发连接时首次生成密钥出现竞态。
        let android_dir = android_home.path().join(".android");
        std::fs::create_dir_all(&android_dir).expect("failed to create .android temp dir");
        let key_path = android_dir.join("adbkey");
        auth::generate_user_key(&key_path).expect("failed to generate temp adbkey");

        let _stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&stderr_path)
            .expect("failed to create server stderr file");
        let child = spawn_adb_with_retry(
            Command::new(adb_bin())
                .arg(arg)
                .arg(value)
                .arg("server")
                .arg("nodaemon")
                .env("ANDROID_SDK_HOME", android_home.path())
                // 集成测试使用显式 fake transport，不应让每个用例在 ACK 前枚举真实 USB
                // 或扫描 emulator 端口；生产默认路径仍由独立启动测试覆盖。
                .env("ADB_USB", "0")
                .env("ADB_EMU", "0")
                .stdout(Stdio::null())
                .stderr(Stdio::from(_stderr_file)),
            "adb server nodaemon",
        );

        let server = Self {
            child,
            port,
            android_home,
            stderr_path,
            _concurrency_permit,
        };
        server.wait_for_ready();
        thread::sleep(Duration::from_millis(200));
        server
    }

    fn stderr_output(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn wait_for_ready(&self) {
        let endpoint = ServerEndpoint::for_port(self.port);
        for attempt in 0..100 {
            if matches!(
                client::server_version(&endpoint),
                Ok(version) if version == protocol::ADB_SERVER_VERSION
            ) {
                return;
            }
            if attempt == 99 {
                panic!(
                    "adb server did not become ready in time: {}",
                    self.stderr_output()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_env(args, &[])
    }

    fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &std::path::Path)]) -> Output {
        for attempt in 0..10 {
            let mut cmd = Command::new(adb_bin());
            cmd.arg("-P")
                .arg(self.port.to_string())
                .args(args)
                .env("ANDROID_SDK_HOME", self.android_home.path());
            for (key, value) in extra_env {
                cmd.env(key, value);
            }
            let output = output_adb_with_retry(&mut cmd, &format!("adb {}", args.join(" ")));
            if output.status.success() || !is_windows_access_denied_output(&output) || attempt == 9
            {
                return output;
            }
            eprintln!(
                "adb {} failed with access denied, retrying...",
                args.join(" ")
            );
            thread::sleep(Duration::from_millis(500));
        }
        unreachable!()
    }

    fn stdout(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(args).stdout).into_owned()
    }
}

impl Drop for AdbServer {
    fn drop(&mut self) {
        let _ = self.run(&["kill-server"]);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn version_prints_android_debug_bridge_version() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["version"]);
    assert!(
        stdout.starts_with("Android Debug Bridge version"),
        "unexpected version output: {stdout:?}"
    );
}

#[test]
fn version_flag_prints_version() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["--version"]);
    assert!(
        stdout.starts_with("Android Debug Bridge version"),
        "unexpected --version output: {stdout:?}"
    );
}

#[test]
fn help_flag_prints_help() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["--help"]);
    assert!(
        stdout.contains("Android Debug Bridge"),
        "unexpected --help output: {stdout:?}"
    );
    assert!(
        stdout.contains("devices [-l]"),
        "missing devices section: {stdout:?}"
    );
    assert!(
        stdout.contains("version                  show version num"),
        "missing version entry: {stdout:?}"
    );
}

#[test]
fn help_lists_core_commands() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["help"]);
    assert!(stdout.contains("Android Debug Bridge"));
    assert!(stdout.contains("devices [-l]"));
    assert!(stdout.contains("version                  show version num"));
    assert!(stdout.contains("environment variables:"));
}

#[test]
fn devices_shows_empty_list_header() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["devices"]);
    assert_eq!(stdout, "List of devices attached\n\n");
}

#[test]
fn devices_long_flag_rejected_with_extra_args() {
    let server = AdbServer::start();
    let output = server.run(&["devices", "-l", "extra"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(stderr.trim(), format!("{prefix}adb devices [-l]"));
}

#[test]
fn unknown_command_prints_executable_prefix_and_exits_one() {
    let server = AdbServer::start();
    let output = server.run(&["not-a-command"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert!(stderr.starts_with(prefix), "unexpected stderr: {stderr:?}");
    assert!(stderr.contains("unknown command not-a-command"));
}

#[test]
fn mdns_validation_preserves_aosp_server_start_order() {
    let _permit = integration_limiter().acquire();
    let android_home = tempfile::tempdir().unwrap();

    let missing_port = ephemeral_port();
    let missing = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(missing_port.to_string())
            .arg("mdns")
            .env("ANDROID_SDK_HOME", android_home.path())
            .env("ADB_EMU", "0")
            .env("ADB_USB", "0")
            .env("ADB_MDNS", "0"),
        "adb mdns missing argument",
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("mdns requires an argument"));
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", missing_port)).is_err(),
        "裸 mdns 不应启动 server"
    );

    let unknown_port = ephemeral_port();
    let unknown = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(unknown_port.to_string())
            .args(["mdns", "bad"])
            .env("ANDROID_SDK_HOME", android_home.path())
            .env("ADB_EMU", "0")
            .env("ADB_USB", "0")
            .env("ADB_MDNS", "0"),
        "adb mdns unknown command",
    );
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown mdns command [bad]"));

    let endpoint = ServerEndpoint::for_port(unknown_port);
    assert_eq!(
        client::server_version(&endpoint).unwrap(),
        protocol::ADB_SERVER_VERSION,
        "带子命令的 mdns 应先启动并检查 server"
    );
    let _ = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(unknown_port.to_string())
            .arg("kill-server")
            .env("ANDROID_SDK_HOME", android_home.path()),
        "adb kill-server after mdns order test",
    );
}

#[test]
fn start_server_auto_launches_with_ack_and_can_be_stopped() {
    let _permit = integration_limiter().acquire();
    let port = ephemeral_port();
    let android_home = tempfile::tempdir().unwrap();
    let port_text = port.to_string();

    let output = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(&port_text)
            .arg("start-server")
            .env("ANDROID_SDK_HOME", android_home.path())
            .env("ADB_EMU", "0")
            .env("ADB_USB", "0")
            .env("ADB_MDNS", "0"),
        "adb start-server",
    );
    assert!(output.status.success(), "start-server failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("* daemon started successfully"),
        "missing startup confirmation: {stderr:?}"
    );

    let devices = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(&port_text)
            .arg("devices")
            .env("ANDROID_SDK_HOME", android_home.path()),
        "adb devices after start-server",
    );
    assert!(devices.status.success(), "devices failed: {devices:?}");

    let kill = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(&port_text)
            .arg("kill-server")
            .env("ANDROID_SDK_HOME", android_home.path()),
        "adb kill-server after start-server",
    );
    assert!(kill.status.success(), "kill-server failed: {kill:?}");

    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("auto-started adb server did not stop listening");
}

#[test]
fn start_server_relays_child_bind_failure_diagnostics() {
    let _permit = integration_limiter().acquire();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept_listener = listener.try_clone().unwrap();
    let accept = thread::spawn(move || {
        let _ = accept_listener.accept();
    });
    let android_home = tempfile::tempdir().unwrap();

    let output = output_adb_with_retry(
        Command::new(adb_bin())
            .arg("-P")
            .arg(port.to_string())
            .arg("start-server")
            .env("ANDROID_SDK_HOME", android_home.path())
            .env("ADB_EMU", "0")
            .env("ADB_USB", "0")
            .env("ADB_MDNS", "0"),
        "adb start-server bind failure",
    );
    accept.join().unwrap();

    assert!(
        !output.status.success(),
        "start-server unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    if cfg!(windows) {
        assert!(
            stderr.contains("adb: ") && stderr.contains("adb.exe: "),
            "child bind error was not relayed before the parent ACK error: {stderr:?}"
        );
    } else {
        assert!(
            stderr.matches("adb: ").count() >= 2,
            "child bind error was not relayed before the parent ACK error: {stderr:?}"
        );
    }
}

#[test]
fn kill_server_stops_listening() {
    let mut server = AdbServer::start();
    let output = server.run(&["kill-server"]);
    assert!(output.status.success());

    // After kill-server, the server process should exit.
    for _attempt in 0..30 {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("adb server did not exit after kill-server");
}

#[test]
fn kill_server_reaches_ipv6_loopback_server() {
    // `-L tcp:[::1]:PORT` 在 Windows 下按 AOSP 当前行为回退到 IPv4 loopback，
    // 在 Unix 下保持真正的 IPv6；无论哪种情况，默认的 127.0.0.1 客户端都应能连上并 kill。
    let mut server = AdbServer::start_with_ipv6_loopback();
    let output = server.run(&["devices"]);
    assert!(output.status.success(), "devices failed: {:?}", output);

    let output = server.run(&["kill-server"]);
    assert!(output.status.success());

    for _attempt in 0..30 {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("adb server did not exit after kill-server");
}

#[test]
fn emulator_service_registers_device_with_console_serial() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let adb_port = device
        .address()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse::<u16>()
        .unwrap();
    let console_port = adb_port.saturating_sub(1);
    let serial = format!("emulator-{console_port}");

    // 向 server 发送 `host:emulator:<adb_port>` 显式注册模拟器。
    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).unwrap();
    let request = format!("host:emulator:{adb_port}");
    stream
        .write_all(&format!("{:04x}{}", request.len(), request).into_bytes())
        .unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(
        &response, b"OKAY",
        "host:emulator should return OKAY without body"
    );

    // 等待注册完成。
    thread::sleep(Duration::from_millis(300));

    let output = server.run(&["-s", &serial, "wait-for-device"]);
    assert!(
        output.status.success(),
        "wait-for-device failed: {:?}",
        output
    );

    let output = server.run(&["-s", &serial, "get-state"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "device", "unexpected state: {stdout:?}");
}

#[test]
fn connect_registers_device_and_disconnect_removes_it() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("connected to {target}")),
        "unexpected connect output: {stdout:?}"
    );

    let devices = server.stdout(&["devices"]);
    assert!(devices.contains(&target), "device not listed: {devices:?}");

    let output = server.run(&["disconnect", &target]);
    assert!(output.status.success(), "disconnect failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("disconnected {target}")),
        "unexpected disconnect output: {stdout:?}"
    );

    let devices = server.stdout(&["devices"]);
    assert!(
        !devices.contains(&target),
        "device still listed: {devices:?}"
    );
}

#[test]
fn disconnect_unknown_target_reports_no_such_device() {
    let server = AdbServer::start();
    let output = server.run(&["disconnect", "192.0.2.1:5555"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert!(
        stderr.contains(&format!("{prefix}no such device '192.0.2.1:5555'")),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn device_service_failure_uses_aosp_error_prefix() {
    let server = AdbServer::start();
    let serial = "emulator-53868";
    let output = server.run(&["-s", serial, "get-state"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.trim(), format!("error: device '{serial}' not found"));
}

#[test]
fn connect_rejects_multiple_arguments() {
    let server = AdbServer::start();
    let output = server.run(&["connect", "127.0.0.1:5555", "extra"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}usage: adb connect HOST[:PORT]")
    );
}

#[test]
fn server_status_reports_backend_and_version() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["server-status"]);
    assert!(
        stdout.contains("usb_backend:"),
        "missing usb_backend: {stdout:?}"
    );
    assert!(
        stdout.contains("mdns_backend:"),
        "missing mdns_backend: {stdout:?}"
    );
    assert!(stdout.contains("version:"), "missing version: {stdout:?}");
    assert!(stdout.contains("build:"), "missing build: {stdout:?}");
    assert!(stdout.contains("os:"), "missing os: {stdout:?}");
    assert!(
        stdout.contains("keystore_path:"),
        "missing keystore_path: {stdout:?}"
    );
    assert!(
        stdout.contains("known_hosts_path:"),
        "missing known_hosts_path: {stdout:?}"
    );
    assert!(
        stdout.contains(".android"),
        "keystore/known_hosts path should point under .android: {stdout:?}"
    );
}

#[test]
fn host_features_lists_supported_features() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["host-features"]);
    assert!(stdout.contains("shell_v2"), "missing shell_v2: {stdout:?}");
    assert!(
        stdout.contains("push_sync"),
        "missing push_sync: {stdout:?}"
    );
    assert!(
        stdout.contains("server_status"),
        "missing server_status: {stdout:?}"
    );
}

#[test]
fn device_features_lists_supported_features() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "features"]);
    assert!(stdout.contains("shell_v2"), "missing shell_v2: {stdout:?}");
    assert!(
        stdout.contains("sendrecv_v2"),
        "missing sendrecv_v2: {stdout:?}"
    );
    assert!(stdout.contains("cmd"), "missing cmd: {stdout:?}");
    // 主机不支持的特性不会被打印出来。
    assert!(
        !stdout.contains("unknown_feature"),
        "should not list unsupported features: {stdout:?}"
    );
}

#[test]
fn forward_lifecycle_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    // 空列表。
    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert_eq!(list.trim(), "");

    // 建立 forward 规则；显式指定设备，避免本机存在 USB 设备时目标歧义。
    let output = server.run(&["-s", &target, "forward", "tcp:0", "tcp:5555"]);
    assert!(output.status.success(), "forward failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a resolved port");

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains(&format!("{target} tcp:{local_port} tcp:5555")),
        "unexpected forward list: {list:?}"
    );

    // 本地端口确实在监听。
    let local_addr = format!("127.0.0.1:{local_port}");
    let conn = std::net::TcpStream::connect(&local_addr);
    assert!(
        conn.is_ok(),
        "forward listener not reachable at {local_addr}"
    );

    // --no-rebind 对已有 local 返回错误。
    let output = server.run(&[
        "-s",
        &target,
        "forward",
        "--no-rebind",
        &format!("tcp:{local_port}"),
        "tcp:6666",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert!(
        stderr.contains(&format!("{prefix}cannot rebind existing socket")),
        "unexpected stderr: {stderr:?}"
    );

    // --remove 移除规则。
    let output = server.run(&[
        "-s",
        &target,
        "forward",
        "--remove",
        &format!("tcp:{local_port}"),
    ]);
    assert!(
        output.status.success(),
        "forward --remove failed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert_eq!(list.trim(), "");
}

#[test]
fn forward_invalid_source_port_reports_usage() {
    let server = AdbServer::start();
    let output = server.run(&["forward", "tcp:-1", "tcp:5555"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}Invalid source port: '-1'"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn forward_invalid_destination_port_reports_usage() {
    let server = AdbServer::start();
    let output = server.run(&["forward", "tcp:5555", "tcp:0"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}Invalid destination port: '0'"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn forward_dev_raw_unsupported_without_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "tcp:0", "dev-raw:echo hi"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}dev-raw is not supported by the device"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn forward_remove_all_clears_rules() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "tcp:0", "tcp:5555"]);
    assert!(
        output.status.success(),
        "first forward failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a port");

    let output = server.run(&["-s", &target, "forward", "tcp:0", "tcp:5556"]);
    assert!(
        output.status.success(),
        "second forward failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let second_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a port");

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains(&format!("tcp:{first_port} tcp:5555")),
        "missing first rule: {list:?}"
    );
    assert!(
        list.contains(&format!("tcp:{second_port} tcp:5556")),
        "missing second rule: {list:?}"
    );

    let output = server.run(&["-s", &target, "forward", "--remove-all"]);
    assert!(
        output.status.success(),
        "forward --remove-all failed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert_eq!(list.trim(), "");
}

#[test]
fn forward_rebind_allows_rebinding_existing_local() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "tcp:0", "tcp:5555"]);
    assert!(
        output.status.success(),
        "first forward failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a port");

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains(&format!("tcp:{local_port} tcp:5555")),
        "missing original rule: {list:?}"
    );

    let output = server.run(&[
        "-s",
        &target,
        "forward",
        &format!("tcp:{local_port}"),
        "tcp:6666",
    ]);
    assert!(
        output.status.success(),
        "forward rebind should succeed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains(&format!("tcp:{local_port} tcp:6666")),
        "missing rebound rule: {list:?}"
    );
    assert!(
        !list.contains(&format!("tcp:{local_port} tcp:5555")),
        "old rule should have been replaced: {list:?}"
    );
}

#[test]
fn forward_no_rebind_with_fresh_local_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "--no-rebind", "tcp:0", "tcp:5555"]);
    assert!(
        output.status.success(),
        "forward --no-rebind failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a port");
    assert!(local_port > 0);

    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains(&format!("tcp:{local_port} tcp:5555")),
        "missing rule: {list:?}"
    );
}

#[test]
fn forward_remove_missing_local_reports_error() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "tcp:0", "tcp:5555"]);
    assert!(output.status.success(), "forward failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "--remove", "tcp:1"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listener 'tcp:1' not found"),
        "unexpected stderr: {stderr:?}"
    );

    // 已有的规则不应被误删。
    let list = server.stdout(&["-s", &target, "forward", "--list"]);
    assert!(
        list.contains("tcp:5555"),
        "existing rule should remain: {list:?}"
    );
}

#[test]
fn forward_tcp_data_bridges_to_device_service() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "forward", "tcp:0", "shell:echo hello"]);
    assert!(output.status.success(), "forward failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("forward did not return a port");

    let local_addr = format!("127.0.0.1:{local_port}");
    let mut stream =
        std::net::TcpStream::connect(&local_addr).expect("forward listener not reachable");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut buf).expect("failed to read forwarded data");
    let response = String::from_utf8_lossy(&buf);
    assert!(
        response.contains("hello"),
        "unexpected forwarded response: {response:?}"
    );
}

#[test]
fn reverse_lifecycle_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    // 空列表。
    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert_eq!(list.trim(), "");

    // 建立 reverse 规则；fake 设备会返回一个 resolved port。
    let output = server.run(&["-s", &target, "reverse", "tcp:0", "tcp:5555"]);
    assert!(output.status.success(), "reverse failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("reverse did not return a resolved port");
    assert!(local_port > 0);

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert!(
        list.contains(&format!("host tcp:{local_port} tcp:5555")),
        "unexpected reverse list: {list:?}"
    );

    // --remove-all 成功。
    let output = server.run(&["-s", &target, "reverse", "--remove-all"]);
    assert!(
        output.status.success(),
        "reverse --remove-all failed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert_eq!(list.trim(), "");
}

#[test]
fn reverse_no_rebind_rejects_existing_remote() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "tcp:0", "tcp:5555"]);
    assert!(output.status.success(), "reverse failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("reverse did not return a port");

    let output = server.run(&[
        "-s",
        &target,
        "reverse",
        "--no-rebind",
        &format!("tcp:{local_port}"),
        "tcp:6666",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert!(
        stderr.contains(&format!("{prefix}cannot rebind existing socket")),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn reverse_rebind_allows_rebinding_existing_remote() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "tcp:0", "tcp:5555"]);
    assert!(output.status.success(), "reverse failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let local_port: u16 = stdout
        .trim()
        .parse()
        .expect("reverse did not return a port");

    let output = server.run(&[
        "-s",
        &target,
        "reverse",
        &format!("tcp:{local_port}"),
        "tcp:6666",
    ]);
    assert!(
        output.status.success(),
        "reverse rebind should succeed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert!(
        list.contains(&format!("host tcp:{local_port} tcp:6666")),
        "missing rebound rule: {list:?}"
    );
    assert!(
        !list.contains(&format!("host tcp:{local_port} tcp:5555")),
        "old rule should have been replaced: {list:?}"
    );
}

#[test]
fn reverse_remove_missing_remote_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "tcp:8081", "tcp:5555"]);
    assert!(output.status.success(), "reverse failed: {:?}", output);

    // 不存在的 remote 移除在 AOSP 上返回成功，且不误删已有规则。
    let output = server.run(&["-s", &target, "reverse", "--remove", "tcp:1"]);
    assert!(
        output.status.success(),
        "reverse --remove missing should succeed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert!(
        list.contains("host tcp:8081 tcp:5555"),
        "existing rule should remain: {list:?}"
    );
}

#[test]
fn reverse_remove_all_clears_rules() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "tcp:0", "tcp:5555"]);
    assert!(
        output.status.success(),
        "first reverse failed: {:?}",
        output
    );
    let first_port: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("reverse did not return a port");

    let output = server.run(&["-s", &target, "reverse", "tcp:0", "tcp:5556"]);
    assert!(
        output.status.success(),
        "second reverse failed: {:?}",
        output
    );
    let second_port: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("reverse did not return a port");

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert!(
        list.contains(&format!("host tcp:{first_port} tcp:5555")),
        "missing first rule: {list:?}"
    );
    assert!(
        list.contains(&format!("host tcp:{second_port} tcp:5556")),
        "missing second rule: {list:?}"
    );

    let output = server.run(&["-s", &target, "reverse", "--remove-all"]);
    assert!(
        output.status.success(),
        "reverse --remove-all failed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert_eq!(list.trim(), "");
}

#[test]
fn reverse_dev_raw_unsupported_without_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "dev-raw:/dev/ttyS0", "tcp:5555"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}dev-raw is not supported by the device"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn reverse_dev_raw_succeeds_with_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,devraw");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reverse", "dev-raw:/dev/ttyS0", "tcp:5555"]);
    assert!(
        output.status.success(),
        "reverse dev-raw failed: {:?}",
        output
    );

    let list = server.stdout(&["-s", &target, "reverse", "--list"]);
    assert!(
        list.contains("dev-raw:/dev/ttyS0 tcp:5555"),
        "missing reverse dev-raw rule: {list:?}"
    );
}

#[test]
fn devices_long_listing_shows_product_model_device_and_transport_id() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["devices", "-l"]);
    assert!(
        stdout.starts_with("List of devices attached\n"),
        "unexpected devices header: {stdout:?}"
    );
    assert!(
        stdout.contains(&format!(
            "{target:<22} device product:adb-rust-test model:Fake device:fake-device"
        )),
        "missing long fields: {stdout:?}"
    );
    assert!(
        stdout.contains("transport_id:"),
        "missing transport_id: {stdout:?}"
    );
}

fn read_track_devices_chunk(stdout: &mut std::process::ChildStdout) -> String {
    use std::io::Read;

    let mut len_buf = [0_u8; 4];
    stdout
        .read_exact(&mut len_buf)
        .expect("failed to read track-devices length");
    let len = usize::from_str_radix(std::str::from_utf8(&len_buf).expect("non-UTF-8 length"), 16)
        .expect("invalid hex length");
    let mut payload = vec![0_u8; len];
    if len > 0 {
        stdout
            .read_exact(&mut payload)
            .expect("failed to read track-devices payload");
    }
    String::from_utf8(payload).expect("non-UTF-8 track-devices payload")
}

#[test]
fn track_devices_initial_snapshot_is_empty() {
    let server = AdbServer::start();

    let mut child = Command::new(adb_bin())
        .arg("-P")
        .arg(server.port.to_string())
        .arg("track-devices")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn track-devices");
    let mut stdout = child.stdout.take().expect("missing stdout");
    let chunk = read_track_devices_chunk(&mut stdout);
    assert_eq!(chunk, "");

    child.kill().expect("failed to kill track-devices");
    let _ = child.wait();
}

#[test]
fn track_devices_reports_connected_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let mut child = Command::new(adb_bin())
        .arg("-P")
        .arg(server.port.to_string())
        .arg("track-devices")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn track-devices");
    let mut stdout = child.stdout.take().expect("missing stdout");

    // 初始空快照。
    let chunk = read_track_devices_chunk(&mut stdout);
    assert_eq!(chunk, "");

    // 连接设备后应收到更新。
    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let mut snapshots = Vec::new();
    for _ in 0..2 {
        let chunk = read_track_devices_chunk(&mut stdout);
        let online = chunk.contains(&format!("{target}\tdevice\n"));
        snapshots.push(chunk);
        if online {
            break;
        }
    }
    assert!(
        snapshots
            .iter()
            .any(|chunk| chunk.contains(&format!("{target}\tdevice\n"))),
        "missing online state: {snapshots:?}"
    );

    child.kill().expect("failed to kill track-devices");
    let _ = child.wait();
}

#[test]
fn track_devices_long_reports_product_and_transport_id() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let mut child = Command::new(adb_bin())
        .arg("-P")
        .arg(server.port.to_string())
        .arg("track-devices")
        .arg("-l")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn track-devices -l");
    let mut stdout = child.stdout.take().expect("missing stdout");

    let chunk = read_track_devices_chunk(&mut stdout);
    assert!(
        chunk.contains(&format!(
            "{target:<22} device product:adb-rust-test model:Fake device:fake-device"
        )),
        "missing long fields: {chunk:?}"
    );
    assert!(
        chunk.contains("transport_id:"),
        "missing transport_id: {chunk:?}"
    );

    child.kill().expect("failed to kill track-devices -l");
    let _ = child.wait();
}

#[test]
fn get_state_serialno_devpath_and_transport_id_with_selector() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    assert_eq!(
        server.stdout(&["-s", &target, "get-state"]).trim(),
        "device"
    );
    assert_eq!(
        server.stdout(&["-s", &target, "get-serialno"]).trim(),
        target
    );
    assert_eq!(
        server.stdout(&["-s", &target, "get-devpath"]).trim(),
        "unknown"
    );
    let id = server.stdout(&["-s", &target, "get-transport-id"]);
    assert!(
        id.trim().parse::<u64>().is_ok(),
        "transport id not numeric: {id:?}"
    );
}

#[test]
fn wait_for_disconnect_empty_registry_succeeds_immediately() {
    let server = AdbServer::start();
    let output = server.run(&["wait-for-disconnect"]);
    assert!(
        output.status.success(),
        "wait-for-disconnect should succeed with no devices: {:?}",
        output
    );
}

#[test]
fn wait_for_device_succeeds_after_late_connect() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();
    let port = server.port;
    let target_for_thread = target.clone();

    thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        let _ = Command::new(adb_bin())
            .arg("-P")
            .arg(port.to_string())
            .arg("connect")
            .arg(&target_for_thread)
            .output();
    });

    let output = server.run(&["-s", &target, "wait-for-device"]);
    assert!(
        output.status.success(),
        "wait-for-device failed: {:?}",
        output
    );
}

#[test]
fn wait_for_disconnect_succeeds_when_target_leaves() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();
    let port = server.port;

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let target_for_thread = target.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        let _ = Command::new(adb_bin())
            .arg("-P")
            .arg(port.to_string())
            .arg("disconnect")
            .arg(&target_for_thread)
            .output();
    });

    let output = server.run(&["-s", &target, "wait-for-disconnect"]);
    assert!(
        output.status.success(),
        "wait-for-disconnect failed: {:?}",
        output
    );
}

#[test]
fn wait_for_local_device_succeeds_immediately() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "wait-for-local-device"]);
    assert!(
        output.status.success(),
        "wait-for-local-device failed: {:?}",
        output
    );
}

#[test]
fn wait_for_device_then_runs_following_command() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&[
        "-s",
        &target,
        "wait-for-device",
        "shell",
        "echo",
        "after-wait",
    ]);
    assert_eq!(
        stdout, "after-wait\n",
        "unexpected wait-for-device command output: {stdout:?}"
    );
}

#[test]
fn wait_for_short_command_reports_unknown_command() {
    let server = AdbServer::start();
    let output = server.run(&["wait-for"]);
    assert!(
        !output.status.success(),
        "wait-for should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown command wait-for"),
        "unexpected wait-for error: {stderr:?}"
    );
}

#[test]
fn shell_v2_echo_command_returns_output_and_exit_code() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "echo", "hello"]);
    assert_eq!(stdout, "hello\n", "unexpected shell output: {stdout:?}");
}

#[test]
fn shell_v2_id_command_returns_stub_identity() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "id"]);
    assert_eq!(stdout, "uid=0(root) gid=0(root)\n");
}

#[test]
fn shell_v2_stderr_is_separate_from_stdout() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "shell", "echo-stderr", "fake-error"]);
    assert!(output.status.success(), "shell failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout, "", "unexpected stdout: {stdout:?}");
    assert_eq!(stderr, "fake-error\n", "unexpected stderr: {stderr:?}");
}

#[test]
fn shell_v2_stdout_and_stderr_are_separate() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "shell", "echo-mixed", "line"]);
    assert!(output.status.success(), "shell failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout, "line-out\n", "unexpected stdout: {stdout:?}");
    assert_eq!(stderr, "line-err\n", "unexpected stderr: {stderr:?}");
}

#[test]
fn shell_command_propagates_exit_code() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "shell", "exit", "42"]);
    assert!(
        !output.status.success(),
        "expected nonzero exit: {:?}",
        output
    );
    assert_eq!(
        output.status.code(),
        Some(42),
        "unexpected exit code: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "", "unexpected stdout: {stdout:?}");
}

#[test]
fn shell_command_exit_zero_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "shell", "exit", "0"]);
    assert!(output.status.success(), "expected success: {:?}", output);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn shell_force_raw_flag_returns_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "-T", "echo", "raw"]);
    assert_eq!(stdout, "raw\n", "unexpected shell -T output: {stdout:?}");
}

#[test]
fn shell_x_flag_uses_legacy_shell() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "-x", "echo", "legacy"]);
    assert_eq!(stdout, "legacy\n", "unexpected shell -x output: {stdout:?}");
}

#[test]
fn shell_legacy_pty_flag_returns_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "-Tx", "echo", "pty-legacy"]);
    assert_eq!(
        stdout, "pty-legacy\n",
        "unexpected shell -Tx output: {stdout:?}"
    );
}

#[test]
fn shell_missing_e_argument_reports_option_requires_argument() {
    let server = AdbServer::start();

    let output = server.run(&["shell", "-e"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        "adb shell: option requires an argument -- e",
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn shell_legacy_command_propagates_exit_code() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    // 无 shell_v2 时 CLI 应回退到 legacy shell 并解析 echo 标记的退出码。
    let output = server.run(&["-s", &target, "shell", "exit", "5"]);
    assert!(
        !output.status.success(),
        "expected nonzero exit: {:?}",
        output
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "unexpected exit code: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "", "unexpected stdout: {stdout:?}");
}

#[test]
fn shell_legacy_command_returns_output_without_echo_marker() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "shell", "echo", "legacy"]);
    assert_eq!(
        stdout, "legacy\n",
        "unexpected legacy shell output: {stdout:?}"
    );
}

#[test]
fn shell_unknown_short_option_reports_unknown_option() {
    let server = AdbServer::start();

    let output = server.run(&["shell", "-Z", "echo", "hi"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        "adb shell: unknown option -- Z",
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn shell_e_multi_character_argument_reports_usage() {
    let server = AdbServer::start();

    let output = server.run(&["shell", "-e", "abc", "echo", "hi"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}-e requires a single-character argument or 'none'"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn shell_x_without_pty_reports_error() {
    let server = AdbServer::start();

    let output = server.run(&["shell", "-xT", "echo", "hi"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        "error: -x only supports allocating a pty",
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn raw_shell_service_forwards_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "raw", "shell:echo raw-hello"]);
    assert_eq!(stdout, "raw-hello\n", "unexpected raw output: {stdout:?}");
}

#[test]
fn raw_missing_service_reports_usage() {
    let server = AdbServer::start();
    let output = server.run(&["raw"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(stderr.trim(), format!("{prefix}usage: adb raw SERVICE"));
}

#[test]
fn raw_dev_raw_reports_unsupported_without_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "raw", "dev-raw:echo hi"]);
    assert!(!output.status.success(), "expected failure: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}dev-raw is not supported by the device"),
        "unexpected stderr: {stderr:?}"
    );
}

#[test]
fn raw_dev_raw_service_forwards_output_with_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,devraw");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "raw", "dev-raw:echo raw-dev"]);
    assert_eq!(stdout, "raw-dev\n", "unexpected dev-raw output: {stdout:?}");
}

#[test]
fn logcat_dump_returns_stub_logs() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "logcat", "-d"]);
    assert!(
        stdout.contains("fake-log message"),
        "unexpected logcat output: {stdout:?}"
    );
}

#[test]
fn reconnect_host_prints_reconnecting_message() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reconnect"]);
    assert!(output.status.success(), "reconnect failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reconnecting") && stdout.contains(&target),
        "unexpected reconnect output: {stdout:?}"
    );
}

#[test]
fn reconnect_device_service_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "reconnect", "device"]);
    let stderr_output = server.stderr_output();
    assert!(
        output.status.success(),
        "reconnect device failed: {:?}\nserver stderr:\n{}",
        output,
        stderr_output
    );
}

#[test]
fn reconnect_unknown_subcommand_reports_usage() {
    let server = AdbServer::start();
    let output = server.run(&["reconnect", "unknown"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}usage: adb reconnect [device|offline]")
    );
}

#[test]
fn root_unroot_and_usb_services_succeed() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    for command in ["root", "unroot", "usb", "usb", "default"] {
        let args = if command == "usb" {
            vec!["-s", &target, "usb"]
        } else if command == "default" {
            vec!["-s", &target, "usb", "default"]
        } else {
            vec!["-s", &target, command]
        };
        let output = server.run(&args);
        assert!(output.status.success(), "{command} failed: {:?}", output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            "OK",
            "unexpected {command} output: {stdout:?}"
        );
    }
}

#[test]
fn reboot_services_succeed() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    for args in [
        vec!["-s", &target, "reboot"],
        vec!["-s", &target, "reboot", "bootloader"],
        vec!["-s", &target, "reboot-fastboot"],
        vec!["-s", &target, "reboot-bootloader"],
    ] {
        let output = server.run(&args);
        assert!(
            output.status.success(),
            "reboot command failed: {:?}",
            output
        );
    }
}

#[test]
fn tcpip_service_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "tcpip", "5555"]);
    assert!(output.status.success(), "tcpip failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("restarting in TCP mode port: 5555"),
        "unexpected tcpip output: {stdout:?}"
    );
}

#[test]
fn remount_and_verity_services_succeed() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    for command in ["remount", "disable-verity", "enable-verity"] {
        let output = server.run(&["-s", &target, command]);
        assert!(output.status.success(), "{command} failed: {:?}", output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            "OK",
            "unexpected {command} output: {stdout:?}"
        );
    }
}

#[test]
fn mdns_check_reports_state() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["mdns", "check"]);
    assert!(
        stdout.to_ascii_lowercase().contains("mdns"),
        "unexpected mdns check output: {stdout:?}"
    );
}

#[test]
fn mdns_services_lists_discovered_services() {
    let server = AdbServer::start();
    let stdout = server.stdout(&["mdns", "services"]);
    assert!(
        stdout.starts_with("List of discovered mdns services\n"),
        "unexpected mdns services header: {stdout:?}"
    );
}

#[test]
fn pair_requires_host_and_reports_failure() {
    let server = AdbServer::start();

    let output = server.run(&["pair"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}usage: adb pair HOST[:PORT] [PAIRING CODE]")
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    drop(listener);
    let output = server.run(&["pair", &target, "123456"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed: Unable to start pairing client."),
        "unexpected pair error: {stderr:?}"
    );
}

#[test]
fn pair_prompts_for_code_and_reads_from_stdin() {
    let server = AdbServer::start();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    drop(listener);

    let mut child = Command::new(adb_bin())
        .arg("-P")
        .arg(server.port.to_string())
        .arg("pair")
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("ANDROID_SDK_HOME", server.android_home.path())
        .spawn()
        .expect("failed to spawn pair");

    let mut stdin = child.stdin.take().expect("missing stdin");
    stdin.write_all(b"123456\n").unwrap();
    drop(stdin);

    let output = child
        .wait_with_output()
        .expect("failed to read pair output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("Enter pairing code: "),
        "missing prompt in stdout: {stdout:?}"
    );
    assert!(
        stderr.contains("Failed: Unable to start pairing client."),
        "unexpected pair error: {stderr:?}"
    );
    assert!(!output.status.success());
}

#[test]
fn exec_out_forwards_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "exec-out", "echo", "exec-hello"]);
    assert!(
        stdout.contains("exec-hello"),
        "unexpected exec-out output: {stdout:?}"
    );
}

#[test]
fn exec_in_succeeds_with_eof() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "exec-in", "cat"]);
    assert!(output.status.success(), "exec-in failed: {:?}", output);
}

#[test]
fn abb_reports_unsupported_without_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "abb", "shell", "echo", "hi"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("abb is not supported by the device"),
        "unexpected abb error: {stderr:?}"
    );
}

#[test]
fn abb_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "abb", "package", "list", "packages"]);
    assert!(output.status.success(), "abb failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("package:com.example.fake"),
        "unexpected abb output: {stdout:?}"
    );
}

#[test]
fn uninstall_succeeds() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "uninstall", "com.example.app"]);
    assert!(
        stdout.contains("Success"),
        "unexpected uninstall output: {stdout:?}"
    );
}

#[test]
fn uninstall_keep_data_reports_warning_and_fails() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "uninstall", "-k", "com.example.app"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("The -k option uninstalls the application"),
        "unexpected uninstall -k output: {stdout:?}"
    );
    assert!(
        stdout.contains("adb shell pm uninstall -k"),
        "unexpected uninstall -k warning command: {stdout:?}"
    );
}

#[test]
fn sync_ls_lists_remote_files() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let stdout = server.stdout(&["-s", &target, "ls", "/data/local/tmp"]);
    assert!(
        stdout.contains("hello.txt"),
        "unexpected ls output: {stdout:?}"
    );
}

#[test]
fn sync_pull_retrieves_remote_file() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("hello.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/hello.txt",
        local.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "pull failed: {:?}", output);
    assert_eq!(
        std::fs::read_to_string(&local).unwrap(),
        "hello, sync\n",
        "pulled content mismatch"
    );
}

#[test]
fn sync_pull_preserve_attrs_restores_mtime() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("hello.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-a",
        "/data/local/tmp/hello.txt",
        local.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "pull -a failed: {:?}", output);
    assert_eq!(
        std::fs::read_to_string(&local).unwrap(),
        "hello, sync\n",
        "pulled content mismatch"
    );
    let metadata = std::fs::metadata(&local).unwrap();
    let mtime = FileTime::from_last_modification_time(&metadata);
    assert_eq!(mtime.unix_seconds(), 1_700_000_000, "mtime mismatch");
}

#[test]
fn sync_push_uploads_local_file() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("pushed.txt");
    std::fs::write(&local, "pushed content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        local.to_str().unwrap(),
        "/data/local/tmp/pushed.txt",
    ]);
    assert!(output.status.success(), "push failed: {:?}", output);

    let pulled = dir.path().join("pulled.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/pushed.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after push failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "pushed content\n",
        "round-trip content mismatch"
    );
}

#[test]
fn sync_push_uploads_local_file_v2() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("pushed-v2.txt");
    std::fs::write(&local, "pushed v2 content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        local.to_str().unwrap(),
        "/data/local/tmp/pushed-v2.txt",
    ]);
    assert!(output.status.success(), "push v2 failed: {:?}", output);

    let pulled = dir.path().join("pulled-v2.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/pushed-v2.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after push v2 failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "pushed v2 content\n",
        "round-trip v2 content mismatch"
    );
}

#[test]
fn push_quiet_suppresses_summary() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("quiet-push.txt");
    std::fs::write(&local, "quiet push content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-q",
        local.to_str().unwrap(),
        "/data/local/tmp/quiet-push.txt",
    ]);
    assert!(output.status.success(), "push -q failed: {:?}", output);
    assert!(
        output.stdout.is_empty(),
        "quiet push should not write to stdout: {:?}",
        output
    );

    let pulled = dir.path().join("pulled-quiet-push.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/quiet-push.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after quiet push failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "quiet push content\n",
        "round-trip content mismatch"
    );
}

#[test]
fn pull_quiet_suppresses_summary() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("quiet-pull-source.txt");
    std::fs::write(&local, "quiet pull content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        local.to_str().unwrap(),
        "/data/local/tmp/quiet-pull-source.txt",
    ]);
    assert!(output.status.success(), "push failed: {:?}", output);

    let pulled = dir.path().join("quiet-pull-target.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-q",
        "/data/local/tmp/quiet-pull-source.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "pull -q failed: {:?}", output);
    assert!(
        output.stdout.is_empty(),
        "quiet pull should not write to stdout: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "quiet pull content\n",
        "pulled content mismatch"
    );
}

#[test]
fn adb_sync_quiet_suppresses_summary() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product = tempfile::tempdir().unwrap();
    let data_dir = product.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("sync-quiet.txt"), "sync quiet content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-q", "data"],
        &[("ANDROID_PRODUCT_OUT", product.path())],
    );
    assert!(output.status.success(), "sync -q failed: {:?}", output);
    assert!(
        output.stdout.is_empty(),
        "quiet sync should not write to stdout: {:?}",
        output
    );

    let pulled = product.path().join("pulled-sync-quiet.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/sync-quiet.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync -q failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "sync quiet content\n",
        "synced content mismatch"
    );
}

#[test]
fn sync_push_dry_run_v2_does_not_write_file() {
    let server = AdbServer::start();
    let device =
        FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_dry_run_send");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("dry-run.txt");
    std::fs::write(&local, "should not land\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-n",
        local.to_str().unwrap(),
        "/data/local/tmp/dry-run.txt",
    ]);
    assert!(output.status.success(), "push -n failed: {:?}", output);

    // dry-run 不应实际写入远端文件，pull 应失败。
    let pulled = dir.path().join("pulled-dry-run.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/dry-run.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull after dry-run should fail: {:?}",
        output
    );
}

#[test]
fn sync_push_dry_run_with_zstd_compression_v2() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features(
        "shell_v2,sendrecv_v2,sendrecv_v2_dry_run_send,sendrecv_v2_zstd",
    );
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("dry-run-compressed.txt");
    std::fs::write(&local, "should not land compressed\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "zstd",
        "-n",
        local.to_str().unwrap(),
        "/data/local/tmp/dry-run-compressed.txt",
    ]);
    assert!(
        output.status.success(),
        "push -z zstd -n failed: {:?}",
        output
    );

    // 压缩 + dry-run 不应实际写入远端文件，pull 应失败。
    let pulled = dir.path().join("pulled-dry-run-compressed.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/dry-run-compressed.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull after push -z zstd -n should fail: {:?}",
        output
    );
}

#[test]
fn sync_push_and_pull_with_zstd_compression_v2() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_zstd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("compressed.txt");
    std::fs::write(&local, "compressed content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "zstd",
        local.to_str().unwrap(),
        "/data/local/tmp/compressed.txt",
    ]);
    assert!(
        output.status.success(),
        "push with zstd failed: {:?}",
        output
    );

    let pulled = dir.path().join("pulled-compressed.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-z",
        "zstd",
        "/data/local/tmp/compressed.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull with zstd failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "compressed content\n",
        "zstd round-trip content mismatch"
    );
}

#[test]
fn sync_push_and_pull_with_lz4_compression_v2() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_lz4");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("compressed.txt");
    std::fs::write(&local, "compressed content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "lz4",
        local.to_str().unwrap(),
        "/data/local/tmp/compressed.txt",
    ]);
    assert!(
        output.status.success(),
        "push with lz4 failed: {:?}",
        output
    );

    let pulled = dir.path().join("pulled-compressed.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-z",
        "lz4",
        "/data/local/tmp/compressed.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull with lz4 failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "compressed content\n",
        "lz4 round-trip content mismatch"
    );
}

#[test]
fn sync_push_and_pull_with_brotli_compression_v2() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_brotli");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("compressed.txt");
    std::fs::write(&local, "compressed content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "brotli",
        local.to_str().unwrap(),
        "/data/local/tmp/compressed.txt",
    ]);
    assert!(
        output.status.success(),
        "push with brotli failed: {:?}",
        output
    );

    let pulled = dir.path().join("pulled-compressed.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-z",
        "brotli",
        "/data/local/tmp/compressed.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull with brotli failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "compressed content\n",
        "brotli round-trip content mismatch"
    );
}

#[test]
fn sync_push_multiple_files_to_directory() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.txt");
    let second = dir.path().join("second.txt");
    std::fs::write(&first, "first content\n").unwrap();
    std::fs::write(&second, "second content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        first.to_str().unwrap(),
        second.to_str().unwrap(),
        "/data/local/tmp/multi_push/",
    ]);
    assert!(output.status.success(), "push failed: {:?}", output);

    for (name, expected) in [
        ("first.txt", "first content\n"),
        ("second.txt", "second content\n"),
    ] {
        let pulled = dir.path().join(format!("pulled-{name}"));
        let output = server.run(&[
            "-s",
            &target,
            "pull",
            &format!("/data/local/tmp/multi_push/{name}"),
            pulled.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "pull {name} failed: {:?}", output);
        assert_eq!(
            std::fs::read_to_string(&pulled).unwrap(),
            expected,
            "content mismatch for {name}"
        );
    }
}

#[test]
fn sync_pull_directory_retrieves_nested_file() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/pull_dir",
        dir.path().to_str().unwrap(),
    ]);
    assert!(output.status.success(), "pull dir failed: {:?}", output);

    let pulled = dir.path().join("pull_dir").join("nested.txt");
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "nested content\n",
        "pulled directory content mismatch"
    );
}

#[test]
fn sync_pull_multiple_files_to_directory() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/hello.txt",
        "/data/local/tmp/pull_dir/nested.txt",
        dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull multiple failed: {:?}",
        output
    );

    assert_eq!(
        std::fs::read_to_string(dir.path().join("hello.txt")).unwrap(),
        "hello, sync\n",
        "hello.txt content mismatch"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("nested.txt")).unwrap(),
        "nested content\n",
        "nested.txt content mismatch"
    );
}

#[test]
fn sync_push_directory_and_pull_back() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let local_dir = tempfile::tempdir().unwrap();
    let src_dir = local_dir.path().join("src");
    std::fs::create_dir(&src_dir).unwrap();
    std::fs::write(src_dir.join("file.txt"), "dir file content\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        src_dir.to_str().unwrap(),
        "/data/local/tmp/push_dir",
    ]);
    assert!(output.status.success(), "push dir failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/push_dir",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull dir after push failed: {:?}",
        output
    );

    let pulled = pull_dir
        .path()
        .join("push_dir")
        .join("src")
        .join("file.txt");
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "dir file content\n",
        "pushed directory round-trip content mismatch"
    );
}

#[test]
fn sync_push_directory_with_zstd_compression_and_pull_back() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_zstd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let local_dir = tempfile::tempdir().unwrap();
    let src_dir = local_dir.path().join("src");
    std::fs::create_dir(&src_dir).unwrap();
    std::fs::write(src_dir.join("file.txt"), "dir file content\n").unwrap();

    // 复用 fake fs 中已存在的 /data/local/tmp/push_dir，使 remote_is_dir=true，
    // 目录 push 行为与 v1 一致：把源目录本身放到目标目录下。
    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "zstd",
        src_dir.to_str().unwrap(),
        "/data/local/tmp/push_dir",
    ]);
    assert!(
        output.status.success(),
        "push dir with zstd failed: {:?}",
        output
    );

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-z",
        "zstd",
        "/data/local/tmp/push_dir/src",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull dir with zstd after push failed: {:?}",
        output
    );

    let pulled = pull_dir.path().join("src").join("file.txt");
    assert_eq!(
        std::fs::read_to_string(&pulled).unwrap(),
        "dir file content\n",
        "pushed directory zstd round-trip content mismatch"
    );
}

#[test]
fn install_multiple_succeeds_with_pm_mode() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk1 = dir.path().join("base.apk");
    let apk2 = dir.path().join("split.apk");
    std::fs::write(&apk1, b"PK\x03\x04 base apk").unwrap();
    std::fs::write(&apk2, b"PK\x03\x04 split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multiple",
        apk1.to_str().unwrap(),
        apk2.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install-multiple failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "unexpected install-multiple output: {stdout:?}"
    );
}

#[test]
fn install_succeeds_with_push_mode() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();

    let output = server.run(&["-s", &target, "install", apk.to_str().unwrap()]);
    assert!(output.status.success(), "install failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Push Install") && stdout.contains("Success"),
        "unexpected install output: {stdout:?}"
    );
}

#[test]
fn install_no_fastdeploy_allows_push_install() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--no-fastdeploy",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install --no-fastdeploy failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Push Install") && stdout.contains("Success"),
        "unexpected install --no-fastdeploy output: {stdout:?}"
    );
}

#[test]
fn install_streaming_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--streaming",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "streaming install failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Streamed Install") && stdout.contains("Success"),
        "unexpected streaming install output: {stdout:?}"
    );
}

#[test]
fn install_no_streaming_forces_push_mode() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--no-streaming",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install --no-streaming failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Push Install") && stdout.contains("Success"),
        "unexpected install --no-streaming output: {stdout:?}"
    );
}

#[test]
fn install_multi_package_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.apk");
    let split = dir.path().join("split.apk");
    std::fs::write(&base, b"PK\x03\x04 fake base apk").unwrap();
    std::fs::write(&split, b"PK\x03\x04 fake split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multi-package",
        base.to_str().unwrap(),
        split.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install-multi-package failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "unexpected install-multi-package output: {stdout:?}"
    );
}

#[test]
fn install_multiple_streaming_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.apk");
    let split = dir.path().join("split.apk");
    std::fs::write(&base, b"PK\x03\x04 fake base apk").unwrap();
    std::fs::write(&split, b"PK\x03\x04 fake split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multiple",
        "--streaming",
        base.to_str().unwrap(),
        split.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install-multiple --streaming failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "unexpected install-multiple --streaming output: {stdout:?}"
    );
}

#[test]
fn sync_push_sync_skips_when_mtime_matches() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("hello.txt");
    std::fs::write(&local, "hello, sync\n").unwrap();
    set_file_mtime(&local, FileTime::from_unix_time(1_700_000_000, 0)).unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "--sync",
        local.to_str().unwrap(),
        "/data/local/tmp/hello.txt",
    ]);
    assert!(output.status.success(), "push --sync failed: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skipped"),
        "expected skip summary on stderr, got stdout: {:?} stderr: {:?}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
}

#[test]
fn sync_pull_missing_file_reports_error() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("missing.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/local/tmp/no-such-file.txt",
        local.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remote object '/data/local/tmp/no-such-file.txt' does not exist"),
        "unexpected pull error: {stderr:?}"
    );
}

#[test]
fn install_multi_package_reports_unsupported_without_cmd_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk1 = dir.path().join("base.apk");
    let apk2 = dir.path().join("feature.apk");
    std::fs::write(&apk1, b"PK\x03\x04 base").unwrap();
    std::fs::write(&apk2, b"PK\x03\x04 feature").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multi-package",
        apk1.to_str().unwrap(),
        apk2.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install-multi-package should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("adb: multi-package install is not supported on this device"),
        "unexpected install-multi-package error: {stderr:?}"
    );
}

#[test]
fn adb_sync_pushes_product_out_partition() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("synced.txt"), "synced content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(pull_dir.path().join("synced.txt")).unwrap(),
        "synced content\n",
        "synced content mismatch"
    );
}

#[test]
fn adb_sync_with_zstd_compression_pushes_product_out() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_zstd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("synced.txt"), "synced compressed content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-z", "zstd"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -z zstd failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync -z zstd failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(pull_dir.path().join("synced.txt")).unwrap(),
        "synced compressed content\n",
        "sync -z zstd content mismatch"
    );
}

#[test]
fn adb_sync_with_lz4_compression_pushes_product_out() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_lz4");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("synced.txt"), "synced lz4 content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-z", "lz4"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -z lz4 failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync -z lz4 failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(pull_dir.path().join("synced.txt")).unwrap(),
        "synced lz4 content\n",
        "sync -z lz4 content mismatch"
    );
}

#[test]
fn adb_sync_with_brotli_compression_pushes_product_out() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_brotli");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("synced.txt"), "synced brotli content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-z", "brotli"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(
        output.status.success(),
        "sync -z brotli failed: {:?}",
        output
    );

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync -z brotli failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(pull_dir.path().join("synced.txt")).unwrap(),
        "synced brotli content\n",
        "sync -z brotli content mismatch"
    );
}

#[test]
fn adb_sync_force_no_compression_overrides_default() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_zstd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(
        data_dir.join("synced.txt"),
        "synced no compression content\n",
    )
    .unwrap();

    // 设备支持 zstd，但命令行 -Z 应强制无压缩。
    let output = server.run_with_env(
        &["-s", &target, "sync", "-Z"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -Z failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "pull after sync -Z failed: {:?}",
        output
    );
    assert_eq!(
        std::fs::read_to_string(pull_dir.path().join("synced.txt")).unwrap(),
        "synced no compression content\n",
        "sync -Z content mismatch"
    );
}

#[test]
fn adb_sync_list_only_quiet_suppresses_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("sync-quiet-list.txt"), "sync quiet list\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-l", "-q", "data"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -l -q failed: {:?}", output);
    assert!(
        output.stdout.is_empty(),
        "quiet list-only sync should not write to stdout: {:?}",
        output
    );

    // list-only 不应实际写入远端文件。
    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/sync-quiet-list.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull after sync -l -q should fail: {:?}",
        output
    );
}

#[test]
fn adb_sync_list_only_lists_files_without_transferring() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("synced.txt"), "synced content\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-l"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -l failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would push:") && stdout.contains("synced.txt"),
        "unexpected sync -l output: {stdout:?}"
    );

    // list-only 不应实际写入远端文件，pull 应失败。
    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/synced.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull after sync -l should fail: {:?}",
        output
    );
}

#[test]
fn adb_sync_dry_run_does_not_write_remote_file() {
    let server = AdbServer::start();
    let device =
        FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2,sendrecv_v2_dry_run_send");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(data_dir.join("dry-run.txt"), "should not land\n").unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-n"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -n failed: {:?}", output);

    let pull_dir = tempfile::tempdir().unwrap();
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "/data/dry-run.txt",
        pull_dir.path().to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "pull after sync -n should fail: {:?}",
        output
    );
}

#[test]
fn adb_sync_skips_unchanged_files_by_size_and_mtime() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let local = data_dir.join("unchanged.txt");
    std::fs::write(&local, "unchanged content\n").unwrap();
    set_file_mtime(&local, FileTime::from_unix_time(1_700_000_000, 0)).unwrap();

    // 第一次 sync 推送文件。
    let output = server.run_with_env(
        &["-s", &target, "sync"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "first sync failed: {:?}", output);

    // 第二次 sync 应因 size/mtime 匹配而跳过。
    let output = server.run_with_env(
        &["-s", &target, "sync"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "second sync failed: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0 files pushed, 1 skipped"),
        "expected skip summary on stderr, got stdout: {:?} stderr: {:?}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
}

#[test]
fn install_requires_argument() {
    let server = AdbServer::start();
    let output = server.run(&["install"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}install requires an argument")
    );
}

#[test]
fn install_rejects_non_apk_file() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let not_apk = dir.path().join("app.txt");
    std::fs::write(&not_apk, b"not an apk").unwrap();

    let output = server.run(&["-s", &target, "install", not_apk.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "install should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("need APK file on command line"),
        "unexpected install error: {stderr:?}"
    );
}

#[test]
fn install_apex_push_mode_requires_streamed_install() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apex = dir.path().join("app.apex");
    std::fs::write(&apex, b"fake apex").unwrap();

    let output = server.run(&["-s", &target, "install", apex.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "install .apex in push mode should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("APEX packages are only compatible with Streamed Install"),
        "unexpected install error: {stderr:?}"
    );
}

#[test]
fn install_apex_streamed_mode_requires_device_support() {
    let server = AdbServer::start();
    // 支持 streamed install（有 cmd/abb_exec）但设备未声明 apex feature。
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apex = dir.path().join("app.apex");
    std::fs::write(&apex, b"fake apex").unwrap();

    let output = server.run(&["-s", &target, "install", apex.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "install .apex on unsupported device should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".apex is not supported on the target device"),
        "unexpected install error: {stderr:?}"
    );
}

#[test]
fn install_streaming_unsupported_on_device_without_cmd() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--streaming",
        apk.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install --streaming should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Attempting to use streaming install on unsupported device"),
        "unexpected install error: {stderr:?}"
    );
}

#[test]
fn install_multiple_streaming_unsupported_on_device_without_cmd() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk1 = dir.path().join("base.apk");
    let apk2 = dir.path().join("split.apk");
    std::fs::write(&apk1, b"PK\x03\x04 base apk").unwrap();
    std::fs::write(&apk2, b"PK\x03\x04 split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multiple",
        "--streaming",
        apk1.to_str().unwrap(),
        apk2.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install-multiple --streaming should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Attempting to use streaming install on unsupported device"),
        "unexpected install-multiple error: {stderr:?}"
    );
}

#[test]
fn install_fastdeploy_push_deploys_agent_and_streams_patch() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    write_fastdeploy_test_apk(&apk);

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--fastdeploy",
        "--force-agent",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install --fastdeploy should have succeeded: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Push Install") && stdout.contains("Success"),
        "unexpected fastdeploy output: {stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Detected 0 equal APK entries"));
}

#[test]
fn install_fastdeploy_streamed_sends_patch_to_agent_pm_mode() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    write_fastdeploy_test_apk(&apk);
    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--streaming",
        "--fastdeploy",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "streamed fastdeploy should have succeeded: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Performing Streamed Install"));
}

#[test]
fn install_fastdeploy_missing_package_falls_back_to_regular_install() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    write_fastdeploy_test_apk_with_package(&apk, "com.example.missingpkg");
    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--fastdeploy",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "missing package should fall back: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Performing Push Install") && stdout.contains("Success"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found, falling back to install"));
}

#[test]
fn install_fastdeploy_old_agent_is_redeployed_and_retried() {
    FASTDEPLOY_OLD_AGENT_DUMPS.store(0, Ordering::SeqCst);
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    write_fastdeploy_test_apk_with_package(&apk, "com.example.oldagentxx");
    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--fastdeploy",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "old agent should be redeployed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Device agent version is old (2), re-deploying"));
    assert!(stdout.contains("Performing Push Install") && stdout.contains("Success"));
    assert_eq!(FASTDEPLOY_OLD_AGENT_DUMPS.load(Ordering::SeqCst), 2);
}

#[test]
fn install_fastdeploy_rejects_apex() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd,apex");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apex = dir.path().join("app.apex");
    std::fs::write(&apex, b"fake apex").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--fastdeploy",
        apex.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install --fastdeploy .apex should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}--fastdeploy doesn't support .apex files"),
        "unexpected fastdeploy apex error: {stderr:?}"
    );
}

#[test]
fn install_fastdeploy_rejects_non_apk_last_arg() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "install", "--fastdeploy", "not-an-apk"]);
    assert!(
        !output.status.success(),
        "install --fastdeploy non-apk should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}filename doesn't end .apk or .apex: not-an-apk"),
        "unexpected fastdeploy non-apk error: {stderr:?}"
    );
}

#[test]
fn install_incremental_unsupported_on_device_without_abb_exec() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--incremental",
        apk.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install --incremental should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Device doesn't support incremental installations"),
        "unexpected incremental error: {stderr:?}"
    );
}

#[test]
fn install_incremental_and_fastdeploy_conflict() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--incremental",
        "--fastdeploy",
        apk.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install --incremental --fastdeploy should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--incremental and --fast-deploy options are incompatible"),
        "unexpected conflict error: {stderr:?}"
    );
}

#[test]
fn install_incremental_falls_back_to_streaming_without_idsig() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--incremental",
        apk.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install --incremental should have fallen back: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Streamed Install") && stdout.contains("Success"),
        "unexpected fallback output: {stdout:?}"
    );
}

#[test]
fn install_incremental_fails_with_invalid_idsig() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    let idsig = dir.path().join("app.apk.idsig");
    std::fs::write(&apk, b"PK\x03\x04 fake apk content").unwrap();
    std::fs::write(&idsig, b"fake idsig").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install",
        "--incremental",
        apk.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "install --incremental should have failed with invalid idsig: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read idsig") || stderr.contains("incremental install"),
        "unexpected incremental error: {stderr:?}"
    );
}

#[test]
fn install_multiple_incremental_falls_back_without_idsig() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.apk");
    let split = dir.path().join("split.apk");
    std::fs::write(&base, b"PK\x03\x04 fake base apk").unwrap();
    std::fs::write(&split, b"PK\x03\x04 fake split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multiple",
        "--incremental",
        base.to_str().unwrap(),
        split.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install-multiple --incremental should have fallen back: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "unexpected fallback output: {stdout:?}"
    );
}

#[test]
fn install_multi_package_passes_incremental_as_session_arg() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,abb_exec,cmd");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.apk");
    let split = dir.path().join("split.apk");
    std::fs::write(&base, b"PK\x03\x04 fake base apk").unwrap();
    std::fs::write(&split, b"PK\x03\x04 fake split apk").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "install-multi-package",
        "--incremental",
        base.to_str().unwrap(),
        split.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "install-multi-package --incremental failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "unexpected install-multi-package --incremental output: {stdout:?}"
    );
}

#[test]
fn bugreport_creates_zip_from_bugreportz_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("report.zip");
    let output = server.run(&["-s", &target, "bugreport", dest.to_str().unwrap()]);
    assert!(output.status.success(), "bugreport failed: {:?}", output);
    assert!(
        dest.exists(),
        "bugreport did not create destination zip file"
    );
    assert_eq!(
        std::fs::read_to_string(&dest).unwrap(),
        "fake zipped bugreport\n",
        "bugreport zip content mismatch"
    );
}

#[test]
fn bugreport_stream_prints_output() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "bugreport", "--stream"]);
    assert!(
        output.status.success(),
        "bugreport --stream failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fake-streamed-bugreport"),
        "unexpected bugreport --stream output: {stdout:?}"
    );
}

#[test]
fn rescue_requires_argument() {
    let server = AdbServer::start();
    let output = server.run(&["rescue"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}rescue requires at least one argument")
    );
}

#[test]
fn backup_requires_packages_or_shared() {
    let server = AdbServer::start();
    let output = server.run(&["backup"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("backup either needs a list of packages or -all/-shared"),
        "unexpected backup error: {stderr:?}"
    );
}

#[test]
fn push_compression_falls_back_to_legacy_without_sendrecv_v2_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("file.txt");
    std::fs::write(&local, "hello\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "zstd",
        local.to_str().unwrap(),
        "/data/local/tmp/file.txt",
    ]);
    assert!(output.status.success(), "legacy push -z failed: {output:?}");

    let pulled = dir.path().join("pulled.txt");
    let output = server.run(&[
        "-s",
        &target,
        "pull",
        "-z",
        "zstd",
        "/data/local/tmp/file.txt",
        pulled.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "legacy pull -z failed: {output:?}");
    assert_eq!(std::fs::read_to_string(pulled).unwrap(), "hello\n");
}

#[test]
fn push_dry_run_unsupported_error_matches_aosp() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {output:?}");

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("dry-run.txt");
    std::fs::write(&local, "dry run\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-n",
        local.to_str().unwrap(),
        "/data/local/tmp/dry-run.txt",
    ]);
    assert!(!output.status.success(), "push -n should fail: {output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "adb: error: dry-run not supported by the device"
    );
}

#[test]
fn explicit_compression_is_sent_without_algorithm_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,sendrecv_v2");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {output:?}");

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("explicit-zstd.txt");
    std::fs::write(&local, "explicit zstd\n").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "push",
        "-z",
        "zstd",
        local.to_str().unwrap(),
        "/data/local/tmp/explicit-zstd.txt",
    ]);
    assert!(
        output.status.success(),
        "explicit zstd push failed: {output:?}"
    );
}

#[test]
fn sync_list_only_reports_zero_files() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let product_out = tempfile::tempdir().unwrap();
    let data_dir = product_out.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();

    let output = server.run_with_env(
        &["-s", &target, "sync", "-l"],
        &[("ANDROID_PRODUCT_OUT", product_out.path())],
    );
    assert!(output.status.success(), "sync -l failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would be pushed") && stdout.contains("0 skipped"),
        "unexpected sync -l output: {stdout:?}"
    );
}

#[test]
fn sideload_requires_argument() {
    let server = AdbServer::start();
    let output = server.run(&["sideload"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}sideload requires an argument")
    );
}

#[test]
fn restore_requires_filename() {
    let server = AdbServer::start();
    let output = server.run(&["restore"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = if cfg!(windows) { "adb.exe: " } else { "adb: " };
    assert_eq!(
        stderr.trim(),
        format!("{prefix}usage: adb restore FILENAME [ARG]...")
    );
}

#[test]
fn track_app_reports_unsupported_without_feature() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "track-app"]);
    assert!(
        !output.status.success(),
        "track-app should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("track-app is not supported by the device"),
        "unexpected track-app error: {stderr:?}"
    );
}

#[test]
fn track_app_with_feature_streams_protobuf_text() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start_with_features("shell_v2,track_app");
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "track-app"]);
    assert!(
        output.status.success(),
        "track-app should have succeeded: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Process count: 1"),
        "missing process count: {stdout:?}"
    );
    assert!(stdout.contains("pid: 12345"), "missing pid: {stdout:?}");
    assert!(
        stdout.contains("process_name: \"adb.test.process\""),
        "missing process_name: {stdout:?}"
    );
    assert!(
        stdout.contains("package_names: \"adb.test.app\""),
        "missing package_names: {stdout:?}"
    );
}

#[test]
fn transport_id_prints_selected_device_id() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "transport-id"]);
    assert!(output.status.success(), "transport-id failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let id = stdout.trim();
    assert!(
        id.parse::<u32>().is_ok(),
        "transport-id should print a numeric id, got {stdout:?}"
    );
    assert!(
        id != "0",
        "transport-id should be non-zero for a connected device"
    );
}

#[test]
fn keygen_creates_private_and_public_key_files() {
    let server = AdbServer::start();
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test_adbkey");

    let output = server.run(&["keygen", key_path.to_str().unwrap()]);
    assert!(output.status.success(), "keygen failed: {:?}", output);
    assert!(key_path.exists(), "private key file was not created");
    let pub_path = key_path.with_extension("pub");
    assert!(pub_path.exists(), "public key file was not created");
}

#[test]
fn pubkey_prints_android_public_key_for_private_key() {
    let server = AdbServer::start();
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test_adbkey");

    let output = server.run(&["keygen", key_path.to_str().unwrap()]);
    assert!(output.status.success(), "keygen failed: {:?}", output);

    let output = server.run(&["pubkey", key_path.to_str().unwrap()]);
    assert!(output.status.success(), "pubkey failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    assert!(
        line.contains(' '),
        "pubkey output should contain a space-separated Android public key, got {stdout:?}"
    );
}

#[test]
fn attach_not_supported_on_tcp_transport() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "attach"]);
    assert!(
        !output.status.success(),
        "attach should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("attach/detach not supported"),
        "unexpected attach error: {stderr:?}"
    );
}

#[test]
fn detach_not_supported_on_tcp_transport() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "detach"]);
    assert!(
        !output.status.success(),
        "detach should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("attach/detach not supported!"),
        "unexpected detach error: {stderr:?}"
    );
}

#[test]
fn jdwp_lists_process_ids_from_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "jdwp"]);
    assert!(output.status.success(), "jdwp failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("12345"), "missing pid 12345: {stdout:?}");
    assert!(stdout.contains("67890"), "missing pid 67890: {stdout:?}");
}

#[test]
fn track_jdwp_streams_process_ids_from_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "track-jdwp"]);
    assert!(output.status.success(), "track-jdwp failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("11111"), "missing pid 11111: {stdout:?}");
    assert!(stdout.contains("22222"), "missing pid 22222: {stdout:?}");
}

#[test]
fn emu_reports_no_emulator_when_none_connected() {
    let server = AdbServer::start();
    let output = server.run(&["emu"]);
    assert!(
        !output.status.success(),
        "emu should have failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no emulator detected") || stderr.contains("no emulator connected"),
        "unexpected emu error: {stderr:?}"
    );
}

#[test]
fn emu_sends_commands_to_console_and_prints_response() {
    // Fake emulator console：监听一个端口，接收命令后返回带两个 OK 前缀的响应。
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let console_port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let received = String::from_utf8_lossy(&buf);
        assert!(
            received.contains("avd name\n"),
            "console did not receive avd name: {received:?}"
        );
        assert!(
            received.contains("quit\n"),
            "console did not receive quit: {received:?}"
        );
        stream
            .write_all(
                b"Android Console: Authentication required\r\nOK\r\n\
                 Android Console: type 'help' for a list of commands\r\nOK\r\n\
                 Pixel_6_API_34\r\nOK\r\n",
            )
            .unwrap();
    });

    let server = AdbServer::start();
    let output = server.run(&[
        "-s",
        &format!("emulator-{console_port}"),
        "emu",
        "avd",
        "name",
    ]);
    assert!(output.status.success(), "emu failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Pixel_6_API_34"),
        "missing console response in stdout: {stdout:?}"
    );
}

#[test]
fn sideload_succeeds_with_fake_device_using_host_protocol() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("ota.zip");
    std::fs::write(&package, b"PK\x03\x04 fake ota package content").unwrap();

    let output = server.run(&["-s", &target, "sideload", package.to_str().unwrap()]);
    assert!(output.status.success(), "sideload failed: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("trying pre-KitKat sideload method"),
        "sideload should use host protocol: {stderr:?}"
    );
}

#[test]
fn backup_creates_file_from_device_stream() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let backup_file = dir.path().join("backup.ab");
    let output = server.run(&[
        "-s",
        &target,
        "backup",
        "-f",
        backup_file.to_str().unwrap(),
        "-all",
    ]);
    assert!(output.status.success(), "backup failed: {:?}", output);
    assert!(backup_file.exists(), "backup file was not created");
    let content = std::fs::read_to_string(&backup_file).unwrap();
    assert!(
        content.contains("fake backup payload"),
        "unexpected backup content: {content:?}"
    );
}

#[test]
fn restore_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("backup.ab");
    std::fs::write(&backup, b"ANDROID BACKUP DATA").unwrap();

    let output = server.run(&["-s", &target, "restore", backup.to_str().unwrap()]);
    assert!(output.status.success(), "restore failed: {:?}", output);
}

#[test]
fn rescue_getprop_returns_properties_from_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "rescue", "getprop"]);
    assert!(
        output.status.success(),
        "rescue getprop failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ro.product.model"),
        "unexpected rescue getprop output: {stdout:?}"
    );
}

#[test]
fn rescue_wipe_userdata_succeeds_with_fake_device() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let output = server.run(&["-s", &target, "rescue", "wipe", "userdata"]);
    assert!(
        output.status.success(),
        "rescue wipe userdata failed: {:?}",
        output
    );
}

#[test]
fn rescue_install_succeeds_with_fake_device_using_host_protocol() {
    let server = AdbServer::start();
    let device = FakeAdbDevice::start();
    let target = device.address();

    let output = server.run(&["connect", &target]);
    assert!(output.status.success(), "connect failed: {:?}", output);

    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("ota.zip");
    std::fs::write(&package, b"PK\x03\x04 fake ota package content").unwrap();

    let output = server.run(&[
        "-s",
        &target,
        "rescue",
        "install",
        package.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "rescue install failed: {:?}",
        output
    );
}
