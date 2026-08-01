use std::fs;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use lz4_flex::block::compress as lz4_compress;

use crate::error::{AdbError, Result};

/// APK 增量安装所需的 idsig 文件后缀。
const IDSIG_SUFFIX: &str = ".idsig";

/// 增量安装使用的数据块大小，与 AOSP `incremental::kBlockSize` 一致。
const BLOCK_SIZE: usize = 4096;

/// fs-verity 摘要大小，与 AOSP `incremental::kDigestSize` 一致。
const DIGEST_SIZE: usize = 32;

/// 每个 verity 树块中包含的摘要数量。
const HASHES_PER_BLOCK: usize = BLOCK_SIZE / DIGEST_SIZE;

/// 响应块类型。
const BLOCK_TYPE_DATA: i8 = 0;
const BLOCK_TYPE_HASH: i8 = 1;

/// 压缩类型。
const COMPRESSION_NONE: i8 = 0;
const COMPRESSION_LZ4: i8 = 1;

/// ZIP / APK 优先级块解析常量，与 AOSP `incremental_utils.cpp` 一致。
const ZIP_EOCD_REC_MIN_SIZE: usize = 22;
const ZIP_EOCD_REC_SIG: u32 = 0x0605_4b50;
const ZIP_EOCD_CENTRAL_DIR_SIZE_OFFSET: usize = 12;
const ZIP_EOCD_COMMENT_LENGTH_OFFSET: usize = 20;
const APK_SIG_BLOCK_MIN_SIZE: usize = 32;
const APK_SIG_BLOCK_FOOTER_SIZE: usize = 24;
const APK_SIG_BLOCK_MAGIC_LO: i64 = 0x2067_6953_204b_5041;
const APK_SIG_BLOCK_MAGIC_HI: i64 = 0x3234_206b_636f_6c42;
const MAX_ZIP_COMMENT_SIZE: usize = 64 * 1024;

/// `.idsig` 文件解析结果。
#[derive(Debug)]
#[allow(dead_code)]
struct IdSigInfo {
    /// 需要透传给 `install-incremental` 的 base64 签名原始字节。
    signature: Vec<u8>,
    /// verity 树在 `.idsig` 文件中的起始偏移。
    tree_offset: u64,
    /// verity 树大小（字节）。
    tree_size: u64,
}

/// 检查给定文件列表是否可以走增量安装路径。
/// AOSP `incremental::can_install` 要求每个文件可访问，且 APK 必须有对应的 `.idsig` 文件。
pub fn can_install(files: &[PathBuf]) -> bool {
    for file in files {
        if !file.exists() {
            return false;
        }
        if is_apk(file) && !idsig_path(file).exists() {
            return false;
        }
    }
    true
}

/// 执行增量安装的入口。
///
/// 若文件不满足增量安装条件，调用方应在检查 `can_install` 后自行降级；
/// 若成功发起增量安装并等待到设备返回 `Success`，返回 `Ok(())`。
/// 若设备返回 `Failure` 或子进程异常结束，返回错误，与 AOSP 行为一致。
pub fn install(
    endpoint: &crate::client::ServerEndpoint,
    selector: &crate::client::TransportSelector,
    files: &[PathBuf],
    passthrough_args: &[String],
    wait: bool,
) -> Result<()> {
    let mut command_args = vec!["package".to_string(), "install-incremental".to_string()];
    command_args.extend_from_slice(passthrough_args);

    for (id, file) in files.iter().enumerate() {
        let metadata = fs::metadata(file).map_err(|err| {
            AdbError::Io(io::Error::new(
                err.kind(),
                format!("adb: failed to stat input file {}: {}", file.display(), err),
            ))
        })?;
        let size = metadata.len();
        let id_sig = parse_id_sig(file, size)?;
        let encoded_signature = BASE64_STANDARD.encode(&id_sig.signature);
        let basename = file
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_desc = format!("{}:{}:{}:{}:1", basename, size, id, encoded_signature);
        command_args.push(file_desc);
    }

    let service = format!("abb_exec:{}", command_args.join("\0"));
    let connection = crate::client::open_device_service(endpoint, selector, &service)?;

    spawn_incremental_server(connection, files, wait)
}

#[cfg(unix)]
fn spawn_incremental_server(
    connection: crate::client::ServerStream,
    files: &[PathBuf],
    wait: bool,
) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let (mut output_read, output_write) = UnixStream::pair().map_err(AdbError::Io)?;

    let connection_fd = connection.as_raw_fd();
    let output_write_fd = output_write.as_raw_fd();

    let adb_path = std::env::current_exe().map_err(AdbError::Io)?;
    let mut command = Command::new(adb_path);
    command
        .arg("inc-server")
        .arg(connection_fd.to_string())
        .arg(output_write_fd.to_string());
    for file in files {
        command.arg(file.as_os_str());
    }
    command.stdin(Stdio::null());

    unsafe {
        command.pre_exec(move || {
            clear_fd_cloexec(connection_fd)?;
            clear_fd_cloexec(output_write_fd)?;
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|err| {
        AdbError::Io(io::Error::new(
            err.kind(),
            format!("adb: failed to spawn incremental server: {}", err),
        ))
    })?;

    // 子进程继承后，父进程关闭自己的副本。
    drop(connection);
    drop(output_write);

    let result = wait_for_installation(&mut output_read).map_err(AdbError::Io)?;
    drop(output_read);

    match result {
        InstallResult::Success => {
            if wait {
                let _ = child.wait().map_err(AdbError::Io)?;
            } else {
                // 与 AOSP 一致：客户端退出，inc-server 继续在后台发送数据。
                // 用一个独立线程 reap 子进程，避免僵尸。
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Ok(())
        }
        InstallResult::Failure | InstallResult::None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(AdbError::Io(io::Error::other(
                "adb: install command failed",
            )))
        }
    }
}

#[cfg(windows)]
fn spawn_incremental_server(
    connection: crate::client::ServerStream,
    files: &[PathBuf],
    wait: bool,
) -> Result<()> {
    use std::os::windows::io::{AsRawSocket, FromRawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, INFINITE, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
        WaitForSingleObject,
    };

    let connection_handle = connection.as_raw_socket();
    unsafe {
        if SetHandleInformation(
            connection_handle as HANDLE,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        ) == 0
        {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
    }

    let mut pipe_read: HANDLE = INVALID_HANDLE_VALUE;
    let mut pipe_write: HANDLE = INVALID_HANDLE_VALUE;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    unsafe {
        if CreatePipe(&mut pipe_read, &mut pipe_write, &sa, 0) == 0 {
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
        if SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            let _ = CloseHandle(pipe_read);
            let _ = CloseHandle(pipe_write);
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
        if SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0) == 0 {
            let _ = CloseHandle(pipe_read);
            let _ = CloseHandle(pipe_write);
            return Err(AdbError::Io(io::Error::last_os_error()));
        }
    }

    let adb_path = std::env::current_exe().map_err(AdbError::Io)?;
    let adb_path_str = adb_path.as_os_str().to_string_lossy().into_owned();
    let mut command_line = String::new();
    command_line.push_str(&quote_arg(&adb_path_str));
    command_line.push_str(" inc-server ");
    command_line.push_str(&connection_handle.to_string());
    command_line.push(' ');
    command_line.push_str(&(pipe_write as usize).to_string());
    for file in files {
        command_line.push(' ');
        command_line.push_str(&quote_arg(&file.to_string_lossy()));
    }

    let mut command_line_wide: Vec<u16> = command_line.encode_utf16().collect();
    command_line_wide.push(0);

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let success = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1, // bInheritHandles
            0,
            std::ptr::null_mut(),
            std::ptr::null(),
            &startup_info,
            &mut process_info,
        )
    };

    // 子进程继承后，父进程关闭自己的副本。
    drop(connection);
    unsafe {
        let _ = CloseHandle(pipe_write);
    }

    if success == 0 {
        unsafe {
            let _ = CloseHandle(pipe_read);
        }
        return Err(AdbError::Io(io::Error::last_os_error()));
    }

    let mut pipe_read_file = unsafe { File::from_raw_handle(pipe_read as _) };
    let result = wait_for_installation(&mut pipe_read_file).map_err(AdbError::Io)?;
    drop(pipe_read_file);

    unsafe {
        match result {
            InstallResult::Success => {
                // 与 AOSP 一致：客户端退出，inc-server 继续在后台运行；
                // 若用户指定 `--wait`，则等待子进程结束。
                if wait {
                    let _ = WaitForSingleObject(process_info.hProcess, INFINITE);
                }
                let _ = CloseHandle(process_info.hProcess);
                let _ = CloseHandle(process_info.hThread);
                Ok(())
            }
            InstallResult::Failure | InstallResult::None => {
                let _ = TerminateProcess(process_info.hProcess, 1);
                let _ = WaitForSingleObject(process_info.hProcess, INFINITE);
                let _ = CloseHandle(process_info.hProcess);
                let _ = CloseHandle(process_info.hThread);
                Err(AdbError::Io(io::Error::other(
                    "adb: install command failed",
                )))
            }
        }
    }
}

#[cfg(windows)]
fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quote = arg.contains(' ') || arg.contains('\t') || arg.contains('"');
    if !needs_quote {
        return arg.to_string();
    }
    let mut s = String::with_capacity(arg.len() + 2);
    s.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else {
            if c == '"' {
                s.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = 0;
        }
        s.push(c);
    }
    s.extend(std::iter::repeat_n('\\', backslashes));
    s.push('"');
    s
}

#[cfg(unix)]
fn clear_fd_cloexec(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 子进程安装结果。
enum InstallResult {
    Success,
    Failure,
    None,
}

/// 从子进程输出中读取，直到识别出 `Success`、`Failure[...]` 或 EOF。
/// 读取的字节会实时透传给 stdout。
fn wait_for_installation<R: Read>(reader: &mut R) -> io::Result<InstallResult> {
    let mut output = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        std::io::stdout().write_all(&buf[..n])?;
        output.extend_from_slice(&buf[..n]);

        let text = String::from_utf8_lossy(&output);
        if text.contains("Success") {
            return Ok(InstallResult::Success);
        }
        if let Some(start) = text.find("Failure [") {
            const MAX_FAILURE_LEN: usize = 256;
            let after = &text[start + "Failure [".len()..];
            if after.contains(']') || output.len() >= MAX_FAILURE_LEN {
                return Ok(InstallResult::Failure);
            }
        }
    }
    Ok(InstallResult::None)
}

/// `inc-server` 入口：从命令行拿到连接 fd、输出 fd 和文件列表后，
/// 按增量安装协议向设备推送 fs-verity 树块和数据块，并响应设备的
/// `PREFETCH`/`BLOCK_MISSING`/`SERVING_COMPLETE`/`DESTROY` 请求。
#[cfg(unix)]
pub fn serve(connection_fd: i32, output_fd: i32, paths: &[PathBuf]) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    let mut connection = InheritedSocket {
        file: unsafe { File::from_raw_fd(connection_fd) },
    };
    let mut output = unsafe { File::from_raw_fd(output_fd) };
    serve_streams(&mut connection, &mut output, paths)
}

#[cfg(windows)]
pub fn serve(connection_handle: usize, output_handle: usize, paths: &[PathBuf]) -> Result<()> {
    use std::os::windows::io::{FromRawHandle, FromRawSocket, RawHandle, RawSocket};

    ensure_wsa_startup().map_err(AdbError::Io)?;
    let mut connection =
        unsafe { std::net::TcpStream::from_raw_socket(connection_handle as RawSocket) };
    let mut output = unsafe { File::from_raw_handle(output_handle as RawHandle) };
    serve_streams(&mut connection, &mut output, paths)
}

#[cfg(windows)]
fn ensure_wsa_startup() -> io::Result<()> {
    use std::sync::Once;
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};

    const WSA_VERSION: u16 = 0x0202; // MAKEWORD(2, 2)

    static START: Once = Once::new();
    static mut ERROR_CODE: i32 = 0;
    START.call_once(|| unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        ERROR_CODE = WSAStartup(WSA_VERSION, &mut data);
    });
    unsafe {
        if ERROR_CODE == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(ERROR_CODE))
        }
    }
}

fn serve_streams(
    connection: &mut dyn IncrementalConnection,
    output: &mut File,
    paths: &[PathBuf],
) -> Result<()> {
    use std::collections::VecDeque;

    let mut files = Vec::with_capacity(paths.len());
    for (id, path) in paths.iter().enumerate() {
        files.push(IncrementalFile::open(id as i16, path)?);
    }

    // 初始握手。
    connection
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(AdbError::Io)?;
    connection.write_all(b"OKAY").map_err(AdbError::Io)?;
    connection.flush().map_err(AdbError::Io)?;

    let mut prefetches = VecDeque::<PrefetchState>::new();
    let mut incoming = Vec::<u8>::new();
    let mut done_sent = false;
    let mut prefetched_files = std::collections::HashSet::<i16>::new();

    loop {
        // 批量推送预取块。
        if !done_sent {
            send_prefetches(connection, &mut files, &mut prefetches)?;

            if prefetches.is_empty() && all_data_blocks_sent(&files) {
                send_done(connection)?;
                done_sent = true;
            }
        }

        // 轮询/读取设备请求。
        match read_request_chunk(connection, &mut incoming)? {
            ReadResult::Data(0) => break,
            ReadResult::Data(_) => {}
            ReadResult::WouldBlock => {
                if done_sent && prefetches.is_empty() {
                    // 再给设备 50ms 发送最终响应，然后退出。
                    match read_request_chunk(connection, &mut incoming)? {
                        ReadResult::WouldBlock => break,
                        ReadResult::Data(0) => break,
                        ReadResult::Data(_) => {}
                    }
                }
                continue;
            }
        }

        if process_incoming(
            &mut incoming,
            &mut files,
            &mut prefetches,
            &mut prefetched_files,
            output,
            connection,
        )? {
            break;
        }
    }

    // 把剩余非协议输出透传给父进程。
    output.write_all(&incoming).map_err(AdbError::Io)?;
    output.flush().map_err(AdbError::Io)?;
    Ok(())
}

trait IncrementalConnection: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl IncrementalConnection for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }
}

#[cfg(unix)]
struct InheritedSocket {
    file: File,
}

#[cfg(unix)]
impl Read for InheritedSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

#[cfg(unix)]
impl Write for InheritedSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
impl IncrementalConnection for InheritedSocket {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let timeout = timeout.unwrap_or_default();
        // libc 对 musl 的过渡期 time_t 别名带弃用标记，但 timeval 仍要求该精确类型。
        #[allow(deprecated)]
        let max_timeout_seconds = libc::time_t::MAX;
        let value = libc::timeval {
            tv_sec: timeout.as_secs().try_into().unwrap_or(max_timeout_seconds),
            tv_usec: timeout.subsec_micros().into(),
        };
        let result = unsafe {
            libc::setsockopt(
                self.file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&value as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn read_request_chunk(
    connection: &mut dyn IncrementalConnection,
    incoming: &mut Vec<u8>,
) -> io::Result<ReadResult> {
    let mut buf = [0u8; 8192];
    match connection.read(&mut buf) {
        Ok(0) => Ok(ReadResult::Data(0)),
        Ok(n) => {
            incoming.extend_from_slice(&buf[..n]);
            Ok(ReadResult::Data(n))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            Ok(ReadResult::WouldBlock)
        }
        Err(e) => Err(e),
    }
}

enum ReadResult {
    Data(usize),
    WouldBlock,
}

fn send_prefetches(
    connection: &mut dyn IncrementalConnection,
    files: &mut [IncrementalFile],
    prefetches: &mut std::collections::VecDeque<PrefetchState>,
) -> Result<()> {
    const BLOCKS_PER_ITER: usize = 128;
    let mut sent = 0;
    while sent < BLOCKS_PER_ITER && !prefetches.is_empty() {
        if let Some((file_id, block_idx)) = prefetches.front_mut().and_then(|p| p.next(files)) {
            if send_data_block(
                files,
                file_id,
                block_idx as i32,
                /*flush=*/ false,
                connection,
            )? {
                sent += 1;
            }
        } else {
            prefetches.pop_front();
        }
    }
    Ok(())
}

#[allow(dead_code)]
struct IncrementalFile {
    id: i16,
    size: u64,
    apk: File,
    idsig: File,
    tree_offset: u64,
    sent_blocks: Vec<bool>,
    sent_tree_blocks: Vec<bool>,
    priority_blocks: Vec<usize>,
}

impl IncrementalFile {
    fn open(id: i16, path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(AdbError::Io)?;
        let size = metadata.len();
        let id_sig = parse_id_sig(path, size)?;
        let apk = File::open(path).map_err(AdbError::Io)?;
        let idsig = File::open(idsig_path(path)).map_err(AdbError::Io)?;
        let data_blocks = num_blocks_for_size(size);
        let tree_blocks = verity_tree_blocks_for_file(size);
        let priority_blocks = priority_blocks_for_apk(path, size);
        Ok(Self {
            id,
            size,
            apk,
            idsig,
            tree_offset: id_sig.tree_offset,
            sent_blocks: vec![false; data_blocks],
            sent_tree_blocks: vec![false; tree_blocks],
            priority_blocks,
        })
    }

    fn read_data_block(
        &mut self,
        block_idx: usize,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> io::Result<usize> {
        self.apk
            .seek(SeekFrom::Start(block_idx as u64 * BLOCK_SIZE as u64))?;
        self.apk.read(buf)
    }

    fn read_tree_block(
        &mut self,
        block_idx: usize,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> io::Result<usize> {
        self.idsig.seek(SeekFrom::Start(
            self.tree_offset + block_idx as u64 * BLOCK_SIZE as u64,
        ))?;
        self.idsig.read(buf)
    }
}

#[derive(Debug)]
struct PrefetchState {
    file_id: i16,
    overall_index: usize,
    overall_end: usize,
    priority_index: usize,
}

impl PrefetchState {
    fn whole(file: &IncrementalFile) -> Self {
        Self {
            file_id: file.id,
            overall_index: 0,
            overall_end: file.sent_blocks.len(),
            priority_index: 0,
        }
    }

    fn range(file_id: i16, start: usize, end: usize) -> Self {
        Self {
            file_id,
            overall_index: start,
            overall_end: end,
            priority_index: 0,
        }
    }

    fn next(&mut self, files: &mut [IncrementalFile]) -> Option<(i16, usize)> {
        let file = files.iter_mut().find(|f| f.id == self.file_id)?;

        // 先发送 ZIP/APK 安装优先级块。
        while self.priority_index < file.priority_blocks.len() {
            let idx = file.priority_blocks[self.priority_index];
            self.priority_index += 1;
            if idx < file.sent_blocks.len() && !file.sent_blocks[idx] {
                return Some((self.file_id, idx));
            }
        }

        while self.overall_index < self.overall_end {
            let idx = self.overall_index;
            self.overall_index += 1;
            if !file.sent_blocks[idx] {
                return Some((self.file_id, idx));
            }
        }
        None
    }
}

fn all_data_blocks_sent(files: &[IncrementalFile]) -> bool {
    files.iter().all(|f| f.sent_blocks.iter().all(|&sent| sent))
}

fn send_data_block(
    files: &mut [IncrementalFile],
    file_id: i16,
    block_idx: i32,
    flush: bool,
    connection: &mut dyn IncrementalConnection,
) -> Result<bool> {
    let file = match files.iter_mut().find(|f| f.id == file_id) {
        Some(f) => f,
        None => return Ok(false),
    };
    let block_idx = block_idx as usize;
    if block_idx >= file.sent_blocks.len() || file.sent_blocks[block_idx] {
        return Ok(false);
    }

    send_tree_blocks_for_data_block(file, block_idx as i32, connection)?;

    let mut buf = [0u8; BLOCK_SIZE];
    let n = file
        .read_data_block(block_idx, &mut buf)
        .map_err(AdbError::Io)?;
    let data = &buf[..n];

    let (payload, compression) = if let Some(compressed) = compress_data_block(data) {
        (compressed, COMPRESSION_LZ4)
    } else {
        (data.to_vec(), COMPRESSION_NONE)
    };

    send_block(
        connection,
        file_id,
        BLOCK_TYPE_DATA,
        block_idx as i32,
        compression,
        &payload,
    )?;
    file.sent_blocks[block_idx] = true;
    if flush {
        connection.flush().map_err(AdbError::Io)?;
    }
    Ok(true)
}

fn compress_data_block(data: &[u8]) -> Option<Vec<u8>> {
    // AOSP 只在压缩后大小小于原数据 95% 时才使用 LZ4。
    let threshold = (data.len() as f64 * 0.95) as usize;
    if threshold == 0 {
        return None;
    }
    let compressed = lz4_compress(data);
    if compressed.is_empty() || compressed.len() >= threshold {
        return None;
    }
    Some(compressed)
}

/// 计算 APK 文件的优先级数据块索引列表，与 AOSP `PriorityBlocksForFile` 行为一致。
/// 非 APK、解析失败或缺少 APK 签名块时返回空列表。
fn priority_blocks_for_apk(path: &Path, file_size: u64) -> Vec<usize> {
    if !is_apk(path) {
        return Vec::new();
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let signer_offset = match central_dir_offset(&mut file, file_size)
        .and_then(|cd| signer_block_offset(&mut file, cd))
    {
        Ok(Some(off)) => off,
        _ => return Vec::new(),
    };

    let mut blocks: Vec<usize> = zip_priority_blocks(signer_offset, file_size)
        .into_iter()
        .map(|b| b as usize)
        .collect();

    if let Ok(install_blocks) = installation_priority_blocks(path, file_size) {
        blocks.extend(install_blocks.into_iter().map(|b| b as usize));
    }

    unduplicate(&mut blocks);
    blocks
}

/// 从 ZIP 文件尾部搜索 EOCD，返回 central directory 起始偏移。
fn central_dir_offset(file: &mut File, file_size: u64) -> io::Result<u64> {
    if (file_size as usize) < ZIP_EOCD_REC_MIN_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }
    let max_eocd_offset = file_size - ZIP_EOCD_REC_MIN_SIZE as u64;

    let mut eocd_offset = None;
    for comment_len in 0..file_size as usize {
        let pos = max_eocd_offset - comment_len as u64;
        let sig = read_u32_at(file, pos)?;
        if sig == ZIP_EOCD_REC_SIG {
            let stored_comment_len =
                read_u16_at(file, pos + ZIP_EOCD_COMMENT_LENGTH_OFFSET as u64)? as u64;
            if stored_comment_len == comment_len as u64 {
                eocd_offset = Some(pos);
                break;
            }
        }
    }

    let eocd_offset =
        eocd_offset.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EOCD not found"))?;
    let cd_len = read_u32_at(file, eocd_offset + ZIP_EOCD_CENTRAL_DIR_SIZE_OFFSET as u64)? as u64;
    Ok(eocd_offset - cd_len)
}

/// 根据 central directory 偏移定位 APK Signing Block 起始偏移。
fn signer_block_offset(file: &mut File, cd_offset: u64) -> io::Result<Option<u64>> {
    if cd_offset < APK_SIG_BLOCK_MIN_SIZE as u64 {
        return Ok(None);
    }
    let lo = read_i64_at(file, cd_offset - 2 * size_of::<i64>() as u64)?;
    let hi = read_i64_at(file, cd_offset - size_of::<i64>() as u64)?;
    if lo != APK_SIG_BLOCK_MAGIC_LO || hi != APK_SIG_BLOCK_MAGIC_HI {
        return Ok(None);
    }

    let signer_size_in_footer = read_u32_at(file, cd_offset - APK_SIG_BLOCK_FOOTER_SIZE as u64)?;
    let signer_block_offset =
        cd_offset as i64 - signer_size_in_footer as i64 - size_of::<i64>() as i64;
    if signer_block_offset < 0 {
        return Ok(None);
    }
    let signer_block_offset = signer_block_offset as u64;

    let signer_size_in_header = read_u32_at(file, signer_block_offset)?;
    if signer_size_in_footer != signer_size_in_header {
        return Ok(None);
    }

    Ok(Some(signer_block_offset))
}

/// APK 签名块到文件末尾的块按 EOCD 搜索优先顺序排列，最后追加第 0 块。
fn zip_priority_blocks(signer_block_offset: u64, file_size: u64) -> Vec<i32> {
    let signer_block_index = offset_to_block_index(signer_block_offset as i64);
    let last_block_index = offset_to_block_index(file_size as i64);
    let num_priority_blocks = last_block_index - signer_block_index + 1;

    let mut blocks = Vec::new();
    let k_num_blocks_in_eocd_search = MAX_ZIP_COMMENT_SIZE / BLOCK_SIZE + 1;

    if num_priority_blocks > k_num_blocks_in_eocd_search as i32 {
        append_blocks(
            last_block_index - k_num_blocks_in_eocd_search as i32 + 1,
            k_num_blocks_in_eocd_search as i32,
            &mut blocks,
        );
        append_blocks(
            signer_block_index,
            num_priority_blocks - k_num_blocks_in_eocd_search as i32,
            &mut blocks,
        );
    } else {
        append_blocks(signer_block_index, num_priority_blocks, &mut blocks);
    }

    append_blocks(0, 1, &mut blocks);
    blocks
}

/// 遍历 ZIP 条目，收集安装阶段需要优先传输的块。
fn installation_priority_blocks(path: &Path, _file_size: u64) -> io::Result<Vec<i32>> {
    use zip::read::HasZipMetadata;

    let file = File::open(path)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut blocks = Vec::new();
    for i in 0..archive.len() {
        let entry = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name();
        let is_match = (name.starts_with("lib/") && name.ends_with(".so"))
            || name == "resources.arsc"
            || name == "AndroidManifest.xml"
            || name == "classes.dex";
        if !is_match {
            continue;
        }

        let start_offset = entry.header_start() as i64;
        if name == "classes.dex" {
            append_blocks(offset_to_block_index(start_offset), 2, &mut blocks);
            continue;
        }

        let data_len = if entry.compression() == zip::CompressionMethod::Stored {
            entry.size()
        } else {
            entry.compressed_size()
        };
        let data_descriptor_len = if entry.get_metadata().using_data_descriptor {
            16
        } else {
            0
        };
        let end_offset = start_offset + data_len as i64 + data_descriptor_len as i64;
        let start_block = offset_to_block_index(start_offset);
        let end_block = offset_to_block_index(end_offset);
        let count = end_block - start_block + 1;
        append_blocks(start_block, count, &mut blocks);
    }

    Ok(blocks)
}

fn offset_to_block_index(offset: i64) -> i32 {
    ((offset & !(BLOCK_SIZE as i64 - 1)) >> 12) as i32
}

fn append_blocks(start: i32, count: i32, blocks: &mut Vec<i32>) {
    if count <= 0 {
        return;
    }
    if count == 1 {
        blocks.push(start);
    } else {
        blocks.extend(start..start + count);
    }
}

fn unduplicate<T: std::hash::Hash + Eq + Copy>(v: &mut Vec<T>) {
    let mut seen = std::collections::HashSet::with_capacity(v.len());
    v.retain(|&x| seen.insert(x));
}

fn read_u32_at(file: &mut File, offset: u64) -> io::Result<u32> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u16_at(file: &mut File, offset: u64) -> io::Result<u16> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 2];
    file.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_i64_at(file: &mut File, offset: u64) -> io::Result<i64> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

fn send_tree_blocks_for_data_block(
    file: &mut IncrementalFile,
    block_idx: i32,
    connection: &mut dyn IncrementalConnection,
) -> Result<()> {
    if file.sent_tree_blocks.is_empty() {
        return Ok(());
    }
    let data_block_count = file.sent_blocks.len();
    let total_nodes = file.sent_tree_blocks.len();
    let leaf_nodes = data_block_count.div_ceil(HASHES_PER_BLOCK);
    let leaf_offset = total_nodes.saturating_sub(leaf_nodes);

    // 单个数据块请求触发对应的叶子树块。
    let block_idx = block_idx as usize;
    let leaf_idx = leaf_offset + block_idx / HASHES_PER_BLOCK;
    if leaf_idx < total_nodes && !file.sent_tree_blocks[leaf_idx] {
        send_tree_block(file, leaf_idx as i32, connection)?;
        file.sent_tree_blocks[leaf_idx] = true;
    }

    // 非叶子节点只需发送一次。
    if leaf_offset > 0 && !file.sent_tree_blocks[0] {
        for i in 0..leaf_offset {
            if !file.sent_tree_blocks[i] {
                send_tree_block(file, i as i32, connection)?;
                file.sent_tree_blocks[i] = true;
            }
        }
    }
    Ok(())
}

fn send_tree_block(
    file: &mut IncrementalFile,
    block_idx: i32,
    connection: &mut dyn IncrementalConnection,
) -> Result<()> {
    let mut buf = [0u8; BLOCK_SIZE];
    let n = file
        .read_tree_block(block_idx as usize, &mut buf)
        .map_err(AdbError::Io)?;
    send_block(
        connection,
        file.id,
        BLOCK_TYPE_HASH,
        block_idx,
        COMPRESSION_NONE,
        &buf[..n],
    )
}

fn send_block(
    connection: &mut dyn IncrementalConnection,
    file_id: i16,
    block_type: i8,
    block_idx: i32,
    compression_type: i8,
    data: &[u8],
) -> Result<()> {
    let mut header = [0u8; 10];
    write_be_i16(&mut header[0..2], file_id);
    header[2] = block_type as u8;
    header[3] = compression_type as u8;
    write_be_i32(&mut header[4..8], block_idx);
    write_be_i16(&mut header[8..10], data.len() as i16);

    let chunk_len = (header.len() + data.len()) as i32;
    connection
        .write_all(&chunk_len.to_be_bytes())
        .map_err(AdbError::Io)?;
    connection.write_all(&header).map_err(AdbError::Io)?;
    connection.write_all(data).map_err(AdbError::Io)?;
    Ok(())
}

fn send_done(connection: &mut dyn IncrementalConnection) -> Result<()> {
    let mut header = [0u8; 10];
    write_be_i16(&mut header[0..2], -1i16);
    header[2] = 0;
    header[3] = 0;
    write_be_i32(&mut header[4..8], 0);
    write_be_i16(&mut header[8..10], 0);

    let chunk_len = header.len() as i32;
    connection
        .write_all(&chunk_len.to_be_bytes())
        .map_err(AdbError::Io)?;
    connection.write_all(&header).map_err(AdbError::Io)?;
    connection.flush().map_err(AdbError::Io)?;
    Ok(())
}

fn process_incoming(
    buffer: &mut Vec<u8>,
    files: &mut [IncrementalFile],
    prefetches: &mut std::collections::VecDeque<PrefetchState>,
    prefetched_files: &mut std::collections::HashSet<i16>,
    output: &mut File,
    connection: &mut dyn IncrementalConnection,
) -> Result<bool> {
    loop {
        let magic_pos = find_incr_magic(buffer);
        match magic_pos {
            Some(pos) => {
                if pos > 0 {
                    output.write_all(&buffer[..pos]).map_err(AdbError::Io)?;
                    buffer.drain(..pos);
                }
                if buffer.len() < 12 {
                    // 请求不完整，保留到下次。
                    return Ok(false);
                }
                let request = parse_request(&buffer[4..12]);
                buffer.drain(..12);
                if handle_request(request, files, prefetches, prefetched_files, connection)? {
                    return Ok(true);
                }
            }
            None => {
                // 避免把 INCR magic 拆分到两次 read 中。
                if buffer.len() > 3 {
                    let keep = buffer.split_off(buffer.len() - 3);
                    output.write_all(buffer).map_err(AdbError::Io)?;
                    *buffer = keep;
                }
                return Ok(false);
            }
        }
    }
}

fn find_incr_magic(buffer: &[u8]) -> Option<usize> {
    if buffer.len() < 4 {
        return None;
    }
    buffer
        .windows(4)
        .position(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]) == INCR_MAGIC)
}

fn parse_request(bytes: &[u8]) -> RequestCommand {
    RequestCommand {
        request_type: i16::from_be_bytes([bytes[0], bytes[1]]),
        file_id: i16::from_be_bytes([bytes[2], bytes[3]]),
        block_idx: i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

#[derive(Debug)]
struct RequestCommand {
    request_type: i16,
    file_id: i16,
    block_idx: i32,
}

fn handle_request(
    request: RequestCommand,
    files: &mut [IncrementalFile],
    prefetches: &mut std::collections::VecDeque<PrefetchState>,
    prefetched_files: &mut std::collections::HashSet<i16>,
    connection: &mut dyn IncrementalConnection,
) -> Result<bool> {
    match request.request_type {
        REQUEST_TYPE_DESTROY => return Ok(true),
        REQUEST_TYPE_SERVING_COMPLETE => {
            // 设备已收到所需全部块，继续读取最终输出。
        }
        REQUEST_TYPE_BLOCK_MISSING => {
            if let Some(file) = files.iter().find(|f| f.id == request.file_id) {
                let block_idx = request.block_idx as usize;
                let sent_blocks_len = file.sent_blocks.len();
                if block_idx < sent_blocks_len {
                    // 只有真正发出该块时才追加后续相邻块预取。
                    if send_data_block(
                        files,
                        request.file_id,
                        request.block_idx,
                        /*flush=*/ true,
                        connection,
                    )? {
                        let end = sent_blocks_len.min(block_idx + 8);
                        if block_idx + 1 < end {
                            prefetches.push_front(PrefetchState::range(
                                request.file_id,
                                block_idx + 1,
                                end,
                            ));
                        }
                    }
                }
            }
        }
        REQUEST_TYPE_PREFETCH => {
            if let Some(file) = files.iter().find(|f| f.id == request.file_id)
                && prefetched_files.insert(request.file_id)
            {
                prefetches.push_back(PrefetchState::whole(file));
            }
        }
        _ => {}
    }
    Ok(false)
}

const INCR_MAGIC: u32 = 0x494e_4352;
const REQUEST_TYPE_SERVING_COMPLETE: i16 = 0;
const REQUEST_TYPE_BLOCK_MISSING: i16 = 1;
const REQUEST_TYPE_PREFETCH: i16 = 2;
const REQUEST_TYPE_DESTROY: i16 = 3;

fn write_be_i16(buf: &mut [u8], value: i16) {
    buf.copy_from_slice(&value.to_be_bytes());
}

fn write_be_i32(buf: &mut [u8], value: i32) {
    buf.copy_from_slice(&value.to_be_bytes());
}

fn is_apk(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.eq_ignore_ascii_case("apk"))
        .unwrap_or(false)
}

fn idsig_path(apk: &Path) -> PathBuf {
    let mut path = apk.as_os_str().to_os_string();
    path.push(IDSIG_SUFFIX);
    PathBuf::from(path)
}

/// 解析 `.idsig` 文件头，返回签名内容和 verity 树偏移/大小。
fn parse_id_sig(apk: &Path, apk_size: u64) -> Result<IdSigInfo> {
    let path = idsig_path(apk);
    let mut file = File::open(&path).map_err(|err| {
        AdbError::Io(io::Error::new(
            err.kind(),
            format!("Failed to open signature file {}: {}", path.display(), err),
        ))
    })?;

    let mut signature = Vec::new();

    // version: 4 bytes little-endian.
    let version = read_i32_le(&mut file)?;
    signature.extend_from_slice(&version.to_le_bytes());

    // hashingInfo: 4 bytes little-endian size + bytes.
    append_bytes_with_size(&mut file, &mut signature)?;

    // signingInfo: 4 bytes little-endian size + bytes。
    append_bytes_with_size(&mut file, &mut signature)?;

    // tree_size: 4 bytes little-endian.
    let tree_size = read_i32_le(&mut file)?;
    let tree_offset = file.stream_position().map_err(|err| {
        AdbError::Io(io::Error::new(
            err.kind(),
            "failed to get stream position".to_string(),
        ))
    })?;

    let expected_tree_size = verity_tree_size_for_file(apk_size) as i32;
    if tree_size != expected_tree_size {
        return Err(AdbError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Verity tree size mismatch in signature file: {} [was {}, expected {}]",
                path.display(),
                tree_size,
                expected_tree_size
            ),
        )));
    }

    Ok(IdSigInfo {
        signature,
        tree_offset,
        tree_size: tree_size as u64,
    })
}

fn read_i32_le(file: &mut File) -> Result<i32> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf).map_err(|err| {
        AdbError::Io(io::Error::new(err.kind(), "failed to read i32".to_string()))
    })?;
    Ok(i32::from_le_bytes(buf))
}

/// 读取 `[size][data]` 并将 size+data 追加到 `out`，返回 data 结束后的文件偏移。
fn append_bytes_with_size(file: &mut File, out: &mut Vec<u8>) -> Result<u64> {
    let le_size = read_i32_le(file)?;
    if le_size < 0 {
        return Err(AdbError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "negative size in idsig header",
        )));
    }
    let size = le_size as usize;
    out.extend_from_slice(&le_size.to_le_bytes());
    let mut buf = vec![0u8; size];
    file.read_exact(&mut buf).map_err(|err| {
        AdbError::Io(io::Error::new(
            err.kind(),
            "failed to read idsig bytes".to_string(),
        ))
    })?;
    out.extend_from_slice(&buf);

    let pos = file.stream_position().map_err(|err| {
        AdbError::Io(io::Error::new(
            err.kind(),
            "failed to get stream position".to_string(),
        ))
    })?;
    Ok(pos)
}

fn num_blocks_for_size(size: u64) -> usize {
    if size == 0 {
        return 0;
    }
    (size as usize).div_ceil(BLOCK_SIZE)
}

fn verity_tree_blocks_for_file(file_size: u64) -> usize {
    if file_size == 0 {
        return 0;
    }
    let mut total = 0usize;
    let mut hash_block_count = num_blocks_for_size(file_size);
    while hash_block_count > 1 {
        hash_block_count = hash_block_count.div_ceil(HASHES_PER_BLOCK);
        total += hash_block_count;
    }
    total
}

fn verity_tree_size_for_file(file_size: u64) -> u64 {
    verity_tree_blocks_for_file(file_size) as u64 * BLOCK_SIZE as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    use lz4_flex::block::decompress as lz4_decompress;

    #[test]
    fn can_install_requires_idsig_for_apk() {
        let dir = std::env::temp_dir().join(format!(
            "adb_rust_incremental_can_install_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let apk = dir.join("app.apk");
        fs::write(&apk, b"fake apk").unwrap();
        assert!(
            !can_install(std::slice::from_ref(&apk)),
            "apk without idsig should fail"
        );

        fs::write(idsig_path(&apk), b"fake idsig").unwrap();
        assert!(can_install(&[apk]), "apk with idsig should succeed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verity_tree_blocks_matches_aosp() {
        // 空文件。
        assert_eq!(verity_tree_blocks_for_file(0), 0);
        // 正好一个数据块：不需要树块（只有一个哈希时无需向上汇总）。
        assert_eq!(verity_tree_blocks_for_file(BLOCK_SIZE as u64), 0);
        // 两个数据块：需要一个叶子块保存两个摘要，若该叶子块仍 >1 则继续汇总。
        // 2 个摘要占 64 字节，一个叶子块即可，无需再上层，因此 1。
        assert_eq!(verity_tree_blocks_for_file(BLOCK_SIZE as u64 * 2), 1);
        // 129 个数据块：需要 2 个叶子块；2 个摘要需 1 个上层块，共 3。
        assert_eq!(verity_tree_blocks_for_file(BLOCK_SIZE as u64 * 129), 3);
    }

    #[test]
    fn parse_id_sig_extracts_signature_and_tree_offset() {
        let dir = std::env::temp_dir().join(format!(
            "adb_rust_incremental_parse_id_sig_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let apk = dir.join("app.apk");
        let idsig = dir.join("app.apk.idsig");
        fs::write(&apk, vec![0u8; BLOCK_SIZE * 2]).unwrap();

        // 构造一个最小合法 idsig：version + hashingInfo(size=0) + signingInfo(size=0) + tree_size.
        let mut data = Vec::new();
        data.extend_from_slice(&1i32.to_le_bytes()); // version
        data.extend_from_slice(&0i32.to_le_bytes()); // hashingInfo size
        let signing_info = b"signing";
        data.extend_from_slice(&(signing_info.len() as i32).to_le_bytes());
        data.extend_from_slice(signing_info);
        let tree_size = verity_tree_size_for_file(BLOCK_SIZE as u64 * 2) as i32;
        data.extend_from_slice(&tree_size.to_le_bytes());
        // 补齐 tree_size 字节的假 verity 树。
        data.extend_from_slice(&vec![0u8; tree_size as usize]);
        fs::write(&idsig, &data).unwrap();

        let info = parse_id_sig(&apk, BLOCK_SIZE as u64 * 2).unwrap();
        assert_eq!(info.signature.len(), 4 + 4 + 4 + signing_info.len());
        assert_eq!(info.tree_size, tree_size as u64);
        assert_eq!(
            info.tree_offset,
            (4 + 4 + 4 + signing_info.len() + 4) as u64
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn data_block_lz4_roundtrip() {
        // 全零块可被 LZ4 显著压缩，应满足阈值并使用 COMPRESSION_LZ4。
        let zeros = vec![0u8; BLOCK_SIZE];
        let compressed = compress_data_block(&zeros).expect("zeros should compress");
        assert!(
            compressed.len() < zeros.len(),
            "compressed zeros should be smaller"
        );
        let decompressed = lz4_decompress(&compressed, zeros.len()).unwrap();
        assert_eq!(decompressed, zeros);

        // 随机高熵数据通常不满足 95% 阈值，应保持未压缩路径。
        let random: Vec<u8> = (0..BLOCK_SIZE).map(|_| rand::random::<u8>()).collect();
        assert!(
            compress_data_block(&random).is_none(),
            "random data should not be compressed under AOSP threshold"
        );
    }

    #[cfg(unix)]
    #[test]
    fn zip_priority_blocks_matches_aosp_shape() {
        // signer block 起始于第 3 块中间（偏移 0x3500），文件共 10 块大小。
        let signer_offset = 0x3500i64;
        let file_size = BLOCK_SIZE as i64 * 10;
        let blocks = zip_priority_blocks(signer_offset as u64, file_size as u64);

        // 应包含从 signer block 到文件末尾的所有块，且最后追加第 0 块。
        let signer_index = offset_to_block_index(signer_offset);
        let last_index = offset_to_block_index(file_size);
        let expected_len = (last_index - signer_index + 1 + 1) as usize;
        assert_eq!(blocks.len(), expected_len);
        assert_eq!(blocks[blocks.len() - 1], 0);
        assert!(blocks.contains(&signer_index));
        assert!(blocks.contains(&last_index));
    }

    #[cfg(unix)]
    #[test]
    fn append_blocks_and_unduplicate_keep_order() {
        let mut v = Vec::new();
        append_blocks(5, 3, &mut v);
        append_blocks(7, 2, &mut v);
        assert_eq!(v, vec![5, 6, 7, 7, 8]);
        unduplicate(&mut v);
        assert_eq!(v, vec![5, 6, 7, 8]);
    }

    #[cfg(unix)]
    #[test]
    fn priority_blocks_for_apk_collects_install_entries() {
        let dir = std::env::temp_dir().join(format!(
            "adb_rust_incremental_priority_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let apk = build_test_apk(&dir.join("test.apk"));

        let blocks = priority_blocks_for_apk(&apk, fs::metadata(&apk).unwrap().len());

        // 至少包含第 0 块、签名块区域以及安装优先级条目所在块。
        assert!(!blocks.is_empty(), "priority blocks should not be empty");
        assert!(blocks.contains(&0), "should include block 0");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn prefetch_state_sends_priority_blocks_first() {
        let dir = std::env::temp_dir().join(format!(
            "adb_rust_incremental_prefetch_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let apk = build_test_apk(&dir.join("test.apk"));
        let apk_size = fs::metadata(&apk).unwrap().len();
        build_test_idsig(&apk, apk_size);

        let mut file = IncrementalFile::open(0, &apk).unwrap();
        assert!(
            !file.priority_blocks.is_empty(),
            "should have priority blocks"
        );

        // 将第 0 块标记为已发送，验证 PrefetchState 会跳过它并继续后续优先级块。
        file.sent_blocks[0] = true;

        let mut state = PrefetchState::whole(&file);
        let mut collected = Vec::new();
        while let Some((_, idx)) = state.next(std::slice::from_mut(&mut file)) {
            collected.push(idx);
            file.sent_blocks[idx] = true;
        }

        assert!(!collected.is_empty(), "should collect at least one block");
        // 前几个应为非 0 的优先级块（签名块区域/安装条目）。
        assert_ne!(
            collected[0], 0,
            "priority blocks should not start with already-sent block 0"
        );
        // 最终覆盖所有未发送块。
        assert!(
            file.sent_blocks.iter().all(|&s| s),
            "all blocks should be consumed"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn build_test_idsig(apk: &Path, apk_size: u64) {
        let idsig = idsig_path(apk);
        let tree_size = verity_tree_size_for_file(apk_size) as i32;
        let mut data = Vec::new();
        data.extend_from_slice(&1i32.to_le_bytes()); // version
        data.extend_from_slice(&0i32.to_le_bytes()); // hashingInfo size
        data.extend_from_slice(&0i32.to_le_bytes()); // signingInfo size
        data.extend_from_slice(&tree_size.to_le_bytes());
        data.extend_from_slice(&vec![0u8; tree_size as usize]);
        fs::write(&idsig, &data).unwrap();
    }

    #[cfg(unix)]
    fn build_test_apk(path: &Path) -> PathBuf {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);

        // 写入安装阶段需要优先读取的条目。
        writer.start_file("classes.dex", options).unwrap();
        writer.write_all(&vec![0u8; BLOCK_SIZE / 2]).unwrap();

        writer.start_file("AndroidManifest.xml", options).unwrap();
        writer.write_all(&vec![0u8; BLOCK_SIZE * 2]).unwrap();

        writer.start_file("resources.arsc", options).unwrap();
        writer.write_all(&vec![0u8; BLOCK_SIZE]).unwrap();

        writer.add_directory("lib/", options).unwrap();
        writer
            .start_file("lib/arm64-v8a/libfoo.so", options)
            .unwrap();
        writer.write_all(&vec![0u8; BLOCK_SIZE * 3 / 2]).unwrap();

        writer.finish().unwrap();

        // 在 central directory 前插入 APK signing block，使其被识别为合法 APK。
        let data = fs::read(path).unwrap();
        let (eocd_pos, cd_pos, _cd_size) = find_zip_eocd(&data).expect("valid EOCD");

        let signing_block = build_apk_signing_block();
        let signing_block_len = signing_block.len();

        // 插入 signing block：保留 local data， central directory + EOCD 后移。
        let mut new_data = Vec::with_capacity(data.len() + signing_block_len);
        new_data.extend_from_slice(&data[..cd_pos]);
        new_data.extend_from_slice(&signing_block);
        new_data.extend_from_slice(&data[cd_pos..]);

        // 更新 EOCD 中的 central directory offset。
        let new_eocd_pos = eocd_pos + signing_block_len;
        let new_cd_pos = (cd_pos + signing_block_len) as u64;
        new_data[new_eocd_pos + 16..new_eocd_pos + 20]
            .copy_from_slice(&(new_cd_pos as u32).to_le_bytes());

        fs::write(path, &new_data).unwrap();
        path.to_path_buf()
    }

    #[cfg(unix)]
    fn find_zip_eocd(data: &[u8]) -> Option<(usize, usize, u32)> {
        if data.len() < ZIP_EOCD_REC_MIN_SIZE {
            return None;
        }
        let max_pos = data.len() - ZIP_EOCD_REC_MIN_SIZE;
        for comment_len in 0..=max_pos {
            let pos = max_pos - comment_len;
            let sig = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            if sig == ZIP_EOCD_REC_SIG {
                let stored = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                if stored == comment_len {
                    let cd_size = u32::from_le_bytes([
                        data[pos + 12],
                        data[pos + 13],
                        data[pos + 14],
                        data[pos + 15],
                    ]);
                    let cd_offset = u32::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                    ]) as usize;
                    return Some((pos, cd_offset, cd_size));
                }
            }
        }
        None
    }

    #[cfg(unix)]
    fn build_apk_signing_block() -> Vec<u8> {
        let magic = b"APK Sig Block 42";
        // signing block size 不包含第一个 8 字节 size 字段，与 AOSP 一致。
        let size = (8 + magic.len()) as u64;
        let mut block = Vec::with_capacity(8 + size as usize);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(magic);
        block
    }
}
