use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use crate::client::{self, ServerEndpoint, ServerStream, TransportSelector};
use crate::error::{AdbError, Result};
use crate::transport;
use filetime::{FileTime, set_file_mtime};

pub const SYNC_DATA_MAX: usize = 64 * 1024;

const SYNC_PATH_MAX: usize = 1024;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

const ID_LSTAT_V1: u32 = mkid(*b"STAT");
const ID_STAT_V2: u32 = mkid(*b"STA2");
const ID_LSTAT_V2: u32 = mkid(*b"LST2");
const ID_LIST_V1: u32 = mkid(*b"LIST");
const ID_LIST_V2: u32 = mkid(*b"LIS2");
const ID_DENT_V1: u32 = mkid(*b"DENT");
const ID_DENT_V2: u32 = mkid(*b"DNT2");
const ID_SEND_V1: u32 = mkid(*b"SEND");
const ID_SEND_V2: u32 = mkid(*b"SND2");
const ID_RECV_V1: u32 = mkid(*b"RECV");
const ID_RECV_V2: u32 = mkid(*b"RCV2");
const ID_DONE: u32 = mkid(*b"DONE");
const ID_DATA: u32 = mkid(*b"DATA");
const ID_OKAY: u32 = mkid(*b"OKAY");
const ID_FAIL: u32 = mkid(*b"FAIL");
const ID_QUIT: u32 = mkid(*b"QUIT");

const SYNC_DENT_V1_REMAINING_AFTER_HEADER: usize = 12;
const SYNC_DENT_V2_REMAINING_AFTER_HEADER: usize = 68;
const SYNC_FLAG_DRY_RUN: u32 = 0x8000_0000;
const SYNC_FLAG_BROTLI: u32 = 1;
const SYNC_FLAG_LZ4: u32 = 2;
const SYNC_FLAG_ZSTD: u32 = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferSummary {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
}

impl TransferSummary {
    pub fn add(&mut self, other: TransferSummary) {
        self.files += other.files;
        self.bytes += other.bytes;
        self.skipped += other.skipped;
    }
}

/// 传输方向，用于最终 summary 文案。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Push,
    Pull,
}

/// 进度回调接口。实现者负责把进度行渲染到合适的输出。
pub trait ProgressTracker {
    /// 报告当前文件传输进度。
    ///
    /// `copied` 为已传输字节，`total` 为当前文件总字节（可能为 0）。
    /// `expect_multiple_files` 为 true 时显示当前文件百分比，
    /// 否则只显示文件名与全局百分比。
    fn report_progress(&mut self, file: &str, copied: u64, total: u64, expect_multiple_files: bool);

    /// 报告传输完成后的速率 summary。
    fn report_transfer_rate(
        &mut self,
        name: &str,
        files: u64,
        skipped: u64,
        bytes: u64,
        direction: TransferDirection,
        start: Instant,
    );

    /// 是否抑制 INFO 级别输出（对应 `-q`）。
    fn set_quiet(&mut self, quiet: bool);
}

/// 空进度实现，默认用于不需要进度的场景。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProgress;

impl ProgressTracker for NoProgress {
    fn report_progress(&mut self, _file: &str, _copied: u64, _total: u64, _expect_multiple: bool) {}

    fn report_transfer_rate(
        &mut self,
        _name: &str,
        _files: u64,
        _skipped: u64,
        _bytes: u64,
        _direction: TransferDirection,
        _start: Instant,
    ) {
    }

    fn set_quiet(&mut self, _quiet: bool) {}
}

/// 包装 Write，在写入时定期调用 ProgressTracker。
struct ProgressWriter<'a, W> {
    writer: W,
    tracker: &'a mut dyn ProgressTracker,
    file: &'a str,
    total: u64,
    copied: u64,
    expect_multiple_files: bool,
    last_report: Instant,
}

impl<'a, W> ProgressWriter<'a, W> {
    fn new(
        writer: W,
        tracker: &'a mut dyn ProgressTracker,
        file: &'a str,
        total: u64,
        expect_multiple_files: bool,
    ) -> Self {
        Self {
            writer,
            tracker,
            file,
            total,
            copied: 0,
            expect_multiple_files,
            last_report: Instant::now() - Duration::from_millis(200),
        }
    }

    fn maybe_report(&mut self) {
        if self.last_report.elapsed() >= Duration::from_millis(100) {
            self.tracker.report_progress(
                self.file,
                self.copied,
                self.total,
                self.expect_multiple_files,
            );
            self.last_report = Instant::now();
        }
    }

    fn finish(self) {
        self.tracker.report_progress(
            self.file,
            self.copied,
            self.total,
            self.expect_multiple_files,
        );
    }
}

impl<W: Write> Write for ProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.copied += n as u64;
        self.maybe_report();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushOptions {
    pub sync: bool,
    pub dry_run: bool,
    pub compression: SyncCompression,
    pub expect_multiple_files: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullOptions {
    pub preserve_attrs: bool,
    pub compression: SyncCompression,
    pub expect_multiple_files: bool,
}

impl Default for PushOptions {
    fn default() -> Self {
        Self {
            sync: false,
            dry_run: false,
            compression: SyncCompression::Any,
            expect_multiple_files: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectorySyncOptions {
    pub list_only: bool,
    pub dry_run: bool,
    pub compression: SyncCompression,
    pub expect_multiple_files: bool,
}

impl Default for DirectorySyncOptions {
    fn default() -> Self {
        Self {
            list_only: false,
            dry_run: false,
            compression: SyncCompression::Any,
            expect_multiple_files: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectorySyncResult {
    pub summary: TransferSummary,
    pub would_push: Vec<PlannedPush>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPush {
    pub local: PathBuf,
    pub remote: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyncCompression {
    #[default]
    None,
    Any,
    Brotli,
    Lz4,
    Zstd,
}

impl SyncCompression {
    fn sync_flag(self) -> u32 {
        match self {
            SyncCompression::None | SyncCompression::Any => 0,
            SyncCompression::Brotli => SYNC_FLAG_BROTLI,
            SyncCompression::Lz4 => SYNC_FLAG_LZ4,
            SyncCompression::Zstd => SYNC_FLAG_ZSTD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: Option<String>,
    pub mode: u32,
    pub size: u64,
    pub mtime: u32,
    pub attrs: Option<RemoteEntryAttrs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteEntryAttrs {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

impl RemoteEntry {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    fn should_pull_file(&self) -> bool {
        matches!(self.mode & S_IFMT, S_IFREG | S_IFBLK | S_IFCHR)
    }
}

pub struct SyncClient<S: Write> {
    stream: S,
    features: SyncFeatures,
    closed: bool,
}

impl SyncClient<ServerStream> {
    pub fn connect(endpoint: &ServerEndpoint, selector: &TransportSelector) -> Result<Self> {
        let features = SyncFeatures::detect(endpoint, selector);
        let stream = client::open_device_service(endpoint, selector, "sync:")?;
        Ok(Self {
            stream,
            features,
            closed: false,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SyncFeatures {
    stat_v2: bool,
    ls_v2: bool,
    sendrecv_v2: bool,
    sendrecv_v2_dry_run: bool,
    sendrecv_v2_brotli: bool,
    sendrecv_v2_lz4: bool,
    sendrecv_v2_zstd: bool,
}

impl SyncFeatures {
    fn detect(endpoint: &ServerEndpoint, selector: &TransportSelector) -> Self {
        let service = format!("{}:features", selector.host_prefix());
        match client::query(endpoint, &service) {
            Ok(features) => Self::from_feature_string(&features),
            Err(_) => Self::default(),
        }
    }

    fn from_feature_string(features: &str) -> Self {
        Self {
            stat_v2: transport::can_use_feature(features, "stat_v2"),
            ls_v2: transport::can_use_feature(features, "ls_v2"),
            sendrecv_v2: transport::can_use_feature(features, "sendrecv_v2"),
            sendrecv_v2_dry_run: transport::can_use_feature(features, "sendrecv_v2_dry_run_send"),
            sendrecv_v2_brotli: transport::can_use_feature(features, "sendrecv_v2_brotli"),
            sendrecv_v2_lz4: transport::can_use_feature(features, "sendrecv_v2_lz4"),
            sendrecv_v2_zstd: transport::can_use_feature(features, "sendrecv_v2_zstd"),
        }
    }

    fn resolve_compression(self, requested: SyncCompression) -> SyncCompression {
        match requested {
            SyncCompression::Any if self.sendrecv_v2_zstd => SyncCompression::Zstd,
            SyncCompression::Any if self.sendrecv_v2_lz4 => SyncCompression::Lz4,
            SyncCompression::Any if self.sendrecv_v2_brotli => SyncCompression::Brotli,
            SyncCompression::Any => SyncCompression::None,
            other => other,
        }
    }
}

impl<S: Write> SyncClient<S> {
    pub fn quit(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        write_request(&mut self.stream, ID_QUIT, "")
    }
}

impl<S> SyncClient<S>
where
    S: Read + Write,
{
    pub fn stat(&mut self, remote: &str) -> Result<Option<RemoteEntry>> {
        let request_id = if self.features.stat_v2 {
            ID_LSTAT_V2
        } else {
            ID_LSTAT_V1
        };
        write_request(&mut self.stream, request_id, remote)?;
        let (id, mode) = read_header(&mut self.stream)?;
        if self.features.stat_v2 {
            return self.read_stat_v2(id, mode);
        }
        if id == ID_FAIL {
            return Err(read_fail(&mut self.stream, mode));
        }
        if id != ID_LSTAT_V1 {
            return Err(unexpected_id("STAT", id));
        }

        let size = read_u32(&mut self.stream)?;
        let mtime = read_u32(&mut self.stream)?;
        if mode == 0 && size == 0 && mtime == 0 {
            return Ok(None);
        }

        Ok(Some(RemoteEntry {
            name: None,
            mode,
            size: u64::from(size),
            mtime,
            attrs: None,
        }))
    }

    pub fn stat_follow(&mut self, remote: &str) -> Result<Option<RemoteEntry>> {
        if self.features.stat_v2 {
            write_request(&mut self.stream, ID_STAT_V2, remote)?;
            let (id, error) = read_header(&mut self.stream)?;
            return self.read_stat_v2(id, error);
        }

        let Some(mut entry) = self.stat(remote)? else {
            return Ok(None);
        };
        if !entry.is_symlink() {
            return Ok(Some(entry));
        }

        let dir_probe = remote_join(remote, "");
        if let Ok(Some(dir_entry)) = self.stat(&dir_probe)
            && dir_entry.is_dir()
        {
            entry.mode = (entry.mode & !S_IFMT) | S_IFDIR;
            entry.size = 0;
            return Ok(Some(entry));
        }

        entry.mode = (entry.mode & !S_IFMT) | S_IFREG;
        entry.size = 0;
        Ok(Some(entry))
    }

    pub fn list(&mut self, remote: &str) -> Result<Vec<RemoteEntry>> {
        let request_id = if self.features.ls_v2 {
            ID_LIST_V2
        } else {
            ID_LIST_V1
        };
        write_request(&mut self.stream, request_id, remote)?;
        let mut entries = Vec::new();

        loop {
            let (id, mode_or_len) = read_header(&mut self.stream)?;
            if self.features.ls_v2 {
                match id {
                    ID_DONE => {
                        skip_exact(&mut self.stream, SYNC_DENT_V2_REMAINING_AFTER_HEADER)?;
                        return Ok(entries);
                    }
                    ID_FAIL => return Err(read_fail(&mut self.stream, mode_or_len)),
                    ID_DENT_V2 => {
                        let entry = read_dent_v2_after_header(&mut self.stream, mode_or_len)?;
                        if let Some(entry) = entry {
                            entries.push(entry);
                        }
                    }
                    other => return Err(unexpected_id("DNT2/DONE", other)),
                }
                continue;
            }

            match id {
                ID_DONE => {
                    skip_exact(&mut self.stream, SYNC_DENT_V1_REMAINING_AFTER_HEADER)?;
                    return Ok(entries);
                }
                ID_FAIL => return Err(read_fail(&mut self.stream, mode_or_len)),
                ID_DENT_V1 => {
                    let size = read_u32(&mut self.stream)?;
                    let mtime = read_u32(&mut self.stream)?;
                    let name_len = read_u32(&mut self.stream)? as usize;
                    if name_len > 255 {
                        return Err(AdbError::Protocol(format!(
                            "sync 文件名过长: {name_len} > 255"
                        )));
                    }

                    let name = read_string(&mut self.stream, name_len)?;
                    if name.contains('/') || name.contains('\\') {
                        return Err(AdbError::Protocol(format!(
                            "sync 目录项包含路径分隔符: {name:?}"
                        )));
                    }
                    if name == "." || name == ".." {
                        continue;
                    }

                    entries.push(RemoteEntry {
                        name: Some(name),
                        mode: mode_or_len,
                        size: u64::from(size),
                        mtime,
                        attrs: None,
                    });
                }
                other => return Err(unexpected_id("DENT/DONE", other)),
            }
        }
    }

    pub fn send_file(
        &mut self,
        local: &Path,
        remote: &str,
        options: PushOptions,
        progress: &mut dyn ProgressTracker,
    ) -> Result<TransferSummary> {
        let (metadata, is_symlink) = local_push_metadata(local)?;
        if !metadata.is_file() && !is_symlink {
            return Err(AdbError::Usage(format!(
                "push 目前只能发送普通文件或符号链接: {}",
                local.display()
            )));
        }

        let mode = file_mode(&metadata);
        let mtime = file_mtime(&metadata);
        if options.sync && self.remote_matches_push_sync(remote, mtime)? {
            return Ok(TransferSummary {
                files: 0,
                bytes: 0,
                skipped: 1,
            });
        }
        if options.dry_run && !self.features.sendrecv_v2_dry_run {
            return Err(AdbError::FileSync(
                "dry-run not supported by the device".to_string(),
            ));
        }
        let compression = if self.features.sendrecv_v2 {
            self.features.resolve_compression(options.compression)
        } else {
            SyncCompression::None
        };

        if self.features.sendrecv_v2 {
            let mut flags = compression.sync_flag();
            if options.dry_run {
                flags |= SYNC_FLAG_DRY_RUN;
            }
            write_send_v2_request(&mut self.stream, remote, mode, flags)?;
        } else {
            let spec = format!("{remote},{mode}");
            write_request(&mut self.stream, ID_SEND_V1, &spec)?;
        }

        let tracker: &mut dyn ProgressTracker = progress;

        let bytes = if is_symlink {
            let payload = read_link_payload(local)?;
            let total = payload.len() as u64;
            let mut progress_writer = ProgressWriter::new(
                &mut self.stream,
                tracker,
                remote,
                total,
                options.expect_multiple_files,
            );
            write_file_data(
                &mut progress_writer,
                &mut payload.as_slice(),
                SyncCompression::None,
            )?;
            progress_writer.finish();
            total
        } else {
            let mut file = File::open(local)?;
            let total = metadata.len();
            let mut progress_writer = ProgressWriter::new(
                &mut self.stream,
                tracker,
                remote,
                total,
                options.expect_multiple_files,
            );
            write_file_data(&mut progress_writer, &mut file, compression)?;
            progress_writer.finish();
            total
        };

        write_header(&mut self.stream, ID_DONE, mtime)?;
        read_status(&mut self.stream)?;
        Ok(TransferSummary {
            files: 1,
            bytes,
            skipped: 0,
        })
    }

    pub fn recv_file(
        &mut self,
        remote: &str,
        local: &Path,
        entry: &RemoteEntry,
        options: PullOptions,
        progress: &mut dyn ProgressTracker,
    ) -> Result<TransferSummary> {
        let compression = if self.features.sendrecv_v2 {
            self.features.resolve_compression(options.compression)
        } else {
            SyncCompression::None
        };

        if self.features.sendrecv_v2 {
            write_recv_v2_request(&mut self.stream, remote, compression.sync_flag())?;
        } else {
            write_request(&mut self.stream, ID_RECV_V1, remote)?;
        }

        let mut file = File::create(local)?;
        let total = entry.size;
        let mut progress_writer = ProgressWriter::new(
            &mut file,
            progress,
            remote,
            total,
            options.expect_multiple_files,
        );
        let bytes = read_file_data(&mut self.stream, &mut progress_writer, compression)?;
        progress_writer.finish();

        if options.preserve_attrs {
            set_pull_attrs(local, entry)?;
        }
        Ok(TransferSummary {
            files: 1,
            bytes,
            skipped: 0,
        })
    }

    fn read_stat_v2(&mut self, id: u32, error: u32) -> Result<Option<RemoteEntry>> {
        if id == ID_FAIL {
            return Err(read_fail(&mut self.stream, error));
        }
        if id != ID_LSTAT_V2 && id != ID_STAT_V2 {
            return Err(unexpected_id("LST2/STA2", id));
        }

        let dev = read_u64(&mut self.stream)?;
        let ino = read_u64(&mut self.stream)?;
        let mode = read_u32(&mut self.stream)?;
        let nlink = read_u32(&mut self.stream)?;
        let uid = read_u32(&mut self.stream)?;
        let gid = read_u32(&mut self.stream)?;
        let size = read_u64(&mut self.stream)?;
        let atime = read_i64(&mut self.stream)?;
        let mtime = read_i64(&mut self.stream)?;
        let ctime = read_i64(&mut self.stream)?;

        if error != 0 {
            if error == 2 {
                return Ok(None);
            }
            return Err(AdbError::Server(format!(
                "remote stat failed: {}",
                wire_errno_text(error)
            )));
        }

        Ok(Some(RemoteEntry {
            name: None,
            mode,
            size,
            mtime: sync_time_to_u32(mtime),
            attrs: Some(RemoteEntryAttrs {
                dev,
                ino,
                nlink,
                uid,
                gid,
                atime,
                mtime,
                ctime,
            }),
        }))
    }

    fn remote_matches_push_sync(&mut self, remote: &str, local_mtime: u32) -> Result<bool> {
        let Some(remote_entry) = self.stat(remote)? else {
            return Ok(false);
        };
        Ok(!remote_entry.is_dir() && remote_entry.mtime == local_mtime)
    }

    fn remote_matches_directory_sync(
        &mut self,
        remote: &str,
        metadata: &fs::Metadata,
        local_mtime: u32,
    ) -> Result<bool> {
        let Some(remote_entry) = self.stat(remote)? else {
            return Ok(false);
        };
        Ok(!remote_entry.is_dir()
            && remote_entry.size == metadata.len()
            && remote_entry.mtime == local_mtime)
    }
}

impl<S: Write> Drop for SyncClient<S> {
    fn drop(&mut self) {
        let _ = self.quit();
    }
}

pub fn push(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    sources: &[PathBuf],
    remote: &str,
    options: PushOptions,
    progress: Option<&mut dyn ProgressTracker>,
) -> Result<TransferSummary> {
    if sources.is_empty() {
        return Err(push_requires_args_error());
    }

    let mut sync = SyncClient::connect(endpoint, selector)?;
    let remote_info = sync.stat(remote)?;
    let remote_is_dir = remote_info.as_ref().is_some_and(RemoteEntry::is_dir);
    if sources.len() > 1 && !remote_is_dir {
        return Err(AdbError::Server(format!(
            "target '{remote}' is not a directory"
        )));
    }

    let mut fallback = NoProgress;
    let tracker: &mut dyn ProgressTracker = progress.unwrap_or(&mut fallback);

    let mut summary = TransferSummary::default();
    for source in sources {
        let (metadata, is_symlink) = local_push_metadata(source)?;
        if metadata.is_dir() {
            if remote_info.is_some() && !remote_is_dir {
                return Err(AdbError::Server(format!(
                    "target '{remote}' is not a directory"
                )));
            }
            let remote_root = if remote_is_dir {
                remote_join(remote, &local_basename(source)?)
            } else {
                remote.trim_end_matches('/').to_string()
            };
            push_dir(
                &mut sync,
                endpoint,
                selector,
                source,
                &remote_root,
                options,
                &mut summary,
                tracker,
            )?;
        } else if metadata.is_file() || is_symlink {
            let remote_path = if remote_is_dir {
                remote_join(remote, &local_basename(source)?)
            } else {
                remote.to_string()
            };
            summary.add(sync.send_file(source, &remote_path, options, tracker)?);
        } else {
            warn_skipping_special_file(&source.to_string_lossy(), file_mode(&metadata));
        }
    }

    let _ = sync.quit();
    Ok(summary)
}

pub fn pull(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    remotes: &[String],
    local: &Path,
    options: PullOptions,
    progress: Option<&mut dyn ProgressTracker>,
) -> Result<TransferSummary> {
    if remotes.is_empty() {
        return Err(pull_requires_arg_error());
    }

    let mut sync = SyncClient::connect(endpoint, selector)?;
    let local_exists = local.exists();
    let local_is_dir = local_exists && local.is_dir();
    if remotes.len() > 1 && !local_is_dir {
        return Err(AdbError::Server(format!(
            "target '{}' is not a directory",
            local.display()
        )));
    }

    let mut fallback = NoProgress;
    let tracker: &mut dyn ProgressTracker = progress.unwrap_or(&mut fallback);

    let mut summary = TransferSummary::default();
    for remote in remotes {
        let entry = sync
            .stat_follow(remote)?
            .ok_or_else(|| AdbError::Server(format!("remote object '{remote}' does not exist")))?;

        if entry.is_dir() {
            if local_exists && !local_is_dir {
                return Err(AdbError::Server(format!(
                    "target '{}' is not a directory",
                    local.display()
                )));
            }
            let local_dir = if local_exists {
                local.join(remote_basename(remote)?)
            } else {
                local.to_path_buf()
            };
            pull_dir(
                &mut sync,
                remote,
                &local_dir,
                &entry,
                options,
                &mut summary,
                tracker,
            )?;
        } else if entry.should_pull_file() || entry.is_symlink() {
            let local_file = if local_is_dir {
                local.join(remote_basename(remote)?)
            } else {
                local.to_path_buf()
            };
            summary.add(sync.recv_file(remote, &local_file, &entry, options, tracker)?);
        } else {
            warn_skipping_special_file(remote, entry.mode);
        }
    }

    let _ = sync.quit();
    Ok(summary)
}

fn push_requires_args_error() -> AdbError {
    AdbError::Usage("push requires <source> and <destination> arguments".to_string())
}

fn pull_requires_arg_error() -> AdbError {
    AdbError::Usage("pull requires an argument".to_string())
}

pub fn ls(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    remote: &str,
) -> Result<Vec<RemoteEntry>> {
    let mut sync = SyncClient::connect(endpoint, selector)?;
    let entries = sync.list(remote)?;
    let _ = sync.quit();
    Ok(entries)
}

pub fn sync_dir(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    local_dir: &Path,
    remote_dir: &str,
    options: DirectorySyncOptions,
    progress: Option<&mut dyn ProgressTracker>,
) -> Result<DirectorySyncResult> {
    if !local_dir.is_dir() {
        return Err(AdbError::Usage(format!(
            "sync 本地目录不存在: {}",
            local_dir.display()
        )));
    }

    let mut fallback = NoProgress;
    let tracker: &mut dyn ProgressTracker = progress.unwrap_or(&mut fallback);

    let mut sync = SyncClient::connect(endpoint, selector)?;
    let mut result = DirectorySyncResult::default();
    sync_dir_inner(
        &mut sync,
        endpoint,
        selector,
        local_dir,
        remote_dir,
        options,
        &mut result,
        tracker,
    )?;
    let _ = sync.quit();
    Ok(result)
}

pub fn format_ls_entry(entry: &RemoteEntry) -> String {
    format!(
        "{:08x} {:08x} {:08x} {}",
        entry.mode,
        entry.size,
        entry.mtime,
        entry.name.as_deref().unwrap_or("")
    )
}

#[allow(clippy::too_many_arguments)]
fn push_dir<S>(
    sync: &mut SyncClient<S>,
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    local_dir: &Path,
    remote_dir: &str,
    options: PushOptions,
    summary: &mut TransferSummary,
    progress: &mut dyn ProgressTracker,
) -> Result<()>
where
    S: Read + Write,
{
    if !options.dry_run {
        ensure_remote_dir(endpoint, selector, remote_dir)?;
    }

    for entry in fs::read_dir(local_dir)? {
        let entry = entry?;
        let path = entry.path();
        let (metadata, is_symlink) = local_push_metadata(&path)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let remote_child = remote_join(remote_dir, &name);

        if metadata.is_dir() {
            push_dir(
                sync,
                endpoint,
                selector,
                &path,
                &remote_child,
                options,
                summary,
                progress,
            )?;
        } else if metadata.is_file() || is_symlink {
            summary.add(sync.send_file(&path, &remote_child, options, progress)?);
        } else {
            warn_skipping_special_file(&path.to_string_lossy(), file_mode(&metadata));
            summary.skipped += 1;
        }
    }
    if !options.dry_run {
        set_remote_dir_attrs_best_effort(endpoint, selector, local_dir, remote_dir);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sync_dir_inner<S>(
    sync: &mut SyncClient<S>,
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    local_dir: &Path,
    remote_dir: &str,
    options: DirectorySyncOptions,
    result: &mut DirectorySyncResult,
    progress: &mut dyn ProgressTracker,
) -> Result<()>
where
    S: Read + Write,
{
    if !options.list_only && !options.dry_run {
        ensure_remote_dir(endpoint, selector, remote_dir)?;
    }

    for entry in sorted_local_entries(local_dir)? {
        let path = entry.path();
        let (metadata, is_symlink) = local_push_metadata(&path)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let remote_child = remote_join(remote_dir, &name);

        if metadata.is_dir() {
            sync_dir_inner(
                sync,
                endpoint,
                selector,
                &path,
                &remote_child,
                options,
                result,
                progress,
            )?;
        } else if metadata.is_file() || is_symlink {
            let mtime = file_mtime(&metadata);
            if sync.remote_matches_directory_sync(&remote_child, &metadata, mtime)? {
                result.summary.skipped += 1;
            } else if options.list_only {
                result.would_push.push(PlannedPush {
                    local: path,
                    remote: remote_child,
                });
            } else {
                result.summary.add(sync.send_file(
                    &path,
                    &remote_child,
                    PushOptions {
                        sync: false,
                        dry_run: options.dry_run,
                        compression: options.compression,
                        expect_multiple_files: options.expect_multiple_files,
                    },
                    progress,
                )?);
            }
        } else {
            warn_skipping_special_file(&path.to_string_lossy(), file_mode(&metadata));
            result.summary.skipped += 1;
        }
    }

    if !options.list_only && !options.dry_run {
        set_remote_dir_attrs_best_effort(endpoint, selector, local_dir, remote_dir);
    }
    Ok(())
}

fn sorted_local_entries(local_dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(local_dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn pull_dir<S>(
    sync: &mut SyncClient<S>,
    remote_dir: &str,
    local_dir: &Path,
    dir_entry: &RemoteEntry,
    options: PullOptions,
    summary: &mut TransferSummary,
    progress: &mut dyn ProgressTracker,
) -> Result<()>
where
    S: Read + Write,
{
    fs::create_dir_all(local_dir)?;
    for entry in sync.list(remote_dir)? {
        let name = entry
            .name
            .as_deref()
            .ok_or_else(|| AdbError::Protocol("LIST 目录项缺少名称".to_string()))?;
        let remote_child = remote_join(remote_dir, name);
        let local_child = local_dir.join(name);
        let resolved_entry = if entry.is_symlink() {
            match sync.stat_follow(&remote_child)? {
                Some(resolved) => resolved,
                None => continue,
            }
        } else {
            entry
        };

        if resolved_entry.is_dir() {
            pull_dir(
                sync,
                &remote_child,
                &local_child,
                &resolved_entry,
                options,
                summary,
                progress,
            )?;
        } else if resolved_entry.should_pull_file() || resolved_entry.is_symlink() {
            summary.add(sync.recv_file(
                &remote_child,
                &local_child,
                &resolved_entry,
                options,
                progress,
            )?);
        } else {
            warn_skipping_special_file(&remote_child, resolved_entry.mode);
            summary.skipped += 1;
        }
    }
    if options.preserve_attrs {
        set_pull_attrs(local_dir, dir_entry)?;
    }
    Ok(())
}

fn warn_skipping_special_file(path: &str, mode: u32) {
    eprintln!("adb: warning: skipping special file '{path}' (mode = 0o{mode:o})");
}

fn ensure_remote_dir(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    remote_dir: &str,
) -> Result<()> {
    let command = format!("mkdir -p {}", shell_quote(remote_dir));
    run_remote_shell(endpoint, selector, &command, "remote mkdir", remote_dir)
}

fn set_remote_dir_attrs_best_effort(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    local_dir: &Path,
    remote_dir: &str,
) {
    let Ok(metadata) = fs::metadata(local_dir) else {
        return;
    };
    let command = remote_dir_attrs_command(
        remote_dir,
        dir_permissions(&metadata),
        file_mtime(&metadata),
    );
    let _ = run_remote_shell(
        endpoint,
        selector,
        &command,
        "remote directory attrs",
        remote_dir,
    );
}

fn remote_dir_attrs_command(remote_dir: &str, mode: u32, mtime: u32) -> String {
    let remote = shell_quote(remote_dir);
    format!(
        "{{ chmod {:o} {remote}; }} >/dev/null 2>&1 || true; {{ touch -d @{mtime} {remote}; }} >/dev/null 2>&1 || true",
        mode & 0o777
    )
}

fn run_remote_shell(
    endpoint: &ServerEndpoint,
    selector: &TransportSelector,
    command: &str,
    action: &str,
    target: &str,
) -> Result<()> {
    match client::open_device_service(endpoint, selector, &format!("shell,v2,raw:{command}")) {
        Ok(stream) => {
            let output = client::stream_shell_v2_to_buffers(stream)?;
            if output.exit_code == 0 {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(AdbError::Server(format!(
                "{action} failed for {target}: {stderr}{stdout}"
            )))
        }
        Err(_) => {
            let stream =
                client::open_device_service(endpoint, selector, &format!("shell:{command}"))?;
            let _ = client::read_stream_to_bytes(stream)?;
            Ok(())
        }
    }
}

fn shell_quote(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

fn write_request<W: Write>(writer: &mut W, id: u32, path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if bytes.len() > SYNC_PATH_MAX {
        return Err(AdbError::Protocol(format!(
            "sync 路径过长: {} > {SYNC_PATH_MAX}",
            bytes.len()
        )));
    }
    write_header(writer, id, bytes.len() as u32)?;
    writer.write_all(bytes)?;
    Ok(())
}

fn write_send_v2_request<W: Write>(
    writer: &mut W,
    remote: &str,
    mode: u32,
    flags: u32,
) -> Result<()> {
    write_request(writer, ID_SEND_V2, remote)?;
    write_header(writer, ID_SEND_V2, mode)?;
    writer.write_all(&flags.to_le_bytes())?;
    Ok(())
}

fn write_recv_v2_request<W: Write>(writer: &mut W, remote: &str, flags: u32) -> Result<()> {
    write_request(writer, ID_RECV_V2, remote)?;
    write_header(writer, ID_RECV_V2, flags)?;
    Ok(())
}

fn write_file_data<W: Write, R: Read>(
    writer: &mut W,
    reader: &mut R,
    compression: SyncCompression,
) -> Result<()> {
    match compression {
        SyncCompression::None => {
            let mut framed = SyncDataWriter { writer };
            io::copy(reader, &mut framed)?;
            Ok(())
        }
        SyncCompression::Zstd => {
            let framed = SyncDataWriter { writer };
            let mut encoder = zstd::stream::write::Encoder::new(framed, 1)?;
            io::copy(reader, &mut encoder)?;
            encoder.finish()?;
            Ok(())
        }
        SyncCompression::Lz4 => {
            let framed = SyncDataWriter { writer };
            let mut encoder = lz4_flex::frame::FrameEncoder::new(framed);
            io::copy(reader, &mut encoder)?;
            encoder
                .finish()
                .map_err(|err| AdbError::Protocol(format!("lz4 压缩失败: {err}")))?;
            Ok(())
        }
        SyncCompression::Brotli => {
            let framed = SyncDataWriter { writer };
            let mut encoder = brotli::CompressorWriter::new(framed, SYNC_DATA_MAX, 1, 22);
            io::copy(reader, &mut encoder)?;
            encoder.flush()?;
            Ok(())
        }
        SyncCompression::Any => unreachable!("Any must be resolved first"),
    }
}

fn read_file_data<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    compression: SyncCompression,
) -> Result<u64> {
    match compression {
        SyncCompression::None => read_uncompressed_file_data(reader, writer),
        SyncCompression::Zstd => {
            let mut framed = SyncDataReader::new(reader);
            let bytes = {
                let mut decoder = zstd::stream::read::Decoder::new(&mut framed)?;
                io::copy(&mut decoder, writer)?
            };
            framed.consume_done()?;
            Ok(bytes)
        }
        SyncCompression::Lz4 => {
            let mut framed = SyncDataReader::new(reader);
            let bytes = {
                let mut decoder = lz4_flex::frame::FrameDecoder::new(&mut framed);
                io::copy(&mut decoder, writer)?
            };
            framed.consume_done()?;
            Ok(bytes)
        }
        SyncCompression::Brotli => {
            let mut framed = SyncDataReader::new(reader);
            let bytes = {
                let mut decoder = brotli::Decompressor::new(&mut framed, SYNC_DATA_MAX);
                io::copy(&mut decoder, writer)?
            };
            framed.consume_done()?;
            Ok(bytes)
        }
        SyncCompression::Any => unreachable!("Any must be resolved first"),
    }
}

fn read_uncompressed_file_data<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64> {
    let mut bytes = 0_u64;
    loop {
        let (id, size_or_len) = read_header(reader)?;
        match id {
            ID_DONE => break,
            ID_FAIL => return Err(read_fail(reader, size_or_len)),
            ID_DATA => {
                let size = size_or_len as usize;
                if size > SYNC_DATA_MAX {
                    return Err(AdbError::Protocol(format!(
                        "sync DATA 过大: {size} > {SYNC_DATA_MAX}"
                    )));
                }

                copy_exact(reader, writer, size)?;
                bytes += size as u64;
            }
            other => return Err(unexpected_id("DATA/DONE", other)),
        }
    }
    Ok(bytes)
}

struct SyncDataWriter<'a, W> {
    writer: &'a mut W,
}

impl<W: Write> Write for SyncDataWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(SYNC_DATA_MAX) {
            write_header(self.writer, ID_DATA, chunk.len() as u32).map_err(io::Error::other)?;
            self.writer.write_all(chunk)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct SyncDataReader<'a, R> {
    reader: &'a mut R,
    buffer: Vec<u8>,
    offset: usize,
    done: bool,
}

impl<'a, R> SyncDataReader<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            offset: 0,
            done: false,
        }
    }

    fn consume_done(&mut self) -> io::Result<()>
    where
        R: Read,
    {
        let mut discard = [0_u8; 4096];
        while self.read(&mut discard)? != 0 {}
        Ok(())
    }
}

impl<R: Read> Read for SyncDataReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if self.offset < self.buffer.len() {
                let available = self.buffer.len() - self.offset;
                let take = available.min(out.len());
                out[..take].copy_from_slice(&self.buffer[self.offset..self.offset + take]);
                self.offset += take;
                return Ok(take);
            }

            if self.done {
                return Ok(0);
            }

            let (id, size_or_len) = read_header(self.reader).map_err(io::Error::other)?;
            match id {
                ID_DONE => {
                    self.done = true;
                    return Ok(0);
                }
                ID_FAIL => {
                    let err = read_fail(self.reader, size_or_len);
                    return Err(io::Error::other(err));
                }
                ID_DATA => {
                    let size = size_or_len as usize;
                    if size > SYNC_DATA_MAX {
                        return Err(io::Error::other(AdbError::Protocol(format!(
                            "sync DATA 过大: {size} > {SYNC_DATA_MAX}"
                        ))));
                    }
                    self.buffer.resize(size, 0);
                    self.reader.read_exact(&mut self.buffer)?;
                    self.offset = 0;
                    if size == 0 {
                        continue;
                    }
                }
                other => return Err(io::Error::other(unexpected_id("DATA/DONE", other))),
            }
        }
    }
}

fn read_dent_v2_after_header<R: Read>(reader: &mut R, error: u32) -> Result<Option<RemoteEntry>> {
    let dev = read_u64(reader)?;
    let ino = read_u64(reader)?;
    let mode = read_u32(reader)?;
    let nlink = read_u32(reader)?;
    let uid = read_u32(reader)?;
    let gid = read_u32(reader)?;
    let size = read_u64(reader)?;
    let atime = read_i64(reader)?;
    let mtime = read_i64(reader)?;
    let ctime = read_i64(reader)?;
    let name_len = read_u32(reader)? as usize;
    if name_len > 255 {
        return Err(AdbError::Protocol(format!(
            "sync 文件名过长: {name_len} > 255"
        )));
    }

    let name = read_string(reader, name_len)?;
    if error != 0 || name == "." || name == ".." {
        return Ok(None);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(AdbError::Protocol(format!(
            "sync 目录项包含路径分隔符: {name:?}"
        )));
    }

    Ok(Some(RemoteEntry {
        name: Some(name),
        mode,
        size,
        mtime: sync_time_to_u32(mtime),
        attrs: Some(RemoteEntryAttrs {
            dev,
            ino,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
        }),
    }))
}

fn read_status<R: Read>(reader: &mut R) -> Result<()> {
    let (id, len) = read_header(reader)?;
    match id {
        ID_OKAY if len == 0 => Ok(()),
        ID_OKAY => Err(AdbError::Protocol(format!(
            "sync OKAY 携带了非零长度: {len}"
        ))),
        ID_FAIL => Err(read_fail(reader, len)),
        other => Err(unexpected_id("OKAY/FAIL", other)),
    }
}

fn read_fail<R: Read>(reader: &mut R, len: u32) -> AdbError {
    match read_string(reader, len as usize) {
        Ok(message) => AdbError::Server(format!("remote sync failed: {message}")),
        Err(err) => err,
    }
}

fn write_header<W: Write>(writer: &mut W, id: u32, value: u32) -> Result<()> {
    writer.write_all(&id.to_le_bytes())?;
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_header<R: Read>(reader: &mut R) -> Result<(u32, u32)> {
    let id = read_u32(reader)?;
    let value = read_u32(reader)?;
    Ok((id, value))
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut raw = [0_u8; 4];
    reader.read_exact(&mut raw)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut raw = [0_u8; 8];
    reader.read_exact(&mut raw)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_i64<R: Read>(reader: &mut R) -> Result<i64> {
    let mut raw = [0_u8; 8];
    reader.read_exact(&mut raw)?;
    Ok(i64::from_le_bytes(raw))
}

fn skip_exact<R: Read>(reader: &mut R, len: usize) -> Result<()> {
    let mut remaining = len;
    let mut buffer = [0_u8; 32];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..take])?;
        remaining -= take;
    }
    Ok(())
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, len: usize) -> Result<()> {
    let mut remaining = len;
    let mut buffer = vec![0_u8; len.min(8192)];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..take])?;
        writer.write_all(&buffer[..take])?;
        remaining -= take;
    }
    Ok(())
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|err| AdbError::Protocol(format!("sync 响应非 UTF-8: {err}")))
}

fn wire_errno_text(errno: u32) -> String {
    match errno {
        1 => "Operation not permitted".to_string(),
        2 => "No such file or directory".to_string(),
        5 => "I/O error".to_string(),
        13 => "Permission denied".to_string(),
        17 => "File exists".to_string(),
        20 => "Not a directory".to_string(),
        21 => "Is a directory".to_string(),
        28 => "No space left on device".to_string(),
        _ => format!("wire errno {errno}"),
    }
}

fn unexpected_id(expected: &str, id: u32) -> AdbError {
    AdbError::Protocol(format!(
        "sync 期望 {expected}，收到 {}",
        String::from_utf8_lossy(&id.to_le_bytes())
    ))
}

fn file_mtime(metadata: &fs::Metadata) -> u32 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs().min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

fn sync_time_to_u32(value: i64) -> u32 {
    value.clamp(0, i64::from(u32::MAX)) as u32
}

fn set_pull_attrs(local: &Path, entry: &RemoteEntry) -> Result<()> {
    set_file_mtime(local, FileTime::from_unix_time(pull_mtime_secs(entry), 0))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(local, fs::Permissions::from_mode(entry.mode & 0o777))?;
    }

    Ok(())
}

fn pull_mtime_secs(entry: &RemoteEntry) -> i64 {
    entry
        .attrs
        .map(|attrs| attrs.mtime)
        .unwrap_or_else(|| i64::from(entry.mtime))
}

fn read_link_payload(local: &Path) -> Result<Vec<u8>> {
    let target = fs::read_link(local)?;
    let mut payload = target.to_string_lossy().into_owned().into_bytes();
    payload.push(0);
    Ok(payload)
}

#[cfg(unix)]
fn local_push_metadata(path: &Path) -> Result<(fs::Metadata, bool)> {
    let metadata = fs::symlink_metadata(path)?;
    let is_symlink = metadata.file_type().is_symlink();
    Ok((metadata, is_symlink))
}

#[cfg(not(unix))]
fn local_push_metadata(path: &Path) -> Result<(fs::Metadata, bool)> {
    Ok((fs::metadata(path)?, false))
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    if metadata.file_type().is_symlink() {
        return S_IFLNK | 0o777;
    }
    S_IFREG | (metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    if _metadata.file_type().is_symlink() {
        S_IFLNK | 0o777
    } else {
        S_IFREG | 0o644
    }
}

#[cfg(unix)]
fn dir_permissions(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn dir_permissions(_metadata: &fs::Metadata) -> u32 {
    0o755
}

fn local_basename(path: &Path) -> Result<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AdbError::Usage(format!("无法从本地路径取文件名: {}", path.display())))
}

fn remote_basename(path: &str) -> Result<String> {
    path.trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .map(str::to_string)
        .ok_or_else(|| AdbError::Usage(format!("无法从远端路径取文件名: {path}")))
}

fn remote_join(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

const fn mkid(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct ScriptedStream {
        read: Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingStream {
        write: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for RecordingStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_uses_little_endian_id_and_length() {
        let mut wire = Vec::new();
        write_request(&mut wire, ID_RECV_V1, "/sdcard/a.txt").unwrap();

        assert_eq!(&wire[..4], b"RECV");
        assert_eq!(
            u32::from_le_bytes(wire[4..8].try_into().unwrap()),
            "/sdcard/a.txt".len() as u32
        );
        assert_eq!(&wire[8..], b"/sdcard/a.txt");
    }

    #[test]
    fn quit_is_idempotent_and_uses_official_quit_request() {
        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(Vec::new()),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };

        client.quit().unwrap();
        client.quit().unwrap();

        assert_eq!(client.stream.write, b"QUIT\0\0\0\0");
    }

    #[test]
    fn drop_sends_quit_like_aosp_sync_connection_destructor() {
        let write = Arc::new(Mutex::new(Vec::new()));
        {
            let _client = SyncClient {
                stream: RecordingStream {
                    write: Arc::clone(&write),
                },
                features: SyncFeatures::default(),
                closed: false,
            };
        }

        assert_eq!(*write.lock().unwrap(), b"QUIT\0\0\0\0".to_vec());
    }

    #[test]
    fn list_reads_dent_entries_until_done() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DENT_V1, S_IFREG | 0o644).unwrap();
        wire.extend_from_slice(&5_u32.to_le_bytes());
        wire.extend_from_slice(&123_u32.to_le_bytes());
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(b"file");
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let entries = client.list("/unused").unwrap();

        assert_eq!(&client.stream.write[..4], b"LIST");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("file"));
        assert_eq!(entries[0].size, 5);
        assert_eq!(entries[0].mtime, 123);
    }

    #[test]
    fn list_v1_consumes_full_done_record() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        write_header(&mut wire, ID_LSTAT_V1, S_IFREG | 0o644).unwrap();
        wire.extend_from_slice(&3_u32.to_le_bytes());
        wire.extend_from_slice(&9_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };

        assert!(client.list("/unused").unwrap().is_empty());
        let stat = client.stat("/after-list").unwrap().unwrap();
        assert_eq!(stat.size, 3);
        assert_eq!(stat.mtime, 9);
    }

    #[test]
    fn pull_dir_creates_empty_directory_and_preserves_mtime() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_pull_empty_{}_{}",
            std::process::id(),
            stamp
        ));
        let entry = RemoteEntry {
            name: None,
            mode: S_IFDIR | 0o755,
            size: 0,
            mtime: 1_700_000_000,
            attrs: None,
        };
        let mut summary = TransferSummary::default();

        pull_dir(
            &mut client,
            "/sdcard/empty",
            &local_dir,
            &entry,
            PullOptions {
                preserve_attrs: true,
                compression: SyncCompression::None,
                expect_multiple_files: false,
            },
            &mut summary,
            &mut NoProgress,
        )
        .unwrap();

        assert_eq!(&client.stream.write[..4], b"LIST");
        assert!(local_dir.is_dir());
        assert_eq!(summary, TransferSummary::default());
        let actual_mtime = fs::metadata(&local_dir)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((actual_mtime as i64 - i64::from(entry.mtime)).abs() <= 2);

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn pull_dir_follows_remote_symlink_to_directory() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DENT_V1, S_IFLNK | 0o777).unwrap();
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(&10_u32.to_le_bytes());
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(b"link");
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        write_header(&mut wire, ID_LSTAT_V1, S_IFLNK | 0o777).unwrap();
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(&10_u32.to_le_bytes());
        write_header(&mut wire, ID_LSTAT_V1, S_IFDIR | 0o755).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&11_u32.to_le_bytes());
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_pull_symlink_dir_{}_{}",
            std::process::id(),
            stamp
        ));
        let entry = RemoteEntry {
            name: None,
            mode: S_IFDIR | 0o755,
            size: 0,
            mtime: 1_700_000_000,
            attrs: None,
        };
        let mut summary = TransferSummary::default();

        pull_dir(
            &mut client,
            "/sdcard/root",
            &local_dir,
            &entry,
            PullOptions::default(),
            &mut summary,
            &mut NoProgress,
        )
        .unwrap();

        assert!(local_dir.join("link").is_dir());
        assert_eq!(summary, TransferSummary::default());
        assert!(
            client
                .stream
                .write
                .windows("/sdcard/root/link/".len())
                .any(|window| window == b"/sdcard/root/link/")
        );

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn stat_v2_reads_extended_record() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_LSTAT_V2, 0).unwrap();
        wire.extend_from_slice(&11_u64.to_le_bytes());
        wire.extend_from_slice(&22_u64.to_le_bytes());
        wire.extend_from_slice(&(S_IFREG | 0o600).to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&2000_u32.to_le_bytes());
        wire.extend_from_slice(&2000_u32.to_le_bytes());
        wire.extend_from_slice(&123_u64.to_le_bytes());
        wire.extend_from_slice(&7_i64.to_le_bytes());
        wire.extend_from_slice(&456_i64.to_le_bytes());
        wire.extend_from_slice(&8_i64.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures {
                stat_v2: true,
                ..SyncFeatures::default()
            },
            closed: false,
        };
        let stat = client.stat("/sdcard/file").unwrap().unwrap();

        assert_eq!(&client.stream.write[..4], b"LST2");
        assert_eq!(stat.mode, S_IFREG | 0o600);
        assert_eq!(stat.size, 123);
        assert_eq!(stat.mtime, 456);
        assert_eq!(
            stat.attrs,
            Some(RemoteEntryAttrs {
                dev: 11,
                ino: 22,
                nlink: 1,
                uid: 2000,
                gid: 2000,
                atime: 7,
                mtime: 456,
                ctime: 8,
            })
        );
    }

    #[test]
    fn stat_follow_v2_uses_sta2_and_follows_symlink_target() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_STAT_V2, 0).unwrap();
        wire.extend_from_slice(&11_u64.to_le_bytes());
        wire.extend_from_slice(&22_u64.to_le_bytes());
        wire.extend_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&2000_u32.to_le_bytes());
        wire.extend_from_slice(&2000_u32.to_le_bytes());
        wire.extend_from_slice(&0_u64.to_le_bytes());
        wire.extend_from_slice(&7_i64.to_le_bytes());
        wire.extend_from_slice(&456_i64.to_le_bytes());
        wire.extend_from_slice(&8_i64.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures {
                stat_v2: true,
                ..SyncFeatures::default()
            },
            closed: false,
        };
        let stat = client.stat_follow("/sdcard/link").unwrap().unwrap();

        assert_eq!(&client.stream.write[..4], b"STA2");
        assert!(stat.is_dir());
        assert_eq!(stat.mtime, 456);
    }

    #[test]
    fn stat_v2_distinguishes_enoent_from_other_errors() {
        let mut enoent = Vec::new();
        write_header(&mut enoent, ID_STAT_V2, 2).unwrap();
        enoent.extend_from_slice(&[0_u8; SYNC_DENT_V2_REMAINING_AFTER_HEADER]);
        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(enoent),
                write: Vec::new(),
            },
            features: SyncFeatures {
                stat_v2: true,
                ..SyncFeatures::default()
            },
            closed: false,
        };
        assert!(client.stat_follow("/missing").unwrap().is_none());

        let mut eacces = Vec::new();
        write_header(&mut eacces, ID_STAT_V2, 13).unwrap();
        eacces.extend_from_slice(&[0_u8; SYNC_DENT_V2_REMAINING_AFTER_HEADER]);
        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(eacces),
                write: Vec::new(),
            },
            features: SyncFeatures {
                stat_v2: true,
                ..SyncFeatures::default()
            },
            closed: false,
        };

        let err = client.stat_follow("/denied").unwrap_err();
        assert!(err.to_string().contains("Permission denied"));
    }

    #[test]
    fn stat_follow_v1_probes_symlink_directory_with_trailing_slash() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_LSTAT_V1, S_IFLNK | 0o777).unwrap();
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(&10_u32.to_le_bytes());
        write_header(&mut wire, ID_LSTAT_V1, S_IFDIR | 0o755).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&11_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let stat = client.stat_follow("/sdcard/link").unwrap().unwrap();

        assert!(stat.is_dir());
        let first_len = u32::from_le_bytes(client.stream.write[4..8].try_into().unwrap()) as usize;
        let second = 8 + first_len;
        assert_eq!(&client.stream.write[..4], b"STAT");
        assert_eq!(&client.stream.write[8..8 + first_len], b"/sdcard/link");
        assert_eq!(&client.stream.write[second..second + 4], b"STAT");
        let second_len = u32::from_le_bytes(
            client.stream.write[second + 4..second + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(
            &client.stream.write[second + 8..second + 8 + second_len],
            b"/sdcard/link/"
        );
    }

    #[test]
    fn recv_file_allows_actual_size_to_differ_from_stat_size() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DATA, 5).unwrap();
        wire.extend_from_slice(b"hello");
        write_header(&mut wire, ID_DONE, 0).unwrap();

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local = std::env::temp_dir().join(format!(
            "adb_rust_recv_size_mismatch_{}_{}",
            std::process::id(),
            stamp
        ));
        let entry = RemoteEntry {
            name: None,
            mode: S_IFREG | 0o644,
            size: 10,
            mtime: 0,
            attrs: None,
        };

        let summary = client
            .recv_file(
                "/sdcard/changing",
                &local,
                &entry,
                PullOptions::default(),
                &mut NoProgress,
            )
            .unwrap();

        assert_eq!(&client.stream.write[..4], b"RECV");
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 5);
        assert_eq!(fs::read(&local).unwrap(), b"hello");

        let _ = fs::remove_file(&local);
    }

    #[test]
    fn list_v2_reads_dent2_and_consumes_done_record() {
        let mut wire = Vec::new();
        write_header(&mut wire, ID_DENT_V2, 0).unwrap();
        wire.extend_from_slice(&1_u64.to_le_bytes());
        wire.extend_from_slice(&2_u64.to_le_bytes());
        wire.extend_from_slice(&(S_IFREG | 0o644).to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&5_u64.to_le_bytes());
        wire.extend_from_slice(&0_i64.to_le_bytes());
        wire.extend_from_slice(&123_i64.to_le_bytes());
        wire.extend_from_slice(&0_i64.to_le_bytes());
        wire.extend_from_slice(&4_u32.to_le_bytes());
        wire.extend_from_slice(b"file");
        write_header(&mut wire, ID_DONE, 0).unwrap();
        wire.extend_from_slice(&[0_u8; SYNC_DENT_V2_REMAINING_AFTER_HEADER]);

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures {
                ls_v2: true,
                ..SyncFeatures::default()
            },
            closed: false,
        };
        let entries = client.list("/unused").unwrap();

        assert_eq!(&client.stream.write[..4], b"LIS2");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("file"));
        assert_eq!(entries[0].size, 5);
        assert_eq!(entries[0].mtime, 123);
        assert_eq!(
            entries[0].attrs,
            Some(RemoteEntryAttrs {
                dev: 1,
                ino: 2,
                nlink: 1,
                uid: 0,
                gid: 0,
                atime: 0,
                mtime: 123,
                ctime: 0,
            })
        );
    }

    #[test]
    fn pull_attr_mtime_prefers_v2_extended_time() {
        let entry = RemoteEntry {
            name: None,
            mode: S_IFREG | 0o644,
            size: 0,
            mtime: u32::MAX,
            attrs: Some(RemoteEntryAttrs {
                dev: 0,
                ino: 0,
                nlink: 1,
                uid: 2000,
                gid: 2000,
                atime: 5,
                mtime: i64::from(u32::MAX) + 123,
                ctime: 7,
            }),
        };
        assert_eq!(pull_mtime_secs(&entry), i64::from(u32::MAX) + 123);

        let v1_entry = RemoteEntry {
            attrs: None,
            mtime: 123,
            ..entry
        };
        assert_eq!(pull_mtime_secs(&v1_entry), 123);
    }

    #[test]
    fn ls_entry_format_matches_official_sync_ls() {
        let entry = RemoteEntry {
            name: Some("file.txt".to_string()),
            mode: S_IFREG | 0o644,
            size: 0x12ab,
            mtime: 0x65aa_bbcc,
            attrs: None,
        };

        assert_eq!(
            format_ls_entry(&entry),
            "000081a4 000012ab 65aabbcc file.txt"
        );
    }

    #[test]
    fn sync_dir_list_only_plans_changed_files_without_send() {
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_sync_list_{}_{}",
            std::process::id(),
            stamp
        ));
        let nested_dir = local_dir.join("local").join("tmp");
        fs::create_dir_all(&nested_dir).unwrap();
        fs::write(nested_dir.join("file.txt"), b"sync-list").unwrap();

        let mut wire = Vec::new();
        write_header(&mut wire, ID_LSTAT_V1, 0).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let endpoint = ServerEndpoint::from_env().unwrap();
        let selector = TransportSelector::default();
        let mut result = DirectorySyncResult::default();

        sync_dir_inner(
            &mut client,
            &endpoint,
            &selector,
            &local_dir,
            "/data",
            DirectorySyncOptions {
                list_only: true,
                dry_run: false,
                compression: SyncCompression::None,
                expect_multiple_files: false,
            },
            &mut result,
            &mut NoProgress,
        )
        .unwrap();

        assert_eq!(result.summary, TransferSummary::default());
        assert_eq!(result.would_push.len(), 1);
        assert_eq!(result.would_push[0].remote, "/data/local/tmp/file.txt");
        assert_eq!(&client.stream.write[..4], b"STAT");
        assert!(
            !client
                .stream
                .write
                .windows(4)
                .any(|window| { window == b"SEND" || window == b"SND2" })
        );

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[cfg(unix)]
    #[test]
    fn sync_dir_list_only_skips_special_file_like_aosp() {
        use std::os::unix::net::UnixListener;

        let local_dir = tempfile::tempdir().unwrap();
        let socket_path = local_dir.path().join("special.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(Vec::new()),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let endpoint = ServerEndpoint::from_env().unwrap();
        let selector = TransportSelector::default();
        let mut result = DirectorySyncResult::default();

        sync_dir_inner(
            &mut client,
            &endpoint,
            &selector,
            local_dir.path(),
            "/data",
            DirectorySyncOptions {
                list_only: true,
                dry_run: false,
                compression: SyncCompression::None,
                expect_multiple_files: false,
            },
            &mut result,
            &mut NoProgress,
        )
        .unwrap();

        assert_eq!(result.summary.skipped, 1);
        assert!(result.would_push.is_empty());
        assert!(client.stream.write.is_empty());
        drop(listener);
    }

    #[test]
    fn push_sync_single_file_matches_aosp_mtime_only() {
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_push_sync_mtime_{}_{}",
            std::process::id(),
            stamp
        ));
        fs::create_dir_all(&local_dir).unwrap();
        let local = local_dir.join("file.txt");
        fs::write(&local, b"local-content").unwrap();
        let metadata = fs::metadata(&local).unwrap();
        let mtime = file_mtime(&metadata);

        let mut wire = Vec::new();
        write_header(&mut wire, ID_LSTAT_V1, S_IFREG | 0o644).unwrap();
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&mtime.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let summary = client
            .send_file(
                &local,
                "/data/local/tmp/file.txt",
                PushOptions {
                    sync: true,
                    dry_run: false,
                    compression: SyncCompression::None,
                    expect_multiple_files: false,
                },
                &mut NoProgress,
            )
            .unwrap();

        assert_eq!(
            summary,
            TransferSummary {
                files: 0,
                bytes: 0,
                skipped: 1
            }
        );
        assert_eq!(&client.stream.write[..4], b"STAT");
        assert!(
            !client
                .stream
                .write
                .windows(4)
                .any(|window| { window == b"SEND" || window == b"SND2" })
        );

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn directory_sync_requires_size_and_mtime_like_aosp() {
        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_dir_sync_size_{}_{}",
            std::process::id(),
            stamp
        ));
        fs::create_dir_all(&local_dir).unwrap();
        let local = local_dir.join("file.txt");
        fs::write(&local, b"local-content").unwrap();
        let metadata = fs::metadata(&local).unwrap();
        let mtime = file_mtime(&metadata);

        let mut wire = Vec::new();
        write_header(&mut wire, ID_LSTAT_V1, S_IFREG | 0o644).unwrap();
        wire.extend_from_slice(&(metadata.len() as u32 + 1).to_le_bytes());
        wire.extend_from_slice(&mtime.to_le_bytes());

        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(wire),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };
        let endpoint = ServerEndpoint::from_env().unwrap();
        let selector = TransportSelector::default();
        let mut result = DirectorySyncResult::default();

        sync_dir_inner(
            &mut client,
            &endpoint,
            &selector,
            &local_dir,
            "/data/local/tmp",
            DirectorySyncOptions {
                list_only: true,
                dry_run: false,
                compression: SyncCompression::None,
                expect_multiple_files: false,
            },
            &mut result,
            &mut NoProgress,
        )
        .unwrap();

        assert_eq!(result.summary, TransferSummary::default());
        assert_eq!(result.would_push.len(), 1);
        assert_eq!(result.would_push[0].local, local);
        assert_eq!(result.would_push[0].remote, "/data/local/tmp/file.txt");
        assert_eq!(&client.stream.write[..4], b"STAT");
        assert!(
            !client
                .stream
                .write
                .windows(4)
                .any(|window| { window == b"SEND" || window == b"SND2" })
        );

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn send_v2_request_writes_setup_after_path() {
        let mut wire = Vec::new();
        write_send_v2_request(
            &mut wire,
            "/data/local/tmp/a",
            S_IFREG | 0o644,
            SYNC_FLAG_DRY_RUN,
        )
        .unwrap();

        assert_eq!(&wire[..4], b"SND2");
        let path_len = u32::from_le_bytes(wire[4..8].try_into().unwrap()) as usize;
        assert_eq!(&wire[8..8 + path_len], b"/data/local/tmp/a");
        let setup = 8 + path_len;
        assert_eq!(&wire[setup..setup + 4], b"SND2");
        assert_eq!(
            u32::from_le_bytes(wire[setup + 4..setup + 8].try_into().unwrap()),
            S_IFREG | 0o644
        );
        assert_eq!(
            u32::from_le_bytes(wire[setup + 8..setup + 12].try_into().unwrap()),
            SYNC_FLAG_DRY_RUN
        );
    }

    #[cfg(unix)]
    #[test]
    fn send_file_preserves_symlink_as_link_payload() {
        use std::os::unix::fs::symlink;

        let stamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_dir = std::env::temp_dir().join(format!(
            "adb_rust_symlink_push_{}_{}",
            std::process::id(),
            stamp
        ));
        fs::create_dir_all(&local_dir).unwrap();
        fs::write(local_dir.join("target.txt"), b"target-content").unwrap();
        let link = local_dir.join("link.txt");
        symlink("target.txt", &link).unwrap();

        let mut read = Vec::new();
        write_header(&mut read, ID_OKAY, 0).unwrap();
        let mut client = SyncClient {
            stream: ScriptedStream {
                read: Cursor::new(read),
                write: Vec::new(),
            },
            features: SyncFeatures::default(),
            closed: false,
        };

        let summary = client
            .send_file(
                &link,
                "/data/local/tmp/link.txt",
                PushOptions::default(),
                &mut NoProgress,
            )
            .unwrap();

        let wire = &client.stream.write;
        assert_eq!(&wire[..4], b"SEND");
        let spec_len = u32::from_le_bytes(wire[4..8].try_into().unwrap()) as usize;
        let spec = std::str::from_utf8(&wire[8..8 + spec_len]).unwrap();
        assert_eq!(
            spec,
            format!("/data/local/tmp/link.txt,{}", S_IFLNK | 0o777)
        );
        let data_offset = 8 + spec_len;
        assert_eq!(&wire[data_offset..data_offset + 4], b"DATA");
        let data_len =
            u32::from_le_bytes(wire[data_offset + 4..data_offset + 8].try_into().unwrap());
        assert_eq!(data_len, "target.txt".len() as u32 + 1);
        assert_eq!(
            &wire[data_offset + 8..data_offset + 8 + data_len as usize],
            b"target.txt\0"
        );
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, u64::from(data_len));

        let _ = fs::remove_dir_all(&local_dir);
    }

    #[test]
    fn recv_v2_request_writes_setup_after_path() {
        let mut wire = Vec::new();
        write_recv_v2_request(&mut wire, "/sdcard/a", SYNC_FLAG_ZSTD).unwrap();

        assert_eq!(&wire[..4], b"RCV2");
        let path_len = u32::from_le_bytes(wire[4..8].try_into().unwrap()) as usize;
        let setup = 8 + path_len;
        assert_eq!(&wire[setup..setup + 4], b"RCV2");
        assert_eq!(
            u32::from_le_bytes(wire[setup + 4..setup + 8].try_into().unwrap()),
            SYNC_FLAG_ZSTD
        );
    }

    #[test]
    fn sync_features_detects_exact_tokens() {
        let features = SyncFeatures::from_feature_string("stat_v2,ls_v2,sendrecv_v2_zstd");

        assert!(features.stat_v2);
        assert!(features.ls_v2);
        assert!(!features.sendrecv_v2);
        assert!(features.sendrecv_v2_zstd);
    }

    #[test]
    fn sync_features_detects_dry_run_token() {
        let features = SyncFeatures::from_feature_string("sendrecv_v2,sendrecv_v2_dry_run_send");

        assert!(features.sendrecv_v2);
        assert!(features.sendrecv_v2_dry_run);
    }

    #[test]
    fn sync_features_ignore_client_unsupported_tokens() {
        let features = SyncFeatures::from_feature_string("openscreen_mdns,unknown");

        assert_eq!(features, SyncFeatures::default());
    }

    #[test]
    fn push_pull_public_entrypoints_keep_aosp_missing_arg_errors() {
        let endpoint = ServerEndpoint::new("127.0.0.1", 5037);

        let err = push(
            &endpoint,
            &TransportSelector::default(),
            &[],
            "/data/local/tmp",
            PushOptions::default(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "push requires <source> and <destination> arguments")
        );

        let err = pull(
            &endpoint,
            &TransportSelector::default(),
            &[],
            Path::new("."),
            PullOptions::default(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, AdbError::Usage(message) if message == "pull requires an argument"));
    }

    #[test]
    fn any_compression_prefers_zstd_when_available() {
        let features = SyncFeatures::from_feature_string("sendrecv_v2,sendrecv_v2_zstd");

        assert_eq!(
            features.resolve_compression(SyncCompression::Any),
            SyncCompression::Zstd
        );
    }

    #[test]
    fn explicit_compression_is_not_gated_by_algorithm_feature() {
        let features = SyncFeatures::from_feature_string("sendrecv_v2");

        assert_eq!(
            features.resolve_compression(SyncCompression::Zstd),
            SyncCompression::Zstd
        );
        assert_eq!(
            features.resolve_compression(SyncCompression::Lz4),
            SyncCompression::Lz4
        );
        assert_eq!(
            features.resolve_compression(SyncCompression::Brotli),
            SyncCompression::Brotli
        );
    }

    #[test]
    fn zstd_file_data_round_trips_through_sync_frames() {
        let input = b"adb sync zstd data ".repeat(64);
        let mut wire = Vec::new();
        write_file_data(
            &mut wire,
            &mut Cursor::new(input.as_slice()),
            SyncCompression::Zstd,
        )
        .unwrap();
        write_header(&mut wire, ID_DONE, 0).unwrap();
        write_header(&mut wire, ID_OKAY, 0).unwrap();

        let mut output = Vec::new();
        let mut cursor = Cursor::new(wire);
        let bytes = read_file_data(&mut cursor, &mut output, SyncCompression::Zstd).unwrap();

        assert_eq!(bytes, input.len() as u64);
        assert_eq!(output, input);
        assert_eq!(read_header(&mut cursor).unwrap(), (ID_OKAY, 0));
    }

    #[test]
    fn lz4_file_data_round_trips_through_sync_frames() {
        let input = b"adb sync lz4 data ".repeat(64);
        let mut wire = Vec::new();
        write_file_data(
            &mut wire,
            &mut Cursor::new(input.as_slice()),
            SyncCompression::Lz4,
        )
        .unwrap();
        write_header(&mut wire, ID_DONE, 0).unwrap();
        write_header(&mut wire, ID_OKAY, 0).unwrap();

        let mut output = Vec::new();
        let mut cursor = Cursor::new(wire);
        let bytes = read_file_data(&mut cursor, &mut output, SyncCompression::Lz4).unwrap();

        assert_eq!(bytes, input.len() as u64);
        assert_eq!(output, input);
        assert_eq!(read_header(&mut cursor).unwrap(), (ID_OKAY, 0));
    }

    #[test]
    fn brotli_file_data_round_trips_through_sync_frames() {
        let input = b"adb sync brotli data ".repeat(64);
        let mut wire = Vec::new();
        write_file_data(
            &mut wire,
            &mut Cursor::new(input.as_slice()),
            SyncCompression::Brotli,
        )
        .unwrap();
        write_header(&mut wire, ID_DONE, 0).unwrap();
        write_header(&mut wire, ID_OKAY, 0).unwrap();

        let mut output = Vec::new();
        let mut cursor = Cursor::new(wire);
        let bytes = read_file_data(&mut cursor, &mut output, SyncCompression::Brotli).unwrap();

        assert_eq!(bytes, input.len() as u64);
        assert_eq!(output, input);
        assert_eq!(read_header(&mut cursor).unwrap(), (ID_OKAY, 0));
    }

    #[test]
    fn remote_path_helpers_match_posix_paths() {
        assert_eq!(remote_join("/sdcard/", "a.txt"), "/sdcard/a.txt");
        assert_eq!(remote_join("/", "a.txt"), "/a.txt");
        assert_eq!(remote_basename("/sdcard/dir/").unwrap(), "dir");
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("/sdcard/a b"), "'/sdcard/a b'");
        assert_eq!(shell_quote("/sdcard/a'b"), r#"'/sdcard/a'\''b'"#);
    }

    #[test]
    fn remote_dir_attrs_command_is_best_effort_and_quotes_path() {
        assert_eq!(
            remote_dir_attrs_command("/data/local/tmp/a'b", 0o40755, 1_700_000_000),
            "{ chmod 755 '/data/local/tmp/a'\\''b'; } >/dev/null 2>&1 || true; { touch -d @1700000000 '/data/local/tmp/a'\\''b'; } >/dev/null 2>&1 || true"
        );
    }

    /// 辅助测试结构体：记录 ProgressTracker 调用。
    #[derive(Default)]
    struct TestTracker {
        progress_calls: Vec<(String, u64, u64, bool)>,
        rate_calls: Vec<(String, u64, u64, u64, TransferDirection)>,
        quiet: bool,
    }

    impl ProgressTracker for TestTracker {
        fn report_progress(
            &mut self,
            file: &str,
            copied: u64,
            total: u64,
            expect_multiple_files: bool,
        ) {
            self.progress_calls
                .push((file.to_string(), copied, total, expect_multiple_files));
        }
        fn report_transfer_rate(
            &mut self,
            name: &str,
            files: u64,
            skipped: u64,
            bytes: u64,
            direction: TransferDirection,
            _start: Instant,
        ) {
            self.rate_calls
                .push((name.to_string(), files, skipped, bytes, direction));
        }
        fn set_quiet(&mut self, quiet: bool) {
            self.quiet = quiet;
        }
    }

    #[test]
    fn no_progress_is_noop() {
        let mut np = NoProgress;
        np.report_progress("test", 100, 200, false);
        np.report_transfer_rate("dir", 5, 1, 1000, TransferDirection::Push, Instant::now());
        np.set_quiet(true);
        // No panics = test passed
    }

    #[test]
    fn progress_writer_tracks_copied_bytes() {
        let mut tracker = TestTracker::default();
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut pw = ProgressWriter::new(&mut buf, &mut tracker, "test.bin", 100, false);
            pw.write_all(b"hello").unwrap();
            pw.write_all(b" world").unwrap();
            pw.finish();
        }
        assert_eq!(buf, b"hello world");
        // At least the final report should have copied=11
        assert!(
            tracker.progress_calls.iter().any(|(_, c, _, _)| *c == 11),
            "expected a progress call with copied=11, got {:#?}",
            tracker.progress_calls
        );
        // Total should be set to 100 (from constructor)
        assert!(
            tracker.progress_calls.iter().any(|(_, _, t, _)| *t == 100),
            "expected a progress call with total=100, got {:#?}",
            tracker.progress_calls
        );
    }

    #[test]
    fn progress_writer_does_not_report_when_nothing_written() {
        let mut tracker = TestTracker::default();
        let mut buf: Vec<u8> = Vec::new();
        let pw = ProgressWriter::new(&mut buf, &mut tracker, "empty.dat", 0, false);
        pw.finish();
        // finish should have called report_progress with copied=0
        assert_eq!(tracker.progress_calls.len(), 1);
        assert_eq!(
            tracker.progress_calls[0],
            ("empty.dat".to_string(), 0, 0, false)
        );
    }

    #[test]
    fn progress_writer_passes_expect_multiple_files_flag() {
        let mut tracker = TestTracker::default();
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut pw = ProgressWriter::new(&mut buf, &mut tracker, "multi.apk", 500, true);
            pw.write_all(b"data").unwrap();
            pw.finish();
        }
        assert!(tracker.progress_calls.iter().any(|(_, _, _, e)| *e));
    }

    #[test]
    fn no_progress_tracker_is_default_for_push_and_pull_tests() {
        // 确认 public API 可以接受 NoProgress / None
        let endpoint = ServerEndpoint::new("127.0.0.1", 5037);

        let err = push(
            &endpoint,
            &TransportSelector::default(),
            &[],
            "/data/local/tmp",
            PushOptions::default(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "push requires <source> and <destination> arguments")
        );
    }
}
