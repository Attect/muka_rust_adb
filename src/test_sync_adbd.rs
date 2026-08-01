use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crate::error::AdbError;
use crate::protocol::{self, AdbMessage};
use crate::test_adbd::StubAdbd;

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;

const SYNC_DATA_MAX: usize = 64 * 1024;
const SYNC_DENT_V1_REMAINING_AFTER_HEADER: usize = 12;
const SYNC_DENT_V2_REMAINING_AFTER_HEADER: usize = 68;

const ID_STAT_V1: u32 = mkid(*b"STAT");
const ID_LSTAT_V2: u32 = mkid(*b"LST2");
const ID_STAT_V2: u32 = mkid(*b"STA2");
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
const SYNC_FLAG_DRY_RUN: u32 = 0x8000_0000;

const SHELL_ID_STDOUT: u8 = 1;
const SHELL_ID_STDERR: u8 = 2;
const SHELL_ID_EXIT: u8 = 3;

const SYNC_FLAG_BROTLI: u32 = 1;
const SYNC_FLAG_LZ4: u32 = 2;
const SYNC_FLAG_ZSTD: u32 = 4;

#[derive(Debug, Clone, Copy)]
enum StubCompression {
    None,
    Brotli,
    Lz4,
    Zstd,
}

fn compression_from_flags(flags: u32) -> StubCompression {
    if flags & SYNC_FLAG_ZSTD != 0 {
        StubCompression::Zstd
    } else if flags & SYNC_FLAG_LZ4 != 0 {
        StubCompression::Lz4
    } else if flags & SYNC_FLAG_BROTLI != 0 {
        StubCompression::Brotli
    } else {
        StubCompression::None
    }
}

fn decompress_data(data: &[u8], compression: StubCompression) -> io::Result<Vec<u8>> {
    match compression {
        StubCompression::None => Ok(data.to_vec()),
        StubCompression::Zstd => {
            let mut decoder = zstd::stream::read::Decoder::new(data)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        StubCompression::Lz4 => {
            let mut decoder = lz4_flex::frame::FrameDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        StubCompression::Brotli => {
            let mut decoder = brotli::Decompressor::new(data, SYNC_DATA_MAX);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
    }
}

fn compress_data(data: &[u8], compression: StubCompression) -> io::Result<Vec<u8>> {
    match compression {
        StubCompression::None => Ok(data.to_vec()),
        StubCompression::Zstd => {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1)?;
            encoder.write_all(data)?;
            encoder.finish().map_err(io::Error::other)
        }
        StubCompression::Lz4 => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
            encoder.write_all(data)?;
            encoder
                .finish()
                .map_err(|err| io::Error::other(format!("lz4 压缩失败: {err}")))
        }
        StubCompression::Brotli => {
            let mut encoder = brotli::CompressorWriter::new(Vec::new(), SYNC_DATA_MAX, 1, 22);
            encoder.write_all(data)?;
            encoder.flush()?;
            Ok(encoder.into_inner())
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum StubNode {
    File {
        mode: u32,
        mtime: u32,
        content: Vec<u8>,
    },
    Dir {
        mode: u32,
        mtime: u32,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StubSyncFs {
    entries: HashMap<String, StubNode>,
    features: String,
    next_session: u32,
}

impl StubSyncFs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn dir(mut self, path: &str, mode: u32) -> Self {
        self.entries.insert(
            normalize_path(path),
            StubNode::Dir {
                mode: S_IFDIR | (mode & 0o7777),
                mtime: 1_700_000_000,
            },
        );
        self
    }

    pub(crate) fn file(mut self, path: &str, content: impl Into<Vec<u8>>, mode: u32) -> Self {
        self.entries.insert(
            normalize_path(path),
            StubNode::File {
                mode: S_IFREG | (mode & 0o7777),
                mtime: 1_700_000_000,
                content: content.into(),
            },
        );
        self
    }

    pub(crate) fn with_mtime(mut self, path: &str, mtime: u32) -> Self {
        let key = normalize_path(path);
        if let Some(node) = self.entries.get_mut(&key) {
            match node {
                StubNode::File { mtime: m, .. } | StubNode::Dir { mtime: m, .. } => *m = mtime,
            }
        }
        self
    }

    pub(crate) fn contains(&self, path: &str) -> bool {
        self.entries.contains_key(&normalize_path(path))
    }

    pub(crate) fn file_content(&self, path: &str) -> Option<Vec<u8>> {
        self.entries
            .get(&normalize_path(path))
            .and_then(|node| match node {
                StubNode::File { content, .. } => Some(content.clone()),
                StubNode::Dir { .. } => None,
            })
    }

    pub(crate) fn spawn(self, features: &str) -> StubSyncAdbd {
        let banner = format!("device::features={features};").into_bytes();
        let fs = Arc::new(Mutex::new(StubSyncFs {
            entries: self.entries,
            features: features.to_string(),
            next_session: 1,
        }));
        let fs_for_closure = Arc::clone(&fs);
        let adbd = StubAdbd::spawn(banner, move |stream| {
            DeviceService::new(fs_for_closure.clone(), stream).run();
        });
        StubSyncAdbd { adbd, fs }
    }
}

pub(crate) struct StubSyncAdbd {
    adbd: StubAdbd,
    fs: Arc<Mutex<StubSyncFs>>,
}

impl std::ops::Deref for StubSyncAdbd {
    type Target = StubAdbd;
    fn deref(&self) -> &Self::Target {
        &self.adbd
    }
}

impl StubSyncAdbd {
    pub(crate) fn fs(&self) -> &Arc<Mutex<StubSyncFs>> {
        &self.fs
    }

    pub(crate) fn join(self) {
        self.adbd.join();
    }
}

#[derive(Debug)]
enum IncomingMessage {
    Data(Vec<u8>),
    Ack,
    Close,
}

#[derive(Debug)]
enum OutgoingMessage {
    Data(Vec<u8>),
    Close,
}

struct Active(Arc<AtomicUsize>);

impl Active {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct DeviceService {
    fs: Arc<Mutex<StubSyncFs>>,
    stream: TcpStream,
}

impl DeviceService {
    fn new(fs: Arc<Mutex<StubSyncFs>>, stream: &mut TcpStream) -> Self {
        Self {
            fs,
            stream: stream.try_clone().expect("stub daemon 克隆 stream 失败"),
        }
    }

    fn run(self) {
        let (out_tx, out_rx) = mpsc::channel::<(u32, u32, OutgoingMessage)>();
        let handlers: Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingMessage>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicBool::new(false));

        // 所有对 transport 的写操作必须通过这把锁序列化，避免 reader/writer 线程并发写导致报文交错。
        let write_stream = Arc::new(Mutex::new(
            self.stream
                .try_clone()
                .expect("stub daemon 克隆 stream 失败"),
        ));

        let writer_write_stream = Arc::clone(&write_stream);
        let writer_failed = Arc::clone(&failed);
        let writer_handle = thread::spawn(move || {
            Self::writer_thread(writer_write_stream, out_rx, writer_failed);
        });

        let read_stream = self
            .stream
            .try_clone()
            .expect("stub daemon 克隆 stream 失败");
        Self::reader_thread(
            read_stream,
            write_stream,
            self.fs,
            handlers,
            out_tx.clone(),
            active,
            failed,
        );

        drop(out_tx);
        writer_handle.join().unwrap();
    }

    fn writer_thread(
        write_stream: Arc<Mutex<TcpStream>>,
        out_rx: mpsc::Receiver<(u32, u32, OutgoingMessage)>,
        failed: Arc<AtomicBool>,
    ) {
        while let Ok((host_id, device_id, msg)) = out_rx.recv() {
            let mut stream = write_stream.lock().unwrap_or_else(|err| err.into_inner());
            match msg {
                OutgoingMessage::Data(payload) => {
                    if let Err(err) = AdbMessage::new(protocol::A_WRTE, device_id, host_id, payload)
                        .unwrap()
                        .write_to(&mut *stream, protocol::A_VERSION)
                    {
                        eprintln!("stub daemon 写入 A_WRTE 失败: {err}");
                        failed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                OutgoingMessage::Close => {
                    if let Err(err) =
                        AdbMessage::new(protocol::A_CLSE, device_id, host_id, Vec::new())
                            .unwrap()
                            .write_to(&mut *stream, protocol::A_VERSION)
                    {
                        eprintln!("stub daemon 写入 A_CLSE 失败: {err}");
                        failed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }
    }

    fn reader_thread(
        mut stream: TcpStream,
        write_stream: Arc<Mutex<TcpStream>>,
        fs: Arc<Mutex<StubSyncFs>>,
        handlers: Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingMessage>>>>,
        out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
        active: Arc<AtomicUsize>,
        failed: Arc<AtomicBool>,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut next_device_id: u32 = 91;

        loop {
            let packet = match AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD) {
                Ok(packet) => packet,
                Err(_) if active.load(Ordering::SeqCst) == 0 => break,
                Err(AdbError::Io(err))
                    if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(_) => {
                    failed.store(true, Ordering::SeqCst);
                    break;
                }
            };

            match packet.command {
                protocol::A_OPEN => {
                    let host_id = packet.arg0;
                    let device_id = next_device_id;
                    next_device_id += 1;
                    let service = String::from_utf8_lossy(&packet.payload);
                    let service = service.strip_suffix('\0').unwrap_or(&service).to_string();

                    {
                        let mut stream = write_stream.lock().unwrap_or_else(|err| err.into_inner());
                        if let Err(err) =
                            AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                                .unwrap()
                                .write_to(&mut *stream, protocol::A_VERSION)
                        {
                            eprintln!("stub daemon 发送 A_OKAY 失败: {err}");
                            failed.store(true, Ordering::SeqCst);
                            break;
                        }
                    }

                    if service == "features" {
                        let features = {
                            let fs = fs.lock().unwrap();
                            fs.features.clone()
                        };
                        let _ = out_tx.send((
                            host_id,
                            device_id,
                            OutgoingMessage::Data(features.into_bytes()),
                        ));
                        let _ = out_tx.send((host_id, device_id, OutgoingMessage::Close));
                        continue;
                    }

                    let (in_tx, in_rx) = mpsc::channel();
                    handlers.lock().unwrap().insert(host_id, in_tx);

                    let fs = Arc::clone(&fs);
                    let out_tx = out_tx.clone();
                    let handler_failed = Arc::clone(&failed);
                    let _guard = Active::new(Arc::clone(&active));
                    thread::spawn(move || {
                        let _guard = _guard;
                        if service == "sync:" {
                            SyncHandler::new(fs, in_rx, out_tx, host_id, device_id, handler_failed)
                                .run();
                        } else if let Some(command) = service.strip_prefix("shell,v2,raw:") {
                            ShellHandler::new(
                                fs,
                                in_rx,
                                out_tx,
                                host_id,
                                device_id,
                                command,
                                true,
                                handler_failed,
                            )
                            .run();
                        } else if let Some(command) = service.strip_prefix("shell:") {
                            ShellHandler::new(
                                fs,
                                in_rx,
                                out_tx,
                                host_id,
                                device_id,
                                command,
                                false,
                                handler_failed,
                            )
                            .run();
                        } else if let Some(args) = parse_abb_service_args(&service) {
                            let args: Vec<String> = args.into_iter().map(String::from).collect();
                            AbbExecHandler::new(
                                fs,
                                in_rx,
                                out_tx,
                                host_id,
                                device_id,
                                args,
                                handler_failed,
                            )
                            .run();
                        } else {
                            let _ = out_tx.send((host_id, device_id, OutgoingMessage::Close));
                        }
                    });
                }
                protocol::A_WRTE if packet.arg0 == packet.arg1 => {}
                protocol::A_WRTE => {
                    let host_id = packet.arg0;
                    let device_id = packet.arg1;
                    let handlers = handlers.lock().unwrap();
                    if let Some(handler) = handlers.get(&host_id) {
                        let _ = handler.send(IncomingMessage::Data(packet.payload));
                    }
                    drop(handlers);
                    let mut stream = write_stream.lock().unwrap_or_else(|err| err.into_inner());
                    if let Err(err) =
                        AdbMessage::new(protocol::A_OKAY, device_id, host_id, Vec::new())
                            .unwrap()
                            .write_to(&mut *stream, protocol::A_VERSION)
                    {
                        eprintln!("stub daemon 发送 A_OKAY 失败: {err}");
                        failed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                protocol::A_OKAY => {
                    let host_id = packet.arg0;
                    let handlers = handlers.lock().unwrap();
                    if let Some(handler) = handlers.get(&host_id) {
                        let _ = handler.send(IncomingMessage::Ack);
                    }
                }
                protocol::A_CLSE => {
                    let host_id = packet.arg0;
                    let handlers = handlers.lock().unwrap();
                    if let Some(handler) = handlers.get(&host_id) {
                        let _ = handler.send(IncomingMessage::Close);
                    }
                }
                _ => {}
            }
        }
    }
}

struct SyncHandler {
    fs: Arc<Mutex<StubSyncFs>>,
    in_rx: mpsc::Receiver<IncomingMessage>,
    out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
    host_id: u32,
    device_id: u32,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    pending_acks: usize,
    closed: bool,
    failed: Arc<AtomicBool>,
}

impl SyncHandler {
    fn new(
        fs: Arc<Mutex<StubSyncFs>>,
        in_rx: mpsc::Receiver<IncomingMessage>,
        out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
        host_id: u32,
        device_id: u32,
        failed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            fs,
            in_rx,
            out_tx,
            host_id,
            device_id,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            pending_acks: 0,
            closed: false,
            failed,
        }
    }

    fn run(&mut self) {
        let result = self.run_inner();
        if result.is_err() {
            self.closed = true;
        }
        let _ = self.flush_writes();
        let _ = self
            .out_tx
            .send((self.host_id, self.device_id, OutgoingMessage::Close));
    }

    fn run_inner(&mut self) -> io::Result<()> {
        loop {
            let id = match self.read_u32() {
                Ok(value) => value,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err),
            };
            let value = self.read_u32()?;

            match id {
                ID_QUIT => break,
                ID_STAT_V1 => self.handle_stat_v1(value)?,
                ID_LSTAT_V2 => self.handle_stat_v2(value, false)?,
                ID_STAT_V2 => self.handle_stat_v2(value, true)?,
                ID_LIST_V1 => self.handle_list_v1(value)?,
                ID_LIST_V2 => self.handle_list_v2(value)?,
                ID_RECV_V1 => self.handle_recv_v1(value)?,
                ID_RECV_V2 => self.handle_recv_v2(value)?,
                ID_SEND_V1 => self.handle_send_v1(value)?,
                ID_SEND_V2 => self.handle_send_v2(value)?,
                other => {
                    return Err(io::Error::other(format!(
                        "sync stub 收到未知请求 ID: {}",
                        String::from_utf8_lossy(&other.to_le_bytes())
                    )));
                }
            }
            self.flush_writes()?;
        }
        Ok(())
    }

    fn wait_for_data(&mut self, min_bytes: usize) -> io::Result<()> {
        while self.read_buffer.len() < min_bytes {
            if self.closed || self.failed.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sync stub 读取时流已关闭或连接已失败",
                ));
            }
            match self.in_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(IncomingMessage::Data(mut payload)) => {
                    self.read_buffer.append(&mut payload);
                }
                Ok(IncomingMessage::Close) => {
                    self.closed = true;
                }
                Ok(IncomingMessage::Ack) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "sync stub 输入 channel 已关闭",
                    ));
                }
            }
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.wait_for_data(buf.len())?;
        let take = buf.len();
        buf.copy_from_slice(&self.read_buffer[..take]);
        self.read_buffer.drain(..take);
        Ok(())
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0_u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_string(&mut self, len: usize) -> io::Result<String> {
        let mut buf = vec![0_u8; len];
        self.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn write_sync_bytes(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_buffer.extend_from_slice(buf);
        if self.write_buffer.len() >= SYNC_DATA_MAX {
            self.flush_writes()?;
        }
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_sync_bytes(buf)
    }

    fn flush_writes(&mut self) -> io::Result<()> {
        while !self.write_buffer.is_empty() {
            if self.failed.load(Ordering::SeqCst) {
                self.pending_acks = 0;
                self.write_buffer.clear();
                return Ok(());
            }
            let chunk_size = self.write_buffer.len().min(SYNC_DATA_MAX);
            let chunk: Vec<u8> = self.write_buffer.drain(..chunk_size).collect();
            self.out_tx
                .send((self.host_id, self.device_id, OutgoingMessage::Data(chunk)))
                .map_err(|err| io::Error::other(format!("sync stub 发送响应失败: {err}")))?;
            self.pending_acks += 1;
            self.wait_for_ack()?;
        }
        Ok(())
    }

    fn wait_for_ack(&mut self) -> io::Result<()> {
        while self.pending_acks > 0 {
            if self.failed.load(Ordering::SeqCst) {
                self.pending_acks = 0;
                return Ok(());
            }
            match self.in_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(IncomingMessage::Ack) => {
                    self.pending_acks -= 1;
                }
                Ok(IncomingMessage::Data(mut payload)) => {
                    self.read_buffer.append(&mut payload);
                }
                Ok(IncomingMessage::Close) => {
                    self.closed = true;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => {
                    return Err(io::Error::other("sync stub 等待 A_OKAY 失败"));
                }
            }
        }
        Ok(())
    }

    fn handle_stat_v1(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let fs = self.fs.lock().unwrap();
        if let Some(entry) = fs.entries.get(&path).cloned() {
            let (mode, size, mtime) = match entry {
                StubNode::File {
                    mode,
                    mtime,
                    ref content,
                } => (mode, content.len() as u32, mtime),
                StubNode::Dir { mode, mtime } => (mode, 0, mtime),
            };
            drop(fs);
            self.write_header(ID_STAT_V1, mode)?;
            self.write_u32(size)?;
            self.write_u32(mtime)?;
        } else {
            drop(fs);
            self.write_header(ID_STAT_V1, 0)?;
            self.write_u32(0)?;
            self.write_u32(0)?;
        }
        Ok(())
    }

    fn handle_stat_v2(&mut self, path_len: u32, follow_symlink: bool) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let request_id = if follow_symlink {
            ID_STAT_V2
        } else {
            ID_LSTAT_V2
        };
        let fs = self.fs.lock().unwrap();
        let Some(entry) = fs.entries.get(&path).cloned() else {
            drop(fs);
            self.write_stat_v2(request_id, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)?;
            return Ok(());
        };
        let (mode, size, mtime) = match entry {
            StubNode::File {
                mode,
                mtime,
                ref content,
            } => (mode, content.len() as u64, mtime),
            StubNode::Dir { mode, mtime } => (mode, 0, mtime),
        };
        drop(fs);
        self.write_stat_v2(
            request_id,
            0,
            1,
            2,
            mode,
            1,
            2000,
            2000,
            size,
            0,
            mtime as i64,
            0,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_stat_v2(
        &mut self,
        id: u32,
        error: u32,
        dev: u64,
        ino: u64,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime: i64,
        mtime: i64,
        ctime: i64,
    ) -> io::Result<()> {
        self.write_header(id, error)?;
        self.write_u64(dev)?;
        self.write_u64(ino)?;
        self.write_u32(mode)?;
        self.write_u32(nlink)?;
        self.write_u32(uid)?;
        self.write_u32(gid)?;
        self.write_u64(size)?;
        self.write_i64(atime)?;
        self.write_i64(mtime)?;
        self.write_i64(ctime)?;
        Ok(())
    }

    fn handle_list_v1(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let fs = self.fs.lock().unwrap();
        if !self.is_directory(&path, &fs) {
            drop(fs);
            self.write_header(ID_FAIL, 0)?;
            return Ok(());
        }
        let children = self.list_children(&path, &fs);
        drop(fs);
        for (name, node) in children {
            let (mode, size, mtime) = match node {
                StubNode::File {
                    mode,
                    mtime,
                    content,
                } => (mode, content.len() as u32, mtime),
                StubNode::Dir { mode, mtime } => (mode, 0, mtime),
            };
            self.write_header(ID_DENT_V1, mode)?;
            self.write_u32(size)?;
            self.write_u32(mtime)?;
            self.write_u32(name.len() as u32)?;
            self.write_sync_bytes(name.as_bytes())?;
        }
        self.write_header(ID_DONE, 0)?;
        self.write_all(&[0_u8; SYNC_DENT_V1_REMAINING_AFTER_HEADER])?;
        Ok(())
    }

    fn handle_list_v2(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let fs = self.fs.lock().unwrap();
        if !self.is_directory(&path, &fs) {
            drop(fs);
            self.write_header(ID_FAIL, 0)?;
            return Ok(());
        }
        let children = self.list_children(&path, &fs);
        drop(fs);
        for (name, node) in children {
            let (mode, size, mtime) = match node {
                StubNode::File {
                    mode,
                    mtime,
                    content,
                } => (mode, content.len() as u64, mtime),
                StubNode::Dir { mode, mtime } => (mode, 0, mtime),
            };
            self.write_header(ID_DENT_V2, 0)?;
            self.write_u64(1)?;
            self.write_u64(2)?;
            self.write_u32(mode)?;
            self.write_u32(1)?;
            self.write_u32(2000)?;
            self.write_u32(2000)?;
            self.write_u64(size)?;
            self.write_i64(0)?;
            self.write_i64(mtime as i64)?;
            self.write_i64(0)?;
            self.write_u32(name.len() as u32)?;
            self.write_sync_bytes(name.as_bytes())?;
        }
        self.write_header(ID_DONE, 0)?;
        self.write_all(&[0_u8; SYNC_DENT_V2_REMAINING_AFTER_HEADER])?;
        Ok(())
    }

    fn list_children(&self, path: &str, fs: &StubSyncFs) -> Vec<(String, StubNode)> {
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        let mut children: Vec<(String, StubNode)> = fs
            .entries
            .iter()
            .filter_map(|(key, node)| {
                if key.starts_with(&prefix) && key.len() > prefix.len() {
                    let rest = &key[prefix.len()..];
                    if !rest.contains('/') {
                        Some((rest.to_string(), node.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        children.sort_by(|a, b| a.0.cmp(&b.0));
        children
    }

    fn is_directory(&self, path: &str, fs: &StubSyncFs) -> bool {
        matches!(fs.entries.get(path), Some(StubNode::Dir { .. }))
    }

    fn handle_recv_v1(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        self.send_file_content(&path, StubCompression::None)?;
        Ok(())
    }

    fn handle_recv_v2(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let setup_id = self.read_u32()?;
        assert_eq!(setup_id, ID_RECV_V2);
        let flags = self.read_u32()?;
        let compression = compression_from_flags(flags);
        self.send_file_content(&path, compression)?;
        Ok(())
    }

    fn send_file_content(&mut self, path: &str, compression: StubCompression) -> io::Result<()> {
        let content = {
            let fs = self.fs.lock().unwrap();
            match fs.entries.get(path) {
                Some(StubNode::File { content, .. }) => content.clone(),
                _ => {
                    drop(fs);
                    self.write_header(ID_FAIL, 0)?;
                    return Ok(());
                }
            }
        };

        let content = compress_data(&content, compression)?;
        for chunk in content.chunks(SYNC_DATA_MAX) {
            self.write_header(ID_DATA, chunk.len() as u32)?;
            self.write_sync_bytes(chunk)?;
        }
        self.write_header(ID_DONE, 0)?;
        Ok(())
    }

    fn handle_send_v1(&mut self, spec_len: u32) -> io::Result<()> {
        let spec = self.read_string(spec_len as usize)?;
        let (path, _mode) = spec.rsplit_once(',').unwrap_or((&spec, "0"));
        let path = path.to_string();
        let content = self.read_data_frames()?;
        self.store_file(path, content);
        self.write_header(ID_OKAY, 0)?;
        Ok(())
    }

    fn handle_send_v2(&mut self, path_len: u32) -> io::Result<()> {
        let path = self.read_string(path_len as usize)?;
        let setup_id = self.read_u32()?;
        assert_eq!(setup_id, ID_SEND_V2);
        let _mode = self.read_u32()?;
        let flags = self.read_u32()?;
        let compression = compression_from_flags(flags);
        let compressed = self.read_data_frames()?;
        let content = decompress_data(&compressed, compression)?;
        if flags & SYNC_FLAG_DRY_RUN == 0 {
            self.store_file(path, content);
        }
        self.write_header(ID_OKAY, 0)?;
        Ok(())
    }

    fn store_file(&mut self, path: String, content: Vec<u8>) {
        self.fs.lock().unwrap().entries.insert(
            path,
            StubNode::File {
                mode: S_IFREG | 0o644,
                mtime: 1_700_000_000,
                content,
            },
        );
    }

    fn read_data_frames(&mut self) -> io::Result<Vec<u8>> {
        let mut content = Vec::new();
        loop {
            let id = self.read_u32()?;
            let value = self.read_u32()?;
            match id {
                ID_DATA => {
                    let mut chunk = vec![0_u8; value as usize];
                    self.read_exact(&mut chunk)?;
                    content.extend_from_slice(&chunk);
                }
                ID_DONE => break,
                other => panic!(
                    "sync stub SEND 收到非预期 ID: {}",
                    String::from_utf8_lossy(&other.to_le_bytes())
                ),
            }
        }
        Ok(content)
    }

    fn write_header(&mut self, id: u32, value: u32) -> io::Result<()> {
        self.write_u32(id)?;
        self.write_u32(value)?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.write_sync_bytes(&value.to_le_bytes())
    }

    fn write_u64(&mut self, value: u64) -> io::Result<()> {
        self.write_sync_bytes(&value.to_le_bytes())
    }

    fn write_i64(&mut self, value: i64) -> io::Result<()> {
        self.write_sync_bytes(&value.to_le_bytes())
    }
}

struct ShellHandler {
    fs: Arc<Mutex<StubSyncFs>>,
    in_rx: mpsc::Receiver<IncomingMessage>,
    out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
    host_id: u32,
    device_id: u32,
    command: String,
    v2: bool,
    failed: Arc<AtomicBool>,
}

impl ShellHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        fs: Arc<Mutex<StubSyncFs>>,
        in_rx: mpsc::Receiver<IncomingMessage>,
        out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
        host_id: u32,
        device_id: u32,
        command: &str,
        v2: bool,
        failed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            fs,
            in_rx,
            out_tx,
            host_id,
            device_id,
            command: command.to_string(),
            v2,
            failed,
        }
    }

    fn run(&mut self) {
        let exit_code = self.execute_command();

        if self.v2 {
            let _ = self.write_shell_packet(SHELL_ID_STDOUT, &[]);
            let _ = self.write_shell_packet(SHELL_ID_STDERR, &[]);
            let _ = self.write_shell_packet(SHELL_ID_EXIT, &[exit_code]);
        }

        let _ = self
            .out_tx
            .send((self.host_id, self.device_id, OutgoingMessage::Close));
    }

    fn execute_command(&mut self) -> u8 {
        let command = self.command.clone();
        let command = command.trim();
        if let Some(rest) = command.strip_prefix("echo ") {
            let output = format!("{rest}\n");
            if self.v2 {
                let _ = self.write_shell_packet(SHELL_ID_STDOUT, output.as_bytes());
            } else {
                let _ = self.write_raw(output.as_bytes());
            }
        } else if command.starts_with("mkdir -p ") {
            let path = command.strip_prefix("mkdir -p ").unwrap_or("").trim();
            self.mkdir_p(strip_quotes(path));
        } else if command.starts_with("chmod ")
            && let Some((mode, path)) = parse_chmod(&self.command)
            && let Some(StubNode::File { mode: m, .. } | StubNode::Dir { mode: m, .. }) =
                self.fs.lock().unwrap().entries.get_mut(&path)
        {
            *m = (*m & !0o7777) | (mode & 0o7777);
        } else if command.starts_with("touch -d @")
            && let Some((mtime, path)) = parse_touch(&self.command)
            && let Some(StubNode::File { mtime: m, .. } | StubNode::Dir { mtime: m, .. }) =
                self.fs.lock().unwrap().entries.get_mut(&path)
        {
            *m = mtime;
        } else if let Some(package) = command
            .strip_prefix("cmd package uninstall ")
            .or_else(|| command.strip_prefix("pm uninstall "))
        {
            let _ = package.split_whitespace().next().unwrap_or(package);
            if self.v2 {
                let _ = self.write_shell_packet(SHELL_ID_STDOUT, b"Success\n");
            } else {
                let _ = self.write_raw(b"Success\n");
            }
        }
        0
    }

    fn mkdir_p(&mut self, path: &str) {
        let normalized = normalize_path(path);
        if normalized.is_empty() || normalized == "/" {
            return;
        }
        let absolute = normalized.starts_with('/');

        let mut current = String::new();
        let mut first = true;
        for part in normalized.split('/') {
            if part.is_empty() {
                continue;
            }
            if first {
                first = false;
                current = if absolute {
                    format!("/{part}")
                } else {
                    part.to_string()
                };
            } else {
                current.push('/');
                current.push_str(part);
            }
            self.fs
                .lock()
                .unwrap()
                .entries
                .entry(current.clone())
                .or_insert(StubNode::Dir {
                    mode: S_IFDIR | 0o755,
                    mtime: 1_700_000_000,
                });
        }
    }

    fn write_shell_packet(&mut self, id: u8, payload: &[u8]) -> io::Result<()> {
        let mut packet = Vec::with_capacity(1 + 4 + payload.len());
        packet.push(id);
        packet.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_le_bytes());
        packet.extend_from_slice(payload);

        self.out_tx
            .send((self.host_id, self.device_id, OutgoingMessage::Data(packet)))
            .map_err(io::Error::other)?;
        self.wait_for_ack()
    }

    fn write_raw(&mut self, payload: &[u8]) -> io::Result<()> {
        self.out_tx
            .send((
                self.host_id,
                self.device_id,
                OutgoingMessage::Data(payload.to_vec()),
            ))
            .map_err(io::Error::other)?;
        self.wait_for_ack()
    }

    fn wait_for_ack(&mut self) -> io::Result<()> {
        loop {
            if self.failed.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.in_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(IncomingMessage::Ack) => return Ok(()),
                Ok(IncomingMessage::Data(_)) => {}
                Ok(IncomingMessage::Close) => {
                    return Err(io::Error::other("shell stub 等待 A_OKAY 时流关闭"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err(io::Error::other("shell stub 等待 A_OKAY 失败")),
            }
        }
    }
}

fn parse_abb_service_args(service: &str) -> Option<Vec<&str>> {
    if let Some(rest) = service.strip_prefix("abb_exec:") {
        return Some(rest.split('\0').collect());
    }
    if let Some(rest) = service.strip_prefix("abb:") {
        return Some(rest.split('\0').collect());
    }
    None
}

struct AbbExecHandler {
    #[allow(dead_code)]
    fs: Arc<Mutex<StubSyncFs>>,
    in_rx: mpsc::Receiver<IncomingMessage>,
    out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
    host_id: u32,
    device_id: u32,
    args: Vec<String>,
    failed: Arc<AtomicBool>,
}

impl AbbExecHandler {
    fn new(
        fs: Arc<Mutex<StubSyncFs>>,
        in_rx: mpsc::Receiver<IncomingMessage>,
        out_tx: mpsc::Sender<(u32, u32, OutgoingMessage)>,
        host_id: u32,
        device_id: u32,
        args: Vec<String>,
        failed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            fs,
            in_rx,
            out_tx,
            host_id,
            device_id,
            args,
            failed,
        }
    }

    fn run(&mut self) {
        let _ = self.dispatch();
        let _ = self
            .out_tx
            .send((self.host_id, self.device_id, OutgoingMessage::Close));
    }

    fn dispatch(&mut self) -> io::Result<()> {
        if self.args.is_empty() {
            return Ok(());
        }
        match self.args[0].as_str() {
            "package" => self.dispatch_package(),
            _ => Ok(()),
        }
    }

    fn dispatch_package(&mut self) -> io::Result<()> {
        let sub = self.args.get(1).map(String::as_str).unwrap_or("");
        match sub {
            "install" | "install-write" => {
                self.drain_input();
                self.write_raw(b"Success\n")
            }
            "install-create" => {
                let session_id = {
                    let mut fs = self.fs.lock().unwrap();
                    let id = fs.next_session;
                    fs.next_session += 1;
                    id
                };
                self.write_raw(
                    format!("Success: created install session [{session_id}]\n").as_bytes(),
                )
            }
            "install-add-session" | "install-commit" | "install-abandon" => {
                self.write_raw(b"Success\n")
            }
            _ => Ok(()),
        }
    }

    fn drain_input(&mut self) {
        loop {
            match self.in_rx.recv() {
                Ok(IncomingMessage::Data(_)) => {}
                Ok(IncomingMessage::Close) => break,
                Ok(IncomingMessage::Ack) => {}
                Err(_) => break,
            }
        }
    }

    fn write_raw(&mut self, payload: &[u8]) -> io::Result<()> {
        self.out_tx
            .send((
                self.host_id,
                self.device_id,
                OutgoingMessage::Data(payload.to_vec()),
            ))
            .map_err(io::Error::other)?;
        self.wait_for_ack()
    }

    fn wait_for_ack(&mut self) -> io::Result<()> {
        loop {
            if self.failed.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.in_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(IncomingMessage::Ack) => return Ok(()),
                Ok(IncomingMessage::Data(_)) => {}
                Ok(IncomingMessage::Close) => {
                    return Err(io::Error::other("abb stub 等待 A_OKAY 时流关闭"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err(io::Error::other("abb stub 等待 A_OKAY 失败")),
            }
        }
    }
}

fn parse_chmod(command: &str) -> Option<(u32, String)> {
    let mut parts = command.split_whitespace();
    parts.next()?;
    let mode_str = parts.next()?;
    let path = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mode = u32::from_str_radix(mode_str, 8).ok()?;
    Some((mode, normalize_path(strip_quotes(path))))
}

fn parse_touch(command: &str) -> Option<(u32, String)> {
    let mut parts = command.split_whitespace();
    parts.next()?;
    let flag = parts.next()?;
    let mtime_str = flag.strip_prefix("@")?;
    let path = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mtime = mtime_str.parse::<u32>().ok()?;
    Some((mtime, normalize_path(strip_quotes(path))))
}

fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(s)
}

const fn mkid(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }

    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }

    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}
