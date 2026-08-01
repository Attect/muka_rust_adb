use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

use adb_rust::client::{self, ServerEndpoint};
use adb_rust::protocol;

struct StartedServer {
    port: u16,
    log_path: PathBuf,
    _home: tempfile::TempDir,
}

impl StartedServer {
    fn start(envs: &[(&str, &str)]) -> (Self, Output) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        Self::start_on_port(port, envs)
    }

    fn start_on_port(port: u16, envs: &[(&str, &str)]) -> (Self, Output) {
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("adb.log");
        let mut command = adb_command(port, home.path(), &log_path);
        command.arg("start-server");
        for (name, value) in envs {
            command.env(name, value);
        }
        let output = command.output().expect("无法运行 adb start-server");
        let server = Self {
            port,
            log_path,
            _home: home,
        };
        (server, output)
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(adb_bin());
        command.arg("-P").arg(self.port.to_string()).args(args);
        command.output().expect("无法运行 adb client")
    }

    fn read_log_until(&self, expected: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
            if log.contains(expected) || Instant::now() >= deadline {
                return log;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for StartedServer {
    fn drop(&mut self) {
        let _ = self.run(&["kill-server"]);
    }
}

#[test]
fn localhost_listener_and_port_client_share_one_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let home = tempfile::tempdir().unwrap();
    let log_path = home.path().join("adb.log");
    let mut child = Command::new(adb_bin())
        .args([
            "-L".to_string(),
            format!("tcp:localhost:{port}"),
            "server".to_string(),
            "nodaemon".to_string(),
        ])
        .env("ANDROID_SDK_HOME", home.path())
        .env("ANDROID_ADB_LOG_PATH", &log_path)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let endpoint = ServerEndpoint::for_port(port);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if client::server_version(&endpoint).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("localhost server 提前退出: {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("IPv4 port client 无法连接 localhost listener");
        }
        thread::sleep(Duration::from_millis(20));
    }

    let kill = Command::new(adb_bin())
        .args(["-P", &port.to_string(), "kill-server"])
        .env("ANDROID_SDK_HOME", home.path())
        .env("ANDROID_ADB_LOG_PATH", &log_path)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0")
        .output()
        .unwrap();
    assert!(kill.status.success(), "kill-server 失败: {kill:?}");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "localhost server 异常退出: {status}");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("kill-server 没有终止原 localhost server");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn mismatched_server_is_killed_and_replaced() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let old_server = thread::spawn(move || {
        let (mut version_stream, _) = listener.accept().unwrap();
        assert_eq!(read_service(&mut version_stream), "host:version");
        write_query_response(&mut version_stream, "0028");

        let (mut kill_stream, _) = listener.accept().unwrap();
        assert_eq!(read_service(&mut kill_stream), "host:kill");
        kill_stream.write_all(b"OKAY").unwrap();
    });

    let (server, output) = StartedServer::start_on_port(port, &[]);
    old_server.join().unwrap();
    assert!(output.status.success(), "start-server 失败: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("adb server version (40) doesn't match this client (41); killing..."),
        "缺少官方版本不匹配提示: {stderr:?}"
    );
    assert_eq!(
        client::server_version(&ServerEndpoint::for_port(server.port)).unwrap(),
        protocol::ADB_SERVER_VERSION
    );
}

#[cfg(target_os = "linux")]
#[test]
fn newer_server_binary_is_reexecuted_before_version_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = tempfile::tempdir().unwrap();
    let log_path = home.path().join("adb.log");
    let android_dir = home.path().join(".android");
    std::fs::create_dir_all(&android_dir).unwrap();

    let newer_adb = home.path().join("newer-adb");
    std::fs::copy(adb_bin(), &newer_adb).unwrap();
    let marker_path = android_dir.join(format!("adb.{port}"));
    std::fs::write(&marker_path, newer_adb.as_os_str().as_bytes()).unwrap();

    let newer_version = format!("{:04x}", protocol::ADB_SERVER_VERSION + 1);
    let old_server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut version_stream, _) = listener.accept().unwrap();
            assert_eq!(read_service(&mut version_stream), "host:version");
            write_query_response(&mut version_stream, &newer_version);
        }

        let (mut kill_stream, _) = listener.accept().unwrap();
        assert_eq!(read_service(&mut kill_stream), "host:kill");
        kill_stream.write_all(b"OKAY").unwrap();
    });

    let output = adb_command(port, home.path(), &log_path)
        .arg("start-server")
        .output()
        .unwrap();
    old_server.join().unwrap();
    assert!(output.status.success(), "start-server 失败: {output:?}");
    assert_eq!(
        std::fs::read(&marker_path).unwrap(),
        newer_adb.as_os_str().as_bytes(),
        "新 server 应把自身可执行路径写回 marker"
    );

    let server = StartedServer {
        port,
        log_path,
        _home: home,
    };
    assert_eq!(
        client::server_version(&ServerEndpoint::for_port(port)).unwrap(),
        protocol::ADB_SERVER_VERSION
    );
    drop(server);
}

#[cfg(target_os = "linux")]
#[test]
fn newer_server_exec_failure_falls_back_to_kill_and_restart() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = tempfile::tempdir().unwrap();
    let log_path = home.path().join("adb.log");
    let android_dir = home.path().join(".android");
    std::fs::create_dir_all(&android_dir).unwrap();
    std::fs::write(
        android_dir.join(format!("adb.{port}")),
        home.path().join("missing-adb").as_os_str().as_bytes(),
    )
    .unwrap();

    let newer_version = format!("{:04x}", protocol::ADB_SERVER_VERSION + 1);
    let old_server = thread::spawn(move || {
        let (mut version_stream, _) = listener.accept().unwrap();
        assert_eq!(read_service(&mut version_stream), "host:version");
        write_query_response(&mut version_stream, &newer_version);

        let (mut kill_stream, _) = listener.accept().unwrap();
        assert_eq!(read_service(&mut kill_stream), "host:kill");
        kill_stream.write_all(b"OKAY").unwrap();
    });

    let output = adb_command(port, home.path(), &log_path)
        .arg("start-server")
        .output()
        .unwrap();
    old_server.join().unwrap();
    assert!(output.status.success(), "start-server 失败: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to exec newer version"),
        "缺少 re-exec 失败诊断: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let server = StartedServer {
        port,
        log_path,
        _home: home,
    };
    assert_eq!(
        client::server_version(&ServerEndpoint::for_port(port)).unwrap(),
        protocol::ADB_SERVER_VERSION
    );
    drop(server);
}

#[test]
fn burst_mode_controls_features_and_server_status() {
    let (normal, normal_start) = StartedServer::start(&[]);
    assert!(
        normal_start.status.success(),
        "普通 server 启动失败: {normal_start:?}"
    );
    let normal_features = normal.run(&["host-features"]);
    assert!(normal_features.status.success());
    assert!(!String::from_utf8_lossy(&normal_features.stdout).contains("delayed_ack"));
    let normal_status = normal.run(&["server-status"]);
    assert!(String::from_utf8_lossy(&normal_status.stdout).contains("burst_mode: false"));
    drop(normal);

    let (burst, burst_start) = StartedServer::start(&[("ADB_BURST_MODE", "1")]);
    assert!(
        burst_start.status.success(),
        "burst server 启动失败: {burst_start:?}"
    );
    let burst_features = burst.run(&["host-features"]);
    assert!(burst_features.status.success());
    assert!(String::from_utf8_lossy(&burst_features.stdout).contains("delayed_ack"));
    let burst_status = burst.run(&["server-status"]);
    assert!(String::from_utf8_lossy(&burst_status.stdout).contains("burst_mode: true"));
}

#[test]
fn daemon_log_and_adb_trace_receive_service_events() {
    let (server, start) = StartedServer::start(&[("ADB_TRACE", "services,bogus")]);
    assert!(start.status.success(), "trace server 启动失败: {start:?}");
    let output = server.run(&["host-features"]);
    assert!(output.status.success(), "host-features 失败: {output:?}");

    let log = server.read_log_until("host:host-features");
    assert!(
        log.contains("--- adb-rust starting"),
        "缺少 daemon 启动日志: {log:?}"
    );
    assert!(
        log.contains("smart service \"host:host-features\""),
        "ADB_TRACE=services 没有写入 service trace: {log:?}"
    );
    assert!(
        log.contains("Unknown trace flag: bogus"),
        "未知 ADB_TRACE 标签没有按 AOSP 记录诊断: {log:?}"
    );
}

#[cfg(unix)]
#[test]
fn localfilesystem_server_socket_supports_start_query_kill_and_stale_restart() {
    let home = tempfile::tempdir().unwrap();
    let socket = home.path().join("adb.sock");
    let socket_spec = format!("localfilesystem:{}", socket.display());
    let log_path = home.path().join("adb.log");
    let endpoint = client::parse_socket_spec(&socket_spec).unwrap();

    let start = socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("start-server")
        .output()
        .unwrap();
    assert!(
        start.status.success(),
        "localfilesystem 启动失败: {start:?}"
    );
    assert_eq!(
        client::server_version(&endpoint).unwrap(),
        protocol::ADB_SERVER_VERSION
    );

    let status = socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("server-status")
        .output()
        .unwrap();
    assert!(status.status.success(), "server-status 失败: {status:?}");

    let kill = socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("kill-server")
        .output()
        .unwrap();
    assert!(kill.status.success(), "kill-server 失败: {kill:?}");
    assert!(socket.exists(), "应与 AOSP 一样保留 filesystem socket 节点");

    let restart = env_socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("start-server")
        .output()
        .unwrap();
    assert!(
        restart.status.success(),
        "残留 socket 节点后的重启失败: {restart:?}"
    );
    assert_eq!(
        client::server_version(&endpoint).unwrap(),
        protocol::ADB_SERVER_VERSION
    );
    let _ = env_socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("kill-server")
        .output();
}

#[cfg(target_os = "linux")]
#[test]
fn localabstract_server_socket_supports_start_query_and_kill() {
    let home = tempfile::tempdir().unwrap();
    let socket_spec = format!(
        "localabstract:adb-rust-test-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    let log_path = home.path().join("adb.log");
    let endpoint = client::parse_socket_spec(&socket_spec).unwrap();

    let start = socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("start-server")
        .output()
        .unwrap();
    assert!(start.status.success(), "localabstract 启动失败: {start:?}");
    assert_eq!(
        client::server_version(&endpoint).unwrap(),
        protocol::ADB_SERVER_VERSION
    );
    let kill = socket_adb_command(&socket_spec, home.path(), &log_path)
        .arg("kill-server")
        .output()
        .unwrap();
    assert!(kill.status.success(), "kill-server 失败: {kill:?}");
}

#[cfg(unix)]
#[test]
fn acceptfd_server_socket_serves_inherited_listener() {
    let home = tempfile::tempdir().unwrap();
    let log_path = home.path().join("adb.log");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let fd = listener.as_raw_fd();
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(original_flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags & !libc::FD_CLOEXEC) },
        0
    );

    let socket_spec = format!("acceptfd:{fd}");
    let mut child = socket_adb_command(&socket_spec, home.path(), &log_path)
        .args(["server", "nodaemon"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags) }, 0);

    let mut version = TcpStream::connect(address).unwrap();
    version
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    protocol::write_protocol_string(&mut version, "host:version").unwrap();
    protocol::read_status(&mut version).unwrap();
    assert_eq!(
        protocol::read_protocol_string(&mut version).unwrap(),
        format!("{:04X}", protocol::ADB_SERVER_VERSION)
    );

    let mut kill = TcpStream::connect(address).unwrap();
    kill.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    protocol::write_protocol_string(&mut kill, "host:kill").unwrap();
    protocol::read_status(&mut kill).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "acceptfd server 异常退出: {status}");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("acceptfd server 未响应 host:kill");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn adb_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_adb"))
}

fn adb_command(port: u16, home: &Path, log_path: &Path) -> Command {
    let mut command = Command::new(adb_bin());
    command
        .arg("-P")
        .arg(port.to_string())
        .env("ANDROID_SDK_HOME", home)
        .env("ANDROID_ADB_LOG_PATH", log_path)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0");
    command
}

#[cfg(unix)]
fn socket_adb_command(socket_spec: &str, home: &Path, log_path: &Path) -> Command {
    let mut command = Command::new(adb_bin());
    command
        .arg("-L")
        .arg(socket_spec)
        .env("ANDROID_SDK_HOME", home)
        .env("ANDROID_ADB_LOG_PATH", log_path)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0");
    command
}

#[cfg(unix)]
fn env_socket_adb_command(socket_spec: &str, home: &Path, log_path: &Path) -> Command {
    let mut command = Command::new(adb_bin());
    command
        .env("ADB_SERVER_SOCKET", socket_spec)
        .env("ANDROID_SDK_HOME", home)
        .env("ANDROID_ADB_LOG_PATH", log_path)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0");
    command
}

fn read_service(stream: &mut TcpStream) -> String {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).unwrap();
    let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
    let mut service = vec![0_u8; length];
    stream.read_exact(&mut service).unwrap();
    String::from_utf8(service).unwrap()
}

fn write_query_response(stream: &mut TcpStream, body: &str) {
    stream.write_all(b"OKAY").unwrap();
    write!(stream, "{:04x}{body}", body.len()).unwrap();
}
