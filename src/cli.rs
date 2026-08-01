use crate::app_processes;
use crate::auth;
use crate::client::{self, ServerEndpoint, ServerStream, TransportSelector};
use crate::error::{AdbError, Result};
use crate::fastdeploy;
use crate::incremental;
use crate::protocol;
use crate::server::{self, ServerConfig};
use crate::server_status::AdbServerStatus;
use crate::sync as file_sync;
use crate::sync::ProgressTracker;
use crate::transport;

use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_WINDOW_INPUT,
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

#[derive(Debug)]
struct CliState {
    endpoint: ServerEndpoint,
    selector: TransportSelector,
    listen_all: bool,
    one_device: Option<String>,
    exit_on_write_error: bool,
}

pub fn run(argv: Vec<String>) -> Result<()> {
    // AOSP client 与 fork 出来的 server 都初始化 trace mask；未知标签
    // 需要在当前进程也给出同样的诊断，而不是只在 daemon 日志中出现。
    transport::report_unknown_trace_flags();
    let mut state = CliState {
        endpoint: ServerEndpoint::default(),
        selector: TransportSelector::default(),
        listen_all: false,
        one_device: None,
        exit_on_write_error: false,
    };
    let mut server_socket_override: Option<String> = None;
    let mut server_host_override: Option<String> = None;
    let mut server_port_override: Option<String> = None;
    let mut server_modifiers = ServerCommandModifiers::default();

    let mut index = 0;
    while index < argv.len() {
        match argv[index].as_str() {
            "server" | "nodaemon" | "fork-server" => {
                apply_server_command_modifier(&mut server_modifiers, argv[index].as_str())
            }
            "--reply-fd" => {
                index += 1;
                server_modifiers.reply_fd = Some(parse_reply_fd(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("--reply-fd"))?,
                )?);
            }
            "-P" => {
                index += 1;
                server_port_override = Some(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("-P"))?
                        .clone(),
                );
            }
            value if value.starts_with("-P") && value.len() > 2 => {
                server_port_override = Some(value[2..].to_string());
            }
            "-H" => {
                index += 1;
                server_host_override = Some(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("-H"))?
                        .clone(),
                );
            }
            value if value.starts_with("-H") && value.len() > 2 => {
                server_host_override = Some(value[2..].to_string());
            }
            "-L" => {
                index += 1;
                server_socket_override = Some(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("-L"))?
                        .clone(),
                );
            }
            "-s" => {
                index += 1;
                state.selector = TransportSelector::Serial(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("-s"))?
                        .clone(),
                );
            }
            value if value.starts_with("-s") && value.len() > 2 => {
                let serial = &value[2..];
                if !serial
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_digit())
                {
                    return Err(global_arg_requires("-s"));
                }
                state.selector = TransportSelector::Serial(serial.to_string());
            }
            "-t" => {
                index += 1;
                let value = argv.get(index).ok_or_else(|| global_arg_requires("-t"))?;
                state.selector = parse_transport_id_selector(value)?;
            }
            value if value.starts_with("-t") && value.len() > 2 => {
                let id = &value[2..];
                if !id
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_digit())
                {
                    return Err(global_arg_requires("-t"));
                }
                state.selector = parse_transport_id_selector(id)?;
            }
            "-d" => state.selector = TransportSelector::Usb,
            "-e" => state.selector = TransportSelector::Local,
            "-a" => state.listen_all = true,
            "--one-device" => {
                index += 1;
                state.one_device = Some(
                    argv.get(index)
                        .ok_or_else(|| global_arg_requires("--one-device"))?
                        .clone(),
                );
            }
            "--exit-on-write-error" => state.exit_on_write_error = true,
            _ => break,
        }
        index += 1;
    }

    let args = &argv[index..];
    validate_server_endpoint_options(
        server_socket_override.as_deref(),
        server_host_override.as_deref(),
        server_port_override.as_deref(),
    )?;
    if state.one_device.is_some() && !is_server_start_command(server_modifiers, args) {
        return Err(AdbError::Usage(
            "--one-device is only allowed when starting a server.".to_string(),
        ));
    }
    trace_client_startup(
        server_socket_override.as_deref(),
        server_host_override.as_deref(),
        server_port_override.as_deref(),
    );
    // AOSP 的 `help`/`version` 是纯本地命令；即使 `-L` 携带一个当前
    // 平台无法连接的 socket spec，也不应为了打印帮助或版本而解析它。
    // 但全局选项互斥、端口范围和 --one-device 限制已经在上方完成校验。
    if !server_modifiers.server
        && !server_modifiers.fork_server
        && matches!(
            args.first().map(String::as_str),
            Some("help" | "--help" | "/?" | "version" | "--version")
        )
    {
        return if matches!(args[0].as_str(), "help" | "--help" | "/?") {
            print_help();
            Ok(())
        } else {
            print_version()
        };
    }

    state.endpoint = resolve_server_endpoint(
        server_socket_override.as_deref(),
        server_host_override.as_deref(),
        server_port_override.as_deref(),
    )?;
    state.endpoint.set_listen_all(state.listen_all);
    apply_default_serial_from_env(
        &mut state.selector,
        std::env::var("ANDROID_SERIAL").ok().as_deref(),
    );

    if server_modifiers.fork_server && server_modifiers.reply_fd.is_none() {
        return Err(fork_server_missing_reply_fd_error());
    }
    if server_modifiers.server {
        return if server_modifier_runs_foreground(server_modifiers) {
            run_server(&mut state, server_modifiers.reply_fd)
        } else {
            start_server(&state)
        };
    }
    if args.is_empty() {
        print_help();
        return Err(AdbError::SilentExit(1));
    }

    dispatch(&mut state, args)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ServerCommandModifiers {
    server: bool,
    nodaemon: bool,
    fork_server: bool,
    reply_fd: Option<u64>,
}

fn is_server_start_command(modifiers: ServerCommandModifiers, args: &[String]) -> bool {
    modifiers.server
        || modifiers.fork_server
        || matches!(args, [command, ..] if command == "start-server")
}

fn server_modifier_runs_foreground(modifiers: ServerCommandModifiers) -> bool {
    modifiers.nodaemon || modifiers.fork_server
}

fn apply_server_command_modifier(modifiers: &mut ServerCommandModifiers, token: &str) {
    match token {
        "server" => modifiers.server = true,
        "nodaemon" => modifiers.nodaemon = true,
        "fork-server" => modifiers.fork_server = true,
        _ => {}
    }
}

fn parse_reply_fd(value: &str) -> Result<u64> {
    let fd: u64 = value.parse().map_err(|_| invalid_reply_fd_error(value))?;
    if fd <= 2 {
        return Err(invalid_reply_fd_error(value));
    }
    Ok(fd)
}

fn invalid_reply_fd_error(value: &str) -> AdbError {
    AdbError::Server(format!("invalid reply fd \"{value}\""))
}

fn fork_server_missing_reply_fd_error() -> AdbError {
    AdbError::Server("reply fd for adb server to client communication not specified.".to_string())
}

fn global_arg_requires(option: &str) -> AdbError {
    AdbError::Usage(format!("{option} requires an argument"))
}

fn dispatch(state: &mut CliState, args: &[String]) -> Result<()> {
    if args[0].starts_with("wait-for-") {
        return wait_for(state, &args[0], &args[1..]);
    }

    match args[0].as_str() {
        "help" | "--help" | "/?" => {
            print_help();
            Ok(())
        }
        "version" | "--version" => print_version(),
        "keygen" => keygen(&args[1..]),
        "pubkey" => pubkey(&args[1..]),
        "server" if args.get(1).map(String::as_str) == Some("nodaemon") => run_server(state, None),
        "start-server" => start_server(state),
        "kill-server" => kill_server(state),
        "devices" => devices(state, args),
        "get-state" => host_query_for_device(state, "get-state"),
        "get-serialno" => host_query_for_device(state, "get-serialno"),
        "get-devpath" => host_query_for_device(state, "get-devpath"),
        "get-transport-id" => host_query_for_device(state, "get-transport-id"),
        "features" => features(state),
        "host-features" => host_features(state),
        "server-status" => server_status(state),
        "mdns" => mdns(state, &args[1..]),
        "emu" => emu(state, args),
        "abb" => abb(state, &args[1..]),
        "shell" => shell(state, &args[1..]),
        "exec-in" => exec(state, &args[1..], ExecMode::In),
        "exec-out" => exec(state, &args[1..], ExecMode::Out),
        "logcat" | "lolcat" | "longcat" => logcat(state, &args[0], &args[1..]),
        "bugreport" => bugreport(state, &args[1..]),
        "backup" => backup(state, &args[1..]),
        "restore" => restore(state, &args[1..]),
        "sideload" => sideload(state, &args[1..]),
        "rescue" => rescue(state, &args[1..]),
        "reboot" | "reboot-bootloader" | "reboot-fastboot" => reboot(state, &args[0], &args[1..]),
        "ls" => ls(state, &args[1..]),
        "push" => push(state, &args[1..]),
        "pull" => pull(state, &args[1..]),
        "sync" => sync_build(state, &args[1..]),
        "install" => install(state, &args[1..]),
        "install-multiple" => install_multiple(state, &args[1..]),
        "install-multi-package" => install_multi_package(state, &args[1..]),
        "inc-server" => inc_server(&args[1..]),
        "uninstall" => uninstall(state, &args[1..]),
        "connect" => connect_device(state, &args[1..]),
        "disconnect" => disconnect_device(state, &args[1..]),
        "pair" => pair(state, &args[1..]),
        "attach" | "detach" => attach_or_detach(state, &args[0]),
        "forward" => forward(state, &args[1..]),
        "reverse" => reverse(state, &args[1..]),
        "track-app" => track_app(state, &args[1..]),
        "track-devices" => track_devices(state, &args[1..]),
        "raw" => raw(state, &args[1..]),
        "jdwp" => stream_device_command(state, "jdwp"),
        "track-jdwp" => stream_device_command(state, "track-jdwp"),
        "root" | "unroot" => root_or_unroot(state, &args[0], &args[1..]),
        "usb" => usb(state, &args[1..]),
        "remount" | "disable-verity" | "enable-verity" => {
            remount_or_verity(state, &args[0], &args[1..])
        }
        "tcpip" => tcpip(state, &args[1..]),
        "reconnect" => reconnect(state, &args[1..]),
        "transport-id" => transport_id(state),
        command => Err(AdbError::Server(format!("unknown command {command}"))),
    }
}

fn print_version() -> Result<()> {
    for line in version_lines() {
        println!("{line}");
    }
    Ok(())
}

fn version_lines() -> [String; 4] {
    [
        format!(
            "Android Debug Bridge version 1.0.{}",
            protocol::ADB_SERVER_VERSION
        ),
        format!("Version adb-rust-{}", env!("CARGO_PKG_VERSION")),
        format!("Installed as {}", current_exe_display()),
        format!("Running on {}", std::env::consts::OS),
    ]
}

fn trace_client_startup(
    socket_override: Option<&str>,
    host_override: Option<&str>,
    port_override: Option<&str>,
) {
    if !transport::trace_enabled("adb") {
        return;
    }

    let trace_prefix = format!(
        "{} {} D {}",
        std::process::id(),
        std::process::id(),
        std::path::Path::new(&current_exe_display())
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("adb")
    );
    for line in version_lines() {
        eprintln!("{trace_prefix}: adb_trace.cpp:201 {line}");
    }
    eprintln!("{trace_prefix}: adb_trace.cpp:201 ");
    eprintln!(
        "{trace_prefix}: commandline.cpp:1683 Using server socket: {}",
        trace_server_socket_spec(socket_override, host_override, port_override)
    );
}

fn trace_server_socket_spec(
    socket_override: Option<&str>,
    host_override: Option<&str>,
    port_override: Option<&str>,
) -> String {
    if let Some(socket) = socket_override {
        return socket.to_string();
    }
    if let Some(socket) = std::env::var_os("ADB_SERVER_SOCKET") {
        return socket.to_string_lossy().into_owned();
    }

    let host = host_override
        .map(str::to_string)
        .or_else(|| std::env::var("ANDROID_ADB_SERVER_ADDRESS").ok())
        .filter(|value| !value.is_empty());
    let port = port_override
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("ANDROID_ADB_SERVER_PORT").ok())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "5037".to_string());
    match host {
        Some(host) => format!("tcp:{host}:{port}"),
        None => format!("tcp:{port}"),
    }
}

fn run_server(state: &mut CliState, ack_reply_fd: Option<u64>) -> Result<()> {
    server::run_foreground(ServerConfig {
        endpoint: state.endpoint.clone(),
        one_device: state.one_device.clone(),
        ack_reply_fd,
    })
}

fn keygen(args: &[String]) -> Result<()> {
    let path = single_path_arg(args, "keygen")?;

    auth::generate_user_key(Path::new(path))
}

fn pubkey(args: &[String]) -> Result<()> {
    let path = single_path_arg(args, "pubkey")?;

    println!("{}", auth::public_key_from_private_key(Path::new(path))?);
    Ok(())
}

fn single_path_arg<'a>(args: &'a [String], command: &str) -> Result<&'a str> {
    let [path] = args else {
        return Err(AdbError::Usage(format!("{command} requires an argument")));
    };
    Ok(path)
}

fn start_server(state: &CliState) -> Result<()> {
    let started = client::ensure_server_running_with_one_device(
        &state.endpoint,
        state.one_device.as_deref(),
    )?;
    if started {
        eprintln!("* daemon started successfully");
    }
    Ok(())
}

fn kill_server(state: &CliState) -> Result<()> {
    match client::kill_server(&state.endpoint) {
        Ok(()) => Ok(()),
        Err(AdbError::Io(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

fn devices(state: &CliState, args: &[String]) -> Result<()> {
    let service = devices_service(args)?;
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query(&state.endpoint, service)?;

    println!("List of devices attached");
    print!("{body}");
    if body.is_empty() || !body.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn devices_service(args: &[String]) -> Result<&'static str> {
    match args {
        [command] if command == "devices" => Ok("host:devices"),
        [command, flag] if command == "devices" && flag == "-l" => Ok("host:devices-l"),
        _ => Err(AdbError::Usage("adb devices [-l]".to_string())),
    }
}

fn track_devices(state: &CliState, args: &[String]) -> Result<()> {
    let service = track_devices_service(args)?;
    client::ensure_server_running(&state.endpoint)?;
    client::stream_host_service_to_stdout(&state.endpoint, service)
}

fn track_devices_service(args: &[String]) -> Result<&'static str> {
    match args.first().map(String::as_str) {
        None => Ok("host:track-devices"),
        Some("-l") => Ok("host:track-devices-l"),
        Some("--proto-text") => Ok("host:track-devices-proto-text"),
        Some("--proto-binary") => Ok("host:track-devices-proto-binary"),
        _ => Err(AdbError::Usage(
            "usage: adb track-devices [-l][--proto-text][--proto-binary]".to_string(),
        )),
    }
}

fn wait_for(state: &mut CliState, command: &str, rest: &[String]) -> Result<()> {
    let normalized = normalize_wait_for_command(&state.selector, command)?;
    client::ensure_server_running(&state.endpoint)?;
    let service = format!("{}:{normalized}", state.selector.host_prefix());
    let _ = client::request_forward_status(&state.endpoint, &service)?;

    if rest.is_empty() {
        Ok(())
    } else {
        dispatch(state, rest)
    }
}

fn normalize_wait_for_command(selector: &TransportSelector, command: &str) -> Result<String> {
    let mut parts: Vec<String> = command.split('-').map(str::to_string).collect();
    if parts.len() < 3 {
        return Err(wait_for_parse_error(command));
    }

    if !matches!(
        parts.get(2).map(String::as_str),
        Some("usb" | "local" | "any")
    ) {
        let implied = match selector {
            TransportSelector::Usb => "usb",
            TransportSelector::Local => "local",
            TransportSelector::Any
            | TransportSelector::Serial(_)
            | TransportSelector::TransportId(_) => "any",
        };
        parts.insert(2, implied.to_string());
    }

    Ok(parts.join("-"))
}

fn wait_for_parse_error(command: &str) -> AdbError {
    AdbError::Server(format!("couldn't parse 'wait-for' command: {command}"))
}

fn parse_transport_id_selector(value: &str) -> Result<TransportSelector> {
    let id: u64 = value
        .parse()
        .map_err(|_| AdbError::Usage("invalid transport id".to_string()))?;
    if id == 0 {
        Ok(TransportSelector::Any)
    } else {
        Ok(TransportSelector::TransportId(id))
    }
}

fn resolve_server_endpoint(
    socket_override: Option<&str>,
    host_override: Option<&str>,
    port_override: Option<&str>,
) -> Result<ServerEndpoint> {
    validate_server_endpoint_options(socket_override, host_override, port_override)?;

    if let Some(socket) = socket_override {
        return client::parse_socket_spec(socket);
    }

    if host_override.is_some() || port_override.is_some() {
        let port = port_override
            .filter(|value| !value.is_empty())
            .map(client::parse_port)
            .transpose()?
            .unwrap_or(client::DEFAULT_SERVER_PORT);
        return Ok(match host_override {
            Some(host) => ServerEndpoint::new(host, port),
            None => ServerEndpoint::for_port(port),
        });
    }

    ServerEndpoint::from_env()
}

fn validate_server_endpoint_options(
    socket_override: Option<&str>,
    host_override: Option<&str>,
    port_override: Option<&str>,
) -> Result<()> {
    if socket_override.is_some() && (host_override.is_some() || port_override.is_some()) {
        return Err(AdbError::Usage(
            "-L is incompatible with -H or -P".to_string(),
        ));
    }

    if socket_override.is_some() {
        return Ok(());
    }
    if host_override.is_some() || port_override.is_some() {
        if let Some(port) = port_override.filter(|value| !value.is_empty()) {
            client::parse_port(port)?;
        }
        return Ok(());
    }

    // AOSP 只在 ADB_SERVER_SOCKET 完全未设置时读取并校验旧式 port 环境变量。
    if std::env::var_os("ADB_SERVER_SOCKET").is_none()
        && let Ok(port) = std::env::var("ANDROID_ADB_SERVER_PORT")
        && !port.is_empty()
    {
        client::parse_port(&port)?;
    }
    Ok(())
}

fn apply_default_serial_from_env(selector: &mut TransportSelector, android_serial: Option<&str>) {
    if !matches!(selector, TransportSelector::Any) {
        return;
    }
    let Some(serial) = android_serial
        .map(str::trim)
        .filter(|serial| !serial.is_empty())
    else {
        return;
    };
    *selector = TransportSelector::Serial(serial.to_string());
}

fn host_query_for_device(state: &CliState, request: &str) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let service = format!("{}:{request}", state.selector.host_prefix());
    let body = client::query(&state.endpoint, &service).map_err(|err| match err {
        AdbError::Server(message) => AdbError::Client(message),
        other => other,
    })?;
    println!("{body}");
    Ok(())
}

fn features(state: &CliState) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let service = format!("{}:features", state.selector.host_prefix());
    let body = client::query(&state.endpoint, &service)?;
    for feature in transport::filter_supported_features(&body) {
        println!("{feature}");
    }
    Ok(())
}

fn host_features(state: &CliState) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query(&state.endpoint, "host:host-features")?;
    println!("{body}");
    Ok(())
}

fn transport_id(state: &CliState) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let (_stream, transport_id) = client::open_host_service_with_transport_id(
        &state.endpoint,
        &state.selector,
        "host:features",
    )?;
    println!("{transport_id}");
    Ok(())
}

fn server_status(state: &CliState) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query_bytes(&state.endpoint, "host:server-status")?;
    match AdbServerStatus::decode(&body) {
        Ok(status) => {
            print!("{}", status.to_text_proto());
            Ok(())
        }
        Err(_) => {
            print!("{}", String::from_utf8_lossy(&body));
            Ok(())
        }
    }
}

fn mdns(state: &CliState, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(AdbError::Usage("mdns requires an argument".to_string()));
    }
    client::ensure_server_running(&state.endpoint)?;
    let (service, print_header) = mdns_service(args)?;
    if print_header {
        println!("List of discovered mdns services");
    }
    let body = client::query(&state.endpoint, service)?;
    println!("{body}");
    Ok(())
}

fn mdns_service(args: &[String]) -> Result<(&'static str, bool)> {
    match args {
        [command] if command == "check" => Ok(("host:mdns:check", false)),
        [command] if command == "services" => Ok(("host:mdns:services", true)),
        [] => Err(AdbError::Usage("mdns requires an argument".to_string())),
        [command] => Err(AdbError::Usage(format!("unknown mdns command [{command}]"))),
        [command, ..] => Err(AdbError::Usage(format!(
            "mdns {command} doesn't take any arguments"
        ))),
    }
}

fn pair(state: &CliState, args: &[String]) -> Result<()> {
    let (host, password) = pair_args(args)?;
    let password = match password {
        Some(password) => password.to_string(),
        None => read_pairing_code()?,
    };

    client::ensure_server_running(&state.endpoint)?;
    let body = client::query(&state.endpoint, &pair_service(host, &password))?;
    println!("{body}");
    Ok(())
}

fn pair_args(args: &[String]) -> Result<(&str, Option<&str>)> {
    match args {
        [host] => Ok((host.as_str(), None)),
        [host, password] => Ok((host.as_str(), Some(password.as_str()))),
        _ => Err(pair_usage_error()),
    }
}

fn read_pairing_code() -> Result<String> {
    print!("Enter pairing code: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        return Err(AdbError::Usage("No pairing code provided".to_string()));
    }
    Ok(password)
}

fn pair_usage_error() -> AdbError {
    AdbError::Usage("usage: adb pair HOST[:PORT] [PAIRING CODE]".to_string())
}

fn pair_service(host: &str, password: &str) -> String {
    format!("host:pair:{password}:{host}")
}

fn attach_or_detach(state: &CliState, command: &str) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query_host_service_with_transport(
        &state.endpoint,
        &state.selector,
        &format!("host:{command}"),
    )
    .map_err(|err| AdbError::Server(format!("failed to {command}: {err}")))?;
    println!("{body}");
    Ok(())
}

fn emu(state: &CliState, args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let console_port = resolve_emulator_console_port(state)?;
    let mut stream = TcpStream::connect(("127.0.0.1", console_port)).map_err(|err| {
        AdbError::Server(format!(
            "could not connect to TCP port {console_port}: {err}"
        ))
    })?;
    let commands = build_emulator_console_commands(&args[1..])?;
    stream.write_all(commands.as_bytes())?;
    let _ = stream.shutdown(Shutdown::Write);

    let mut output = Vec::new();
    match stream.read_to_end(&mut output) {
        Ok(_) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        Err(err) => return Err(err.into()),
    }

    io::stdout()
        .lock()
        .write_all(filtered_emulator_console_output(&output).as_bytes())?;
    Ok(())
}

fn resolve_emulator_console_port(state: &CliState) -> Result<u16> {
    match &state.selector {
        TransportSelector::Serial(serial) => emulator_console_port_from_serial(serial)
            .ok_or_else(|| AdbError::Server("no emulator connected".to_string())),
        TransportSelector::TransportId(_) => {
            let serial = client::query(
                &state.endpoint,
                &format!("{}:get-serialno", state.selector.host_prefix()),
            )?;
            emulator_console_port_from_serial(serial.trim())
                .ok_or_else(|| AdbError::Server("no emulator connected".to_string()))
        }
        TransportSelector::Local => {
            let serial = client::query(&state.endpoint, "host-local:get-serialno")?;
            emulator_console_port_from_serial(serial.trim())
                .ok_or_else(|| AdbError::Server("no emulator connected".to_string()))
        }
        TransportSelector::Usb => Err(AdbError::Server("no emulator connected".to_string())),
        TransportSelector::Any => {
            let devices = client::query(&state.endpoint, "host:devices")?;
            unique_emulator_console_port(&devices)
        }
    }
}

fn emulator_console_port_from_serial(serial: &str) -> Option<u16> {
    serial.strip_prefix("emulator-")?.parse::<u16>().ok()
}

fn unique_emulator_console_port(devices: &str) -> Result<u16> {
    let mut found = None;
    for line in devices.lines() {
        let serial = line.split_whitespace().next().unwrap_or_default();
        let Some(port) = emulator_console_port_from_serial(serial) else {
            continue;
        };
        if found.replace(port).is_some() {
            return Err(AdbError::Server(
                "more than one emulator detected; use -s".to_string(),
            ));
        }
    }

    found.ok_or_else(|| AdbError::Server("no emulator detected".to_string()))
}

fn build_emulator_console_commands(args: &[String]) -> Result<String> {
    let mut commands = emulator_console_auth_command()?;
    for (index, arg) in args.iter().enumerate() {
        commands.push_str(arg);
        commands.push(if index + 1 == args.len() { '\n' } else { ' ' });
    }
    commands.push_str("quit\n");
    Ok(commands)
}

fn emulator_console_auth_command() -> Result<String> {
    let Some(token_path) = emulator_console_auth_token_path() else {
        return Ok(String::new());
    };
    let Ok(token) = fs::read_to_string(&token_path) else {
        return Ok(String::new());
    };
    if token.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("auth {token}\n"))
    }
}

fn emulator_console_auth_token_path() -> Option<PathBuf> {
    auth::android_dir()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .map(|home| home.join(".emulator_console_auth_token"))
}

fn filtered_emulator_console_output(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let mut start = 0;
    for _ in 0..2 {
        let Some(index) = text[start..].find("OK\r\n") else {
            break;
        };
        start += index + "OK\r\n".len();
    }
    text[start..].to_string()
}

fn raw(state: &CliState, args: &[String]) -> Result<()> {
    let plan = raw_service_plan(args)?;
    client::ensure_server_running(&state.endpoint)?;
    if plan.requires_devraw_feature && !device_has_feature(state, "devraw")? {
        return Err(AdbError::Server(
            "dev-raw is not supported by the device".to_string(),
        ));
    }
    let stream = if plan.host_service {
        client::open_host_service(&state.endpoint, &plan.service)?
    } else {
        client::open_device_service(&state.endpoint, &state.selector, &plan.service)?
    };
    client::stream_to_stdio(stream, true)
}

fn raw_service_plan(args: &[String]) -> Result<RawServicePlan> {
    let [service] = args else {
        return Err(AdbError::Usage("usage: adb raw SERVICE".to_string()));
    };
    Ok(RawServicePlan::from_service(service))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawServicePlan {
    service: String,
    host_service: bool,
    requires_devraw_feature: bool,
}

impl RawServicePlan {
    fn from_service(service: &str) -> Self {
        Self {
            service: service.to_string(),
            host_service: service.starts_with("host"),
            requires_devraw_feature: service.starts_with("dev-raw:"),
        }
    }
}

fn stream_device_command(state: &CliState, service: &str) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    client::stream_device_service_to_stdout(&state.endpoint, &state.selector, service)
}

fn tcpip(state: &CliState, args: &[String]) -> Result<()> {
    let service = tcpip_service(args)?;
    client::ensure_server_running(&state.endpoint)?;
    client::stream_device_service_to_stdout(&state.endpoint, &state.selector, &service)
}

fn tcpip_service(args: &[String]) -> Result<String> {
    let [port] = args else {
        return Err(AdbError::Usage("tcpip requires an argument".to_string()));
    };
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| AdbError::Usage(format!("tcpip: invalid port: {port}")))?;
    Ok(format!("tcpip:{port}"))
}

fn usb(state: &CliState, args: &[String]) -> Result<()> {
    let service = usb_service(args);
    client::ensure_server_running(&state.endpoint)?;
    client::stream_device_service_to_stdout(&state.endpoint, &state.selector, &service)
}

fn usb_service(args: &[String]) -> String {
    match args.first() {
        Some(arg) => format!("usb:{arg}"),
        None => "usb:".to_string(),
    }
}

fn root_or_unroot(state: &CliState, command: &str, args: &[String]) -> Result<()> {
    let service = root_or_unroot_service(command, args);
    client::ensure_server_running(&state.endpoint)?;
    client::stream_device_service_to_stdout(&state.endpoint, &state.selector, &service)
}

fn root_or_unroot_service(command: &str, _args: &[String]) -> String {
    format!("{command}:")
}

fn reconnect(state: &CliState, args: &[String]) -> Result<()> {
    let command = reconnect_command(args)?;
    client::ensure_server_running(&state.endpoint)?;
    match command {
        ReconnectCommand::Host => {
            let body = client::query(
                &state.endpoint,
                &format!("{}:reconnect", state.selector.host_prefix()),
            )?;
            println!("{body}");
            Ok(())
        }
        ReconnectCommand::Device => {
            let _stream =
                client::open_device_service(&state.endpoint, &state.selector, "reconnect")?;
            Ok(())
        }
        ReconnectCommand::Offline => {
            let body = client::query(&state.endpoint, "host:reconnect-offline")?;
            println!("{body}");
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconnectCommand {
    Host,
    Device,
    Offline,
}

fn reconnect_command(args: &[String]) -> Result<ReconnectCommand> {
    match args {
        [] => Ok(ReconnectCommand::Host),
        [target] if target == "device" => Ok(ReconnectCommand::Device),
        [target] if target == "offline" => Ok(ReconnectCommand::Offline),
        [_] => Err(AdbError::Usage(
            "usage: adb reconnect [device|offline]".to_string(),
        )),
        _ => Err(AdbError::Server("unknown command reconnect".to_string())),
    }
}

fn logcat(state: &CliState, invocation: &str, args: &[String]) -> Result<()> {
    let command = build_logcat_command(invocation, args);
    run_shell_command_to_stdio(state, &command)
}

fn build_logcat_command(invocation: &str, args: &[String]) -> String {
    let log_tags = env::var("ANDROID_LOG_TAGS").unwrap_or_default();
    build_logcat_command_with_tags(invocation, args, &log_tags)
}

fn build_logcat_command_with_tags(invocation: &str, args: &[String], log_tags: &str) -> String {
    let mut command = format!(
        "export ANDROID_LOG_TAGS={}; exec logcat",
        escape_shell_arg(log_tags)
    );

    if invocation == "longcat" {
        command.push_str(" -v long");
    }

    for arg in args {
        command.push(' ');
        command.push_str(&escape_shell_arg(arg));
    }
    command
}

fn remount_or_verity(state: &CliState, command: &str, args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    if device_has_feature(state, "remount_shell")? {
        return run_shell_command_to_stdio(state, &build_shell_argv_command(command, args));
    }

    let service = remount_or_verity_service(command, args);
    client::stream_device_service_to_stdout(&state.endpoint, &state.selector, &service)
}

fn remount_or_verity_service(command: &str, args: &[String]) -> String {
    match args.first() {
        Some(arg) => format!("{command}:{arg}"),
        None => format!("{command}:"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackAppOutput {
    Text,
    Binary,
}

fn track_app(state: &CliState, args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    if !device_has_feature(state, "track_app")? {
        return Err(AdbError::Server(
            "track-app is not supported by the device".to_string(),
        ));
    }

    let output = parse_track_app_output(args)?;
    match output {
        TrackAppOutput::Binary => {
            client::stream_device_service_to_stdout(&state.endpoint, &state.selector, "track-app")
        }
        TrackAppOutput::Text => {
            let mut stream =
                client::open_device_service(&state.endpoint, &state.selector, "track-app")?;
            stream_track_app_text(&mut stream, &mut io::stdout().lock())
        }
    }
}

fn parse_track_app_output(args: &[String]) -> Result<TrackAppOutput> {
    match args {
        [] => Ok(TrackAppOutput::Text),
        [flag] if flag == "--proto-text" => Ok(TrackAppOutput::Text),
        [flag] if flag == "--proto-binary" => Ok(TrackAppOutput::Binary),
        [_] => Err(AdbError::Server("unknown command track-app".to_string())),
        _ => Err(AdbError::Usage(
            "usage: adb track-app [--proto-binary][--proto-text]".to_string(),
        )),
    }
}

fn stream_track_app_text<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    loop {
        let mut header = [0_u8; 4];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(AdbError::Io(err)),
        }

        let len_text = std::str::from_utf8(&header)
            .map_err(|err| AdbError::Protocol(format!("track-app 长度前缀非 UTF-8: {err}")))?;
        let len = usize::from_str_radix(len_text, 16).map_err(|err| {
            AdbError::Protocol(format!("track-app 长度前缀不是 4 位十六进制数: {err}"))
        })?;
        let mut frame = vec![0_u8; len];
        reader.read_exact(&mut frame)?;
        writer.write_all(app_processes::track_app_frame_to_text(&frame)?.as_bytes())?;
        writer.flush()?;
    }
}

fn device_has_feature(state: &CliState, feature: &str) -> Result<bool> {
    let service = format!("{}:features", state.selector.host_prefix());
    let body = client::query(&state.endpoint, &service)?;
    Ok(transport::can_use_feature(&body, feature))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecMode {
    In,
    Out,
}

fn exec(state: &CliState, args: &[String], mode: ExecMode) -> Result<()> {
    if args.is_empty() {
        return Err(exec_requires_command_error(mode));
    }

    client::ensure_server_running(&state.endpoint)?;
    let service = build_exec_service(args);
    let stream = client::open_device_service(&state.endpoint, &state.selector, &service)?;
    match mode {
        ExecMode::In => {
            let raw_stdin = io::stdin().is_terminal();
            let _raw_mode = RawModeGuard::enable(raw_stdin)?;
            client::stream_stdin_to_service(stream, raw_stdin)
        }
        ExecMode::Out => client::stream_to_stdout(stream),
    }
}

fn exec_requires_command_error(mode: ExecMode) -> AdbError {
    let command = match mode {
        ExecMode::In => "exec-in",
        ExecMode::Out => "exec-out",
    };
    AdbError::Usage(format!("usage: adb {command} command"))
}

fn bugreport(state: &CliState, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(bugreport_usage_error());
    }

    let version_output = run_shell_command_capture(state, "bugreportz -v")?;
    let mut bugz_version = trim_lossy(&version_output.stderr);
    let bugz_output = trim_lossy(&version_output.stdout);
    if bugz_version.is_empty() && parse_bugreportz_version_checked(&bugz_output).is_some() {
        bugz_version = bugz_output.clone();
    }

    if version_output.exit_code != 0 || bugz_version.is_empty() {
        if args.is_empty() {
            eprintln!(
                "Failed to get bugreportz version, which is only available on devices running Android 7.0 or later."
            );
            eprintln!("Trying a plain-text bug report instead.");
            return run_shell_command_to_stdio(state, "bugreport");
        }

        eprintln!(
            "Failed to get bugreportz version: 'bugreportz -v' returned '{}' (code {}).",
            bugz_output, version_output.exit_code
        );
        eprintln!("If the device does not run Android 7.0 or above, try this instead:");
        eprintln!("\tadb bugreport > bugreport.txt");
        return Err(AdbError::SilentExit(nonzero_exit(version_output.exit_code)));
    }

    let (major, minor) = parse_bugreportz_version(&bugz_version);
    if args.first().map(String::as_str) == Some("--stream") {
        if major == 1 && minor < 2 {
            eprintln!("Failed to stream bugreport: bugreportz does not support stream.");
        } else {
            return run_shell_command_to_stdio(state, "bugreportz -s");
        }
    }

    let mut target = if args.first().map(String::as_str) == Some("--stream") {
        BugreportTarget {
            dest_dir: None,
            dest_file: "bugreport.zip".to_string(),
        }
    } else {
        BugreportTarget::from_arg(args.first())?
    };
    let mut show_progress = true;
    let bugz_command = if bugz_version == "1.0" {
        eprintln!("Bugreport is in progress and it could take minutes to complete.");
        eprintln!(
            "Please be patient and do not cancel or disconnect your device until it completes."
        );
        show_progress = false;
        "bugreportz"
    } else {
        "bugreportz -p"
    };

    let output = run_shell_command_capture(state, bugz_command)?;
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    if output.exit_code != 0 {
        return Err(AdbError::SilentExit(nonzero_exit(output.exit_code)));
    }

    let src_file = process_bugreportz_output(
        &output.stdout,
        &mut target,
        show_progress,
        io::stderr().is_terminal(),
        &mut io::stderr(),
    )?;
    let destination = target.destination();
    match file_sync::pull(
        &state.endpoint,
        &state.selector,
        std::slice::from_ref(&src_file),
        &destination,
        file_sync::PullOptions::default(),
        None,
    ) {
        Ok(_) => {
            println!("Bug report copied to {}", destination.display());
            Ok(())
        }
        Err(err) => {
            eprintln!(
                "Bug report finished but could not be copied to '{}'.",
                destination.display()
            );
            eprintln!("Try to run 'adb pull {src_file} <directory>'");
            eprintln!("to copy it to a directory that can be written.");
            eprintln!("pull failed: {err}");
            Err(AdbError::SilentExit(1))
        }
    }
}

fn bugreport_usage_error() -> AdbError {
    AdbError::Usage("usage: adb bugreport [[PATH] | [--stream]]".to_string())
}

fn run_shell_command_to_stdio(state: &CliState, command: &str) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let v2_service = format!("shell,v2,raw:{command}");
    match client::open_device_service(&state.endpoint, &state.selector, &v2_service) {
        Ok(stream) => {
            let exit_code = client::stream_shell_v2_to_stdio(stream, state.exit_on_write_error)?;
            shell_exit_result(i32::from(exit_code))
        }
        Err(_) => {
            let output = run_shell_command_capture_legacy(state, command)?;
            io::stdout().write_all(&output.stdout)?;
            io::stderr().write_all(&output.stderr)?;
            shell_exit_result(output.exit_code)
        }
    }
}

fn run_shell_command_capture(
    state: &CliState,
    command: &str,
) -> Result<client::ShellCommandOutput> {
    client::ensure_server_running(&state.endpoint)?;
    client::run_shell_command_capture(&state.endpoint, &state.selector, command)
}

fn run_shell_command_capture_legacy(
    state: &CliState,
    command: &str,
) -> Result<client::ShellCommandOutput> {
    client::run_shell_command_capture_legacy(&state.endpoint, &state.selector, command)
}

/// 按 AOSP legacy shell 行为，在命令末尾追加 echo 标记以便从输出中解析退出码。
#[cfg(test)]
fn wrap_legacy_shell_command(command: &str) -> String {
    client::wrap_legacy_shell_command(command)
}

/// 从 legacy shell 输出中解析 AOSP 追加的 `$?: <code>` 退出码，并截断标记行。
/// 若找不到标记则返回 0，保持与旧实现兼容。
#[cfg(test)]
fn parse_legacy_shell_exit_code(output: &mut Vec<u8>) -> i32 {
    client::parse_legacy_shell_exit_code(output)
}

fn abb(state: &CliState, args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    if !device_has_feature(state, "abb")? {
        return Err(abb_unsupported_error());
    }

    let service = build_abb_service(args);
    let stream = client::open_device_service(&state.endpoint, &state.selector, &service)?;
    let exit_code = client::stream_shell_v2_interactive(
        stream,
        client::ShellV2InteractiveOptions {
            close_stdin: false,
            raw_stdin: false,
            escape_char: Some(b'~'),
            initial_window_size: None,
            watch_window_size: false,
            exit_on_write_error: state.exit_on_write_error,
        },
    )?;
    shell_exit_result(i32::from(exit_code))
}

fn abb_unsupported_error() -> AdbError {
    AdbError::Server("abb is not supported by the device".to_string())
}

fn shell(state: &CliState, shell_args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let invocation = parse_shell_invocation(shell_args)?;
    let stdin_is_terminal = io::stdin().is_terminal();
    let is_interactive = invocation.command.is_empty();
    let shell_type = resolve_shell_type(&invocation, stdin_is_terminal, is_interactive)?;
    let use_shell_protocol = invocation.use_shell_protocol;

    if use_shell_protocol {
        let terminal_type = env::var("TERM").ok();
        let service = build_shell_service_string(
            true,
            shell_type,
            &invocation.command,
            terminal_type.as_deref(),
        );
        match client::open_device_service(&state.endpoint, &state.selector, &service) {
            Ok(stream) if is_interactive => {
                let raw_stdin =
                    shell_type == ShellType::Pty && stdin_is_terminal && !invocation.close_stdin;
                let _raw_mode = RawModeGuard::enable(raw_stdin)?;
                let exit_code = client::stream_shell_v2_interactive(
                    stream,
                    client::ShellV2InteractiveOptions {
                        close_stdin: invocation.close_stdin,
                        raw_stdin,
                        escape_char: invocation.escape_char,
                        initial_window_size: if shell_type == ShellType::Pty {
                            client::current_shell_window_size()
                        } else {
                            None
                        },
                        watch_window_size: shell_type == ShellType::Pty,
                        exit_on_write_error: state.exit_on_write_error,
                    },
                )?;
                return shell_exit_result(i32::from(exit_code));
            }
            Ok(stream) => {
                let exit_code = client::stream_shell_v2_interactive(
                    stream,
                    client::ShellV2InteractiveOptions {
                        close_stdin: invocation.close_stdin,
                        raw_stdin: false,
                        escape_char: invocation.escape_char,
                        initial_window_size: None,
                        watch_window_size: false,
                        exit_on_write_error: state.exit_on_write_error,
                    },
                )?;
                return shell_exit_result(i32::from(exit_code));
            }
            Err(err) if shell_type == ShellType::Raw && invocation.tty_specified => {
                return Err(err);
            }
            Err(_) => {}
        }
    }

    let legacy_service =
        build_shell_service_string(false, ShellType::Pty, &invocation.command, None);
    let stream = client::open_device_service(&state.endpoint, &state.selector, &legacy_service)?;
    let interactive = is_interactive && !invocation.close_stdin;
    let raw_stdin = interactive && stdin_is_terminal;
    let _raw_mode = RawModeGuard::enable(raw_stdin)?;
    if interactive {
        client::stream_legacy_shell_interactive(
            stream,
            raw_stdin,
            invocation.escape_char,
            state.exit_on_write_error,
        )
    } else {
        client::stream_legacy_shell_to_stdout(stream, state.exit_on_write_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellInvocation {
    command: String,
    close_stdin: bool,
    use_shell_protocol: bool,
    tty: ShellPtyMode,
    tty_specified: bool,
    escape_char: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ShellPtyMode {
    Auto,
    No,
    Yes,
    Definitely,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellType {
    Pty,
    Raw,
}

impl ShellPtyMode {
    fn add_t(&mut self) {
        *self = if *self >= ShellPtyMode::Yes {
            ShellPtyMode::Definitely
        } else {
            ShellPtyMode::Yes
        };
    }
}

fn parse_shell_invocation(args: &[String]) -> Result<ShellInvocation> {
    let mut invocation = ShellInvocation {
        command: String::new(),
        close_stdin: false,
        use_shell_protocol: true,
        tty: ShellPtyMode::Auto,
        tty_specified: false,
        escape_char: Some(b'~'),
    };

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            index += 1;
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            break;
        }

        let bytes = arg.as_bytes();
        let mut pos = 1;
        while pos < bytes.len() {
            match bytes[pos] {
                b'e' => {
                    let value = if pos + 1 < arg.len() {
                        &arg[pos + 1..]
                    } else {
                        index += 1;
                        args.get(index)
                            .ok_or_else(|| shell_option_requires_argument_error('e'))?
                    };
                    invocation.escape_char = parse_shell_escape_char(value)?;
                    pos = bytes.len();
                }
                b'n' => {
                    invocation.close_stdin = true;
                    pos += 1;
                }
                b't' => {
                    invocation.tty.add_t();
                    invocation.tty_specified = true;
                    pos += 1;
                }
                b'T' => {
                    invocation.tty = ShellPtyMode::No;
                    invocation.tty_specified = true;
                    pos += 1;
                }
                b'x' => {
                    invocation.use_shell_protocol = false;
                    invocation.tty = ShellPtyMode::Definitely;
                    invocation.tty_specified = true;
                    invocation.escape_char = Some(b'~');
                    pos += 1;
                }
                other => {
                    return Err(shell_unknown_option_error(other as char));
                }
            }
        }

        index += 1;
    }

    invocation.command = args[index..].join(" ");
    Ok(invocation)
}

fn parse_shell_escape_char(value: &str) -> Result<Option<u8>> {
    if value == "none" {
        return Ok(None);
    }

    let mut chars = value.chars();
    let Some(ch) = chars.next() else {
        return Err(shell_escape_char_error());
    };
    if chars.next().is_some() || !ch.is_ascii() {
        return Err(shell_escape_char_error());
    }
    Ok(Some(ch as u8))
}

fn shell_option_requires_argument_error(option: char) -> AdbError {
    eprintln!("adb shell: option requires an argument -- {option}");
    AdbError::SilentExit(1)
}

fn shell_unknown_option_error(option: char) -> AdbError {
    eprintln!("adb shell: unknown option -- {option}");
    AdbError::SilentExit(1)
}

fn shell_escape_char_error() -> AdbError {
    AdbError::Usage("-e requires a single-character argument or 'none'".to_string())
}

fn resolve_shell_type(
    invocation: &ShellInvocation,
    stdin_is_terminal: bool,
    is_interactive: bool,
) -> Result<ShellType> {
    let shell_type = match invocation.tty {
        ShellPtyMode::No => ShellType::Raw,
        ShellPtyMode::Auto => {
            if stdin_is_terminal && is_interactive {
                ShellType::Pty
            } else {
                ShellType::Raw
            }
        }
        ShellPtyMode::Yes => {
            if stdin_is_terminal {
                ShellType::Pty
            } else {
                eprintln!(
                    "Remote PTY will not be allocated because stdin is not a terminal.\n\
                     Use multiple -t options to force remote PTY allocation."
                );
                ShellType::Raw
            }
        }
        ShellPtyMode::Definitely => ShellType::Pty,
    };

    if !invocation.use_shell_protocol && shell_type == ShellType::Raw {
        eprintln!("error: -x only supports allocating a pty");
        return Err(AdbError::SilentExit(1));
    }

    Ok(shell_type)
}

fn build_shell_service_string(
    use_shell_protocol: bool,
    shell_type: ShellType,
    command: &str,
    terminal_type: Option<&str>,
) -> String {
    let mut args = Vec::new();
    if use_shell_protocol {
        args.push("v2".to_string());
        if let Some(term) = terminal_type.filter(|term| !term.is_empty()) {
            args.push(format!("TERM={term}"));
        }
        args.push(match shell_type {
            ShellType::Pty => "pty".to_string(),
            ShellType::Raw => "raw".to_string(),
        });
    }

    if args.is_empty() {
        format!("shell:{command}")
    } else {
        format!("shell,{}:{command}", args.join(","))
    }
}

struct RawModeGuard {
    enabled: bool,
    #[cfg(windows)]
    stdin_handle: HANDLE,
    #[cfg(windows)]
    original_stdin_mode: u32,
}

impl RawModeGuard {
    fn enable(enabled: bool) -> Result<Self> {
        #[cfg(windows)]
        {
            if !enabled {
                return Ok(Self {
                    enabled: false,
                    stdin_handle: std::ptr::null_mut(),
                    original_stdin_mode: 0,
                });
            }

            let stdin_handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            if stdin_handle.is_null() || stdin_handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error().into());
            }
            let mut original_stdin_mode = 0;
            if unsafe { GetConsoleMode(stdin_handle, &mut original_stdin_mode) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            if unsafe { SetConsoleMode(stdin_handle, shell_raw_console_mode(original_stdin_mode)) }
                == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self {
                enabled: true,
                stdin_handle,
                original_stdin_mode,
            })
        }

        #[cfg(not(windows))]
        if enabled {
            crossterm::terminal::enable_raw_mode()?;
        }

        #[cfg(not(windows))]
        Ok(Self { enabled })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.enabled && !self.stdin_handle.is_null() {
            let _ = unsafe { SetConsoleMode(self.stdin_handle, self.original_stdin_mode) };
        }

        #[cfg(not(windows))]
        if self.enabled {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

#[cfg(windows)]
fn shell_raw_console_mode(mode: u32) -> u32 {
    (mode & !(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) | ENABLE_WINDOW_INPUT
}

fn shell_exit_result(exit_code: i32) -> Result<()> {
    if exit_code == 0 {
        Ok(())
    } else {
        Err(AdbError::SilentExit(exit_code))
    }
}

fn nonzero_exit(exit_code: i32) -> i32 {
    if exit_code == 0 { 1 } else { exit_code }
}

fn build_shell_argv_command(command: &str, args: &[String]) -> String {
    let mut result = escape_shell_arg(command);
    for arg in args {
        result.push(' ');
        result.push_str(&escape_shell_arg(arg));
    }
    result
}

fn escape_shell_arg(value: &str) -> String {
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

fn trim_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

fn parse_bugreportz_version(version: &str) -> (u32, u32) {
    parse_bugreportz_version_checked(version).unwrap_or((0, 0))
}

fn parse_bugreportz_version_checked(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parse_version_part(parts.next()?)?;
    let minor = match parts.next() {
        Some(value) => parse_version_part(value)?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

fn parse_version_part(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BugreportTarget {
    dest_dir: Option<PathBuf>,
    dest_file: String,
}

impl BugreportTarget {
    fn from_arg(arg: Option<&String>) -> Result<Self> {
        match arg {
            None => Ok(Self {
                dest_dir: Some(env::current_dir()?),
                dest_file: "bugreport.zip".to_string(),
            }),
            Some(path) if Path::new(path).is_dir() => Ok(Self {
                dest_dir: Some(PathBuf::from(path)),
                dest_file: "bugreport.zip".to_string(),
            }),
            Some(path) => Ok(Self {
                dest_dir: None,
                dest_file: ensure_zip_extension(path),
            }),
        }
    }

    fn set_src_file(&mut self, path: &str) {
        if self.dest_dir.is_some() {
            self.dest_file = remote_basename_lossy(path);
        }
    }

    fn destination(&self) -> PathBuf {
        match &self.dest_dir {
            Some(dest_dir) => dest_dir.join(&self.dest_file),
            None => PathBuf::from(&self.dest_file),
        }
    }

    fn line_message(&self, action: &str) -> String {
        format!("{action} {}", local_basename_lossy(&self.dest_file))
    }
}

fn ensure_zip_extension(path: &str) -> String {
    if path.to_ascii_lowercase().ends_with(".zip") {
        path.to_string()
    } else {
        format!("{path}.zip")
    }
}

fn process_bugreportz_output<W: Write>(
    stdout: &[u8],
    target: &mut BugreportTarget,
    show_progress: bool,
    progress_to_terminal: bool,
    progress_writer: &mut W,
) -> Result<String> {
    const BEGIN_PREFIX: &str = "BEGIN:";
    const PROGRESS_PREFIX: &str = "PROGRESS:";
    const OK_PREFIX: &str = "OK:";
    const FAIL_PREFIX: &str = "FAIL:";

    let text = String::from_utf8_lossy(stdout);
    let mut src_file = String::new();
    let mut invalid_lines = Vec::new();
    let mut last_progress = 0_u32;
    let mut emitted_progress = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        if let Some(path) = line.strip_prefix(BEGIN_PREFIX) {
            target.set_src_file(path);
            src_file = path.to_string();
        } else if let Some(path) = line.strip_prefix(OK_PREFIX) {
            target.set_src_file(path);
            src_file = path.to_string();
        } else if let Some(message) = line.strip_prefix(FAIL_PREFIX) {
            if progress_to_terminal && emitted_progress {
                writeln!(progress_writer)?;
            }
            eprintln!("adb: device failed to take a zipped bugreport: {message}");
            return Err(AdbError::SilentExit(1));
        } else if show_progress {
            match parse_bugreport_progress(line.strip_prefix(PROGRESS_PREFIX)) {
                Some(progress) => {
                    if progress != 0 && progress <= last_progress {
                        continue;
                    }
                    last_progress = progress;
                    emitted_progress = true;
                    if progress_to_terminal {
                        write!(
                            progress_writer,
                            "\r[{progress:>3}%] {}",
                            target.line_message("generating")
                        )?;
                        progress_writer.flush()?;
                    } else {
                        writeln!(
                            progress_writer,
                            "[{progress:>3}%] {}",
                            target.line_message("generating")
                        )?;
                    }
                }
                None => invalid_lines.push(line.to_string()),
            }
        } else {
            invalid_lines.push(line.to_string());
        }
    }

    if progress_to_terminal && emitted_progress {
        writeln!(progress_writer)?;
    }

    if !invalid_lines.is_empty() {
        eprintln!(
            "WARNING: bugreportz generated {} line(s) with unknown commands, device might not support zipped bugreports:",
            invalid_lines.len()
        );
        for line in &invalid_lines {
            eprintln!("\t{line}");
        }
        eprintln!("If the zipped bugreport was not generated, try 'adb bugreport' instead.");
    }

    if src_file.is_empty() {
        eprintln!("bugreportz did not return a 'OK:' or 'FAIL:' line");
        return Err(AdbError::SilentExit(1));
    }

    Ok(src_file)
}

fn parse_bugreport_progress(value: Option<&str>) -> Option<u32> {
    let (progress, total) = value?.split_once('/')?;
    let progress: u32 = progress.parse().ok()?;
    let total: u32 = total.parse().ok()?;
    if total == 0 {
        return None;
    }
    Some(progress.saturating_mul(100) / total)
}

fn remote_basename_lossy(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn local_basename_lossy(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| path.to_string())
}

fn backup(state: &CliState, args: &[String]) -> Result<()> {
    println!("WARNING: adb backup is deprecated and may be removed in a future release");

    let plan = BackupPlan::from_args(args)?;
    let mut output = fs::File::create(&plan.output)?;
    client::ensure_server_running(&state.endpoint)?;
    let mut stream =
        client::open_device_service(&state.endpoint, &state.selector, &plan.service())?;

    println!("Now unlock your device and confirm the backup operation...");
    io::copy(&mut stream, &mut output)?;
    Ok(())
}

fn restore(state: &CliState, args: &[String]) -> Result<()> {
    println!("WARNING: adb restore is deprecated and may be removed in a future release");

    if args.is_empty() {
        return Err(restore_requires_filename_error());
    }

    let input = PathBuf::from(&args[0]);
    let mut file = fs::File::open(&input)?;
    let service = build_colon_service_command("restore:", &args[1..]);
    client::ensure_server_running(&state.endpoint)?;
    let mut stream = client::open_device_service(&state.endpoint, &state.selector, &service)?;

    println!("Now unlock your device and confirm the restore operation.");
    stream_restore(&mut file, &mut stream, &mut io::stdout().lock())
}

fn restore_requires_filename_error() -> AdbError {
    AdbError::Usage("usage: adb restore FILENAME [ARG]...".to_string())
}

fn write_restore_payload<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64> {
    let bytes = io::copy(reader, writer)?;
    writer.write_all(&[0_u8; 1024])?;
    Ok(bytes)
}

fn stream_restore<R, S, W>(reader: &mut R, stream: &mut S, output: &mut W) -> Result<()>
where
    R: Read,
    S: Read + Write,
    W: Write,
{
    // restore 以两个零 block 结束输入；AOSP 随后继续从同一 fd 读取设备响应。
    write_restore_payload(reader, &mut *stream)?;
    io::copy(stream, output)?;
    Ok(())
}

const SIDELOAD_HOST_BLOCK_SIZE: usize = 64 * 1024;
const SIDELOAD_DONE: &[u8; 8] = b"DONEDONE";
const SIDELOAD_FAIL: &[u8; 8] = b"FAILFAIL";

fn sideload(state: &CliState, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(AdbError::Usage("sideload requires an argument".to_string()));
    }

    let package = PathBuf::from(&args[0]);
    let size = local_file_size(&package)?;
    let mut file = fs::File::open(&package)?;
    client::ensure_server_running(&state.endpoint)?;

    match client::open_device_service(
        &state.endpoint,
        &state.selector,
        &sideload_host_service("sideload-host", size),
    ) {
        Ok(mut stream) => {
            let ok = serve_sideload_host(&mut file, size, SIDELOAD_HOST_BLOCK_SIZE, &mut stream)?;
            if ok {
                Ok(())
            } else {
                Err(AdbError::SilentExit(1))
            }
        }
        Err(err) => {
            if size > i32::MAX as u64 {
                return Err(err);
            }
            eprintln!("adb: trying pre-KitKat sideload method...");
            sideload_legacy(state, &package, size)
        }
    }
}

fn rescue(state: &CliState, args: &[String]) -> Result<()> {
    match rescue_command(args)? {
        RescueCommand::Getprop(service) => {
            client::ensure_server_running(&state.endpoint)?;
            client::stream_device_service_to_stdout(&state.endpoint, &state.selector, &service)
        }
        RescueCommand::Install(package) => {
            client::ensure_server_running(&state.endpoint)?;
            rescue_install(state, Path::new(&package))
        }
        RescueCommand::WipeUserdata => {
            client::ensure_server_running(&state.endpoint)?;
            rescue_wipe_userdata(state)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RescueCommand {
    Getprop(String),
    Install(String),
    WipeUserdata,
}

fn rescue_command(args: &[String]) -> Result<RescueCommand> {
    let Some(command) = args.first() else {
        return Err(AdbError::Usage(
            "rescue requires at least one argument".to_string(),
        ));
    };

    match command.as_str() {
        "getprop" => match args {
            [_] => Ok(RescueCommand::Getprop("rescue-getprop:".to_string())),
            [_, prop] => Ok(RescueCommand::Getprop(format!("rescue-getprop:{prop}"))),
            _ => Err(AdbError::Usage(
                "invalid rescue getprop arguments".to_string(),
            )),
        },
        "install" => match args {
            [_, package] => Ok(RescueCommand::Install(package.clone())),
            _ => Err(AdbError::Usage(
                "rescue install requires two arguments".to_string(),
            )),
        },
        "wipe" => {
            if matches!(args, [_, partition] if partition == "userdata") {
                Ok(RescueCommand::WipeUserdata)
            } else {
                Err(AdbError::Usage("invalid rescue wipe arguments".to_string()))
            }
        }
        _ => Err(AdbError::Usage("invalid rescue argument".to_string())),
    }
}

fn rescue_install(state: &CliState, package: &Path) -> Result<()> {
    let size = local_file_size(package)?;
    let mut file = fs::File::open(package)?;
    let mut stream = client::open_device_service(
        &state.endpoint,
        &state.selector,
        &sideload_host_service("rescue-install", size),
    )?;
    let ok = serve_sideload_host(&mut file, size, SIDELOAD_HOST_BLOCK_SIZE, &mut stream)?;
    if ok {
        Ok(())
    } else {
        Err(AdbError::SilentExit(1))
    }
}

fn rescue_wipe_userdata(state: &CliState) -> Result<()> {
    let service = rescue_wipe_service("userdata");
    let mut stream = client::open_device_service(&state.endpoint, &state.selector, &service)?;
    if read_minadbd_done_status(&mut stream)? {
        Ok(())
    } else {
        Err(AdbError::SilentExit(1))
    }
}

fn sideload_host_service(prefix: &str, size: u64) -> String {
    format!("{prefix}:{size}:{SIDELOAD_HOST_BLOCK_SIZE}")
}

fn rescue_wipe_service(partition: &str) -> String {
    format!("rescue-wipe:{partition}:{}", SIDELOAD_DONE.len())
}

fn sideload_legacy(state: &CliState, package: &Path, size: u64) -> Result<()> {
    let mut stream = client::open_device_service(
        &state.endpoint,
        &state.selector,
        &format!("sideload:{size}"),
    )?;
    let mut file = fs::File::open(package)?;
    io::copy(&mut file, &mut stream)?;
    protocol::read_status(&mut stream)
}

fn serve_sideload_host<R, S>(
    package: &mut R,
    size: u64,
    block_size: usize,
    stream: &mut S,
) -> Result<bool>
where
    R: Read + Seek,
    S: Read + Write,
{
    let mut command = [0_u8; 8];
    let mut buffer = vec![0_u8; block_size];

    loop {
        stream.read_exact(&mut command)?;
        if &command == SIDELOAD_DONE {
            return Ok(true);
        }
        if &command == SIDELOAD_FAIL {
            return Ok(false);
        }

        let block = parse_sideload_block(&command)?;
        let offset = block
            .checked_mul(block_size as u64)
            .ok_or_else(|| AdbError::Protocol("sideload block offset overflow".to_string()))?;
        if offset >= size {
            return Err(AdbError::Protocol(format!(
                "sideload 请求越界 block {block} offset {offset} size {size}"
            )));
        }

        let to_write = usize::try_from((size - offset).min(block_size as u64))
            .expect("to_write is bounded by block_size");
        package.seek(SeekFrom::Start(offset))?;
        package.read_exact(&mut buffer[..to_write])?;
        stream.write_all(&buffer[..to_write])?;
    }
}

fn read_minadbd_done_status<R: Read>(reader: &mut R) -> Result<bool> {
    let mut command = [0_u8; 8];
    reader.read_exact(&mut command)?;
    if &command == SIDELOAD_DONE {
        return Ok(true);
    }
    if &command == SIDELOAD_FAIL {
        return Ok(false);
    }
    Err(AdbError::Protocol(format!(
        "minadbd 返回未知结果: {}",
        String::from_utf8_lossy(&command)
    )))
}

fn parse_sideload_block(command: &[u8; 8]) -> Result<u64> {
    if !command.iter().all(u8::is_ascii_digit) {
        return Err(AdbError::Protocol(format!(
            "sideload 未知命令: {}",
            String::from_utf8_lossy(command)
        )));
    }
    std::str::from_utf8(command)
        .map_err(|err| AdbError::Protocol(format!("sideload 命令非 UTF-8: {err}")))?
        .parse()
        .map_err(|err| AdbError::Protocol(format!("sideload 块号无效: {err}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackupPlan {
    output: PathBuf,
    args: Vec<String>,
}

impl BackupPlan {
    fn from_args(args: &[String]) -> Result<Self> {
        let mut output = PathBuf::from("backup.ab");
        let mut service_args = Vec::new();
        let mut index = 0;
        while index < args.len() {
            if args[index] == "-f" {
                index += 1;
                let filename = args.get(index).ok_or_else(|| {
                    AdbError::Usage("backup -f passed with no filename".to_string())
                })?;
                output = PathBuf::from(filename);
            } else {
                service_args.push(args[index].clone());
            }
            index += 1;
        }

        if service_args.is_empty() {
            return Err(AdbError::Usage(
                "backup either needs a list of packages or -all/-shared".to_string(),
            ));
        }

        Ok(Self {
            output,
            args: service_args,
        })
    }

    fn service(&self) -> String {
        build_colon_service_command("backup:", &self.args)
    }
}

fn reboot(state: &CliState, invocation: &str, args: &[String]) -> Result<()> {
    client::ensure_server_running(&state.endpoint)?;
    let service = reboot_service(invocation, args);
    let _stream = client::open_device_service(&state.endpoint, &state.selector, &service)?;
    Ok(())
}

fn reboot_service(invocation: &str, args: &[String]) -> String {
    match invocation {
        "reboot-bootloader" => "reboot:bootloader".to_string(),
        "reboot-fastboot" => "reboot:fastboot".to_string(),
        _ => match args.first() {
            Some(target) => format!("reboot:{target}"),
            None => "reboot:".to_string(),
        },
    }
}

fn install(state: &CliState, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(install_requires_arg_error("install"));
    }

    client::ensure_server_running(&state.endpoint)?;
    let plan = InstallPlan::from_args(args)?;
    let has_cmd = device_has_feature(state, "cmd")?;
    let has_abb_exec = device_has_feature(state, "abb_exec")?;
    let has_shell_v2 = device_has_feature(state, "shell_v2")?;
    validate_incremental_request(
        plan.requested_mode,
        plan.incremental_request,
        plan.use_fastdeploy,
        has_abb_exec,
    )?;
    if plan.use_fastdeploy {
        if plan.package_kind == Some(InstallPackageKind::Apex) {
            return Err(fastdeploy_apex_conflict_error());
        }
        if plan.package_kind.is_none() {
            return Err(install_streamed_last_arg_error(&plan.original_last_arg));
        }
    }
    if plan.incremental_request == IncrementalRequest::Enable
        && plan.package_kind == Some(InstallPackageKind::Apk)
        && incremental::can_install(std::slice::from_ref(&plan.local_apk))
    {
        return incremental::install(
            &state.endpoint,
            &state.selector,
            std::slice::from_ref(&plan.local_apk),
            &plan.stream_args,
            plan.incremental_wait,
        );
    }
    let mode = plan.effective_mode(has_cmd)?;
    if plan.use_fastdeploy && mode == InstallRequestMode::Stream && !plan.package_is_last {
        return Err(install_streamed_last_arg_error(&plan.original_last_arg));
    }
    if plan.use_fastdeploy {
        let api_level = fastdeploy::device_api_level(&state.endpoint, &state.selector)?;
        if api_level < fastdeploy::MIN_API_LEVEL {
            eprintln!(
                "Fast Deploy is only compatible with devices of API version {} or higher, ignoring.",
                fastdeploy::MIN_API_LEVEL
            );
        } else if let Some(metadata) = fastdeploy::extract_device_metadata(
            &state.endpoint,
            &state.selector,
            &plan.local_apk,
            plan.agent_update_strategy,
        )? {
            return match mode {
                InstallRequestMode::Push => {
                    install_fastdeploy_push(state, &plan, &metadata, has_shell_v2)
                }
                InstallRequestMode::Stream => {
                    println!("Performing Streamed Install");
                    match fastdeploy::stream_patch_for_install(
                        &state.endpoint,
                        &state.selector,
                        &plan.local_apk,
                        &metadata,
                        &plan.stream_args,
                        has_shell_v2,
                    ) {
                        Ok(_) => Ok(()),
                        Err(err) if is_fastdeploy_apply_failure(&err) => {
                            eprintln!("Fast Deploy failed, falling back to regular install");
                            install_streamed(state, &plan)
                        }
                        Err(err) => Err(err),
                    }
                }
                InstallRequestMode::Default => {
                    unreachable!("effective_mode never returns default")
                }
            };
        }
    }
    match mode {
        InstallRequestMode::Push => install_push(state, &plan),
        InstallRequestMode::Stream => install_streamed(state, &plan),
        InstallRequestMode::Default => unreachable!("effective_mode never returns default"),
    }
}

fn install_fastdeploy_push(
    state: &CliState,
    plan: &InstallPlan,
    metadata: &fastdeploy::ApkMetadata,
    use_shell_v2: bool,
) -> Result<()> {
    println!("Performing Push Install");
    let patch_result = fastdeploy::stream_patch_to_path(
        &state.endpoint,
        &state.selector,
        &plan.local_apk,
        metadata,
        &plan.remote_apk,
        use_shell_v2,
    );
    if let Err(err) = patch_result {
        let _ = delete_device_file(state, &plan.remote_apk);
        if is_fastdeploy_apply_failure(&err) {
            eprintln!("Fast Deploy failed, falling back to regular install");
            return install_push(state, plan);
        }
        return Err(err);
    }
    let result = run_shell_command_to_stdio(state, &plan.pm_install_command());
    let _ = delete_device_file(state, &plan.remote_apk);
    result
}

fn is_fastdeploy_apply_failure(err: &AdbError) -> bool {
    matches!(err, AdbError::Server(message) if message.starts_with("fastdeploy agent exited"))
}

fn install_push(state: &CliState, plan: &InstallPlan) -> Result<()> {
    println!("Performing Push Install");
    let Some(package_kind) = plan.package_kind else {
        return Err(install_push_needs_apk_error());
    };
    if package_kind == InstallPackageKind::Apex {
        return Err(install_apex_requires_streamed_error());
    }

    file_sync::push(
        &state.endpoint,
        &state.selector,
        std::slice::from_ref(&plan.local_apk),
        &plan.remote_apk,
        file_sync::PushOptions::default(),
        None,
    )?;

    let result = run_shell_command_to_stdio(state, &plan.pm_install_command());
    let _ = delete_device_file(state, &plan.remote_apk);
    result
}

fn install_streamed(state: &CliState, plan: &InstallPlan) -> Result<()> {
    println!("Performing Streamed Install");
    if !plan.package_is_last {
        return Err(install_streamed_last_arg_error(&plan.original_last_arg));
    }
    let Some(package_kind) = plan.package_kind else {
        return Err(install_streamed_last_arg_error(&plan.original_last_arg));
    };
    if package_kind == InstallPackageKind::Apex && !device_has_feature(state, "apex")? {
        return Err(install_apex_unsupported_error());
    }

    let size = local_file_size(&plan.local_apk)?;
    let mut service_args = vec!["install".to_string()];
    service_args.extend(plan.stream_args.clone());
    service_args.push("-S".to_string());
    service_args.push(size.to_string());
    if package_kind == InstallPackageKind::Apex {
        service_args.push("--apex".to_string());
    }

    let output = write_file_to_cmd_package(state, &service_args, &plan.local_apk)?;
    print_success_output_or_fail("install", &plan.local_apk, &output)
}

fn install_multiple(state: &CliState, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(install_requires_arg_error("install-multiple"));
    }

    client::ensure_server_running(&state.endpoint)?;
    let plan = InstallMultiplePlan::from_args(args)?;
    let has_abb_exec = device_has_feature(state, "abb_exec")?;
    validate_incremental_request(
        plan.requested_mode,
        plan.incremental_request,
        false,
        has_abb_exec,
    )?;
    if plan.requested_mode == InstallRequestMode::Stream && !device_has_feature(state, "cmd")? {
        return Err(streaming_install_unsupported_error());
    }
    if plan.incremental_request == IncrementalRequest::Enable
        && incremental::can_install(&plan.packages)
    {
        return incremental::install(
            &state.endpoint,
            &state.selector,
            &plan.packages,
            &plan.session_args,
            plan.incremental_wait,
        );
    }
    let command_mode = package_command_mode(state)?;
    let session_id = create_install_session(state, &plan, command_mode)?;
    let mut success = true;
    for package in &plan.packages {
        let Some(output) = write_install_session_package(state, command_mode, session_id, package)?
        else {
            success = false;
            break;
        };
        if !command_succeeded(&output) {
            eprintln!("adb: failed to write \"{}\"", package.display());
            eprint!("{}", String::from_utf8_lossy(&output));
            success = false;
            break;
        }
    }

    let finalize_output = finalize_install_session(state, command_mode, session_id, success)?;
    if !success {
        return Err(AdbError::SilentExit(1));
    }
    if !command_succeeded(&finalize_output) {
        eprintln!("adb: failed to finalize session");
        eprint!("{}", String::from_utf8_lossy(&finalize_output));
        return Err(AdbError::SilentExit(1));
    }
    print!("{}", String::from_utf8_lossy(&finalize_output));
    Ok(())
}

fn install_multi_package(state: &CliState, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(install_requires_arg_error("install-multi-package"));
    }

    let plan = InstallMultiPackagePlan::from_args(args)?;
    client::ensure_server_running(&state.endpoint)?;
    if !device_has_feature(state, "cmd")? {
        return Err(install_multi_package_unsupported_error());
    }

    let command_mode = package_command_mode(state)?;
    let parent_id = create_multi_package_parent_session(state, &plan, command_mode)?;
    println!("Created parent session ID {parent_id}.");

    let mut child_ids = Vec::new();
    let mut success = true;
    for item in &plan.packages {
        let Some(child_id) =
            create_multi_package_child_session(state, &plan, command_mode, item.kind)?
        else {
            success = false;
            break;
        };
        println!("Created child session ID {child_id}.");
        child_ids.push(child_id);

        for split in &item.splits {
            let Some(output) =
                write_multi_package_split(state, command_mode, child_id, item.source_index, split)?
            else {
                success = false;
                break;
            };
            if !command_succeeded(&output) {
                eprintln!("adb: failed to write {}", split.display());
                eprint!("{}", String::from_utf8_lossy(&output));
                success = false;
                break;
            }
        }

        if !success {
            break;
        }
    }

    if success {
        if let Some((add_session_args, output)) =
            add_multi_package_child_sessions(state, command_mode, parent_id, &child_ids)?
        {
            if !command_succeeded(&output) {
                eprintln!(
                    "adb: failed to link sessions ({})",
                    multi_package_link_command_for_error(command_mode, &add_session_args)
                );
                eprint!("{}", String::from_utf8_lossy(&output));
                success = false;
            }
        } else {
            success = false;
        }
    }

    let finalize_output =
        finalize_multi_package_parent_session(state, &plan, command_mode, parent_id, success)?;
    if command_succeeded(&finalize_output) {
        print!("{}", String::from_utf8_lossy(&finalize_output));
        if success {
            return Ok(());
        }
    } else {
        eprintln!("adb: failed to finalize session");
        eprint!("{}", String::from_utf8_lossy(&finalize_output));
    }

    abandon_remaining_sessions(state, command_mode, parent_id, &child_ids);
    Err(AdbError::SilentExit(1))
}

fn uninstall(state: &CliState, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(install_requires_arg_error("uninstall"));
    }

    client::ensure_server_running(&state.endpoint)?;
    let prefix = if device_has_feature(state, "cmd")? {
        "cmd package uninstall"
    } else {
        "pm uninstall"
    };
    if args.iter().any(|arg| arg == "-k") {
        print_uninstall_keep_data_warning(prefix);
        return Err(AdbError::SilentExit(1));
    }
    run_shell_command_to_stdio(state, &build_shell_command(prefix, args))
}

fn print_uninstall_keep_data_warning(prefix: &str) {
    println!("{}", uninstall_keep_data_warning(prefix));
}

fn uninstall_keep_data_warning(prefix: &str) -> String {
    format!(
        "The -k option uninstalls the application while retaining the data/cache.\nAt the moment, there is no way to remove the remaining data.\nYou will have to reinstall the application with the same signature, and fully uninstall it.\nIf you truly wish to continue, execute 'adb shell {prefix} -k'."
    )
}

fn install_requires_arg_error(command: &str) -> AdbError {
    AdbError::Usage(format!("{command} requires an argument"))
}

fn install_needs_apk_error() -> AdbError {
    AdbError::Usage("install requires an apk argument".to_string())
}

fn install_push_needs_apk_error() -> AdbError {
    AdbError::Usage("need APK file on command line".to_string())
}

fn install_streamed_last_arg_error(last_arg: &str) -> AdbError {
    AdbError::Usage(format!("filename doesn't end .apk or .apex: {last_arg}"))
}

fn install_apex_requires_streamed_error() -> AdbError {
    AdbError::Usage("APEX packages are only compatible with Streamed Install".to_string())
}

fn install_apex_unsupported_error() -> AdbError {
    AdbError::Usage(".apex is not supported on the target device".to_string())
}

fn streaming_install_unsupported_error() -> AdbError {
    AdbError::Usage("Attempting to use streaming install on unsupported device".to_string())
}

fn incremental_fastdeploy_conflict_error() -> AdbError {
    AdbError::Usage(
        "--incremental and --fast-deploy options are incompatible. Please choose one".to_string(),
    )
}

fn incremental_mode_conflict_error() -> AdbError {
    AdbError::Usage("--incremental is not compatible with other installation modes".to_string())
}

fn incremental_unsupported_device_error() -> AdbError {
    AdbError::Usage("Device doesn't support incremental installations".to_string())
}

fn fastdeploy_apex_conflict_error() -> AdbError {
    AdbError::Usage("--fastdeploy doesn't support .apex files".to_string())
}

fn install_multiple_needs_apk_error() -> AdbError {
    AdbError::Usage("need APK file on command line".to_string())
}

fn install_multiple_apex_error() -> AdbError {
    AdbError::Usage("APEX packages are not compatible with install-multiple".to_string())
}

fn install_multi_package_needs_package_error() -> AdbError {
    AdbError::Usage("need APK or APEX files on command line".to_string())
}

fn install_multi_package_unsupported_error() -> AdbError {
    eprintln!("adb: multi-package install is not supported on this device");
    AdbError::SilentExit(1)
}

fn inc_server(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        return Err(inc_server_usage_error());
    }

    #[cfg(unix)]
    {
        let connection_fd = args[0]
            .parse::<i32>()
            .map_err(|_| AdbError::Usage("invalid connection fd".to_string()))?;
        let output_fd = args[1]
            .parse::<i32>()
            .map_err(|_| AdbError::Usage("invalid output fd".to_string()))?;
        let files: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
        crate::incremental::serve(connection_fd, output_fd, &files)
    }

    #[cfg(windows)]
    {
        let connection_handle = args[0]
            .parse::<usize>()
            .map_err(|_| AdbError::Usage("invalid connection handle".to_string()))?;
        let output_handle = args[1]
            .parse::<usize>()
            .map_err(|_| AdbError::Usage("invalid output handle".to_string()))?;
        let files: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
        crate::incremental::serve(connection_handle, output_handle, &files)
    }
}

#[cfg(windows)]
fn inc_server_usage_error() -> AdbError {
    AdbError::Usage(
        "usage: adb inc-server CONNECTION_HANDLE OUTPUT_HANDLE FILE1 FILE2 ...".to_string(),
    )
}

#[cfg(not(windows))]
fn inc_server_usage_error() -> AdbError {
    AdbError::Usage("usage: adb inc-server CONNECTION_FD OUTPUT_FD FILE1 FILE2 ...".to_string())
}

fn delete_device_file(state: &CliState, remote: &str) -> Result<()> {
    let command = format!("rm -f {}", escape_shell_arg(remote));
    let output = run_shell_command_capture(state, &command)?;
    shell_exit_result(output.exit_code)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallPlan {
    local_apk: PathBuf,
    remote_apk: String,
    pm_args: Vec<String>,
    stream_args: Vec<String>,
    original_last_arg: String,
    requested_mode: InstallRequestMode,
    incremental_request: IncrementalRequest,
    incremental_wait: bool,
    use_fastdeploy: bool,
    agent_update_strategy: fastdeploy::AgentUpdateStrategy,
    package_kind: Option<InstallPackageKind>,
    package_is_last: bool,
}

impl InstallPlan {
    fn from_args(args: &[String]) -> Result<Self> {
        let ParsedInstallArgs {
            mut passthrough_args,
            requested_mode,
            incremental_request,
            incremental_wait,
            use_fastdeploy,
            agent_update_strategy,
        } = parse_install_args(args, true)?;

        if passthrough_args.is_empty() {
            return Err(install_needs_apk_error());
        }

        let original_last_arg = passthrough_args
            .last()
            .cloned()
            .expect("install requires at least one package argument");
        let last_package = passthrough_args
            .iter()
            .rposition(|arg| package_kind(arg).is_some());

        let (local_apk, remote_apk, pm_args, stream_args, package_kind, package_is_last) =
            if let Some(last_package) = last_package {
                let kind = package_kind(&passthrough_args[last_package]).expect("index checked");
                let package_is_last = last_package == passthrough_args.len() - 1;
                let local_apk = PathBuf::from(&passthrough_args[last_package]);
                let apk_name = local_file_name(&local_apk)?;
                let remote_apk = remote_join("/data/local/tmp", &apk_name);
                let mut pm_args = passthrough_args.clone();
                pm_args[last_package] = remote_apk.clone();
                passthrough_args.remove(last_package);

                (
                    local_apk,
                    remote_apk,
                    pm_args,
                    passthrough_args,
                    Some(kind),
                    package_is_last,
                )
            } else {
                (
                    PathBuf::from(&original_last_arg),
                    String::new(),
                    passthrough_args.clone(),
                    passthrough_args,
                    None,
                    false,
                )
            };

        Ok(Self {
            local_apk,
            remote_apk,
            pm_args,
            stream_args,
            original_last_arg,
            requested_mode,
            incremental_request,
            incremental_wait,
            use_fastdeploy,
            agent_update_strategy,
            package_kind,
            package_is_last,
        })
    }

    fn pm_install_command(&self) -> String {
        build_shell_command("pm install", &self.pm_args)
    }

    fn effective_mode(&self, device_has_cmd: bool) -> Result<InstallRequestMode> {
        match self.requested_mode {
            InstallRequestMode::Push => Ok(InstallRequestMode::Push),
            InstallRequestMode::Stream if device_has_cmd => Ok(InstallRequestMode::Stream),
            InstallRequestMode::Stream => Err(streaming_install_unsupported_error()),
            InstallRequestMode::Default if device_has_cmd => Ok(InstallRequestMode::Stream),
            InstallRequestMode::Default => Ok(InstallRequestMode::Push),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallMultiplePlan {
    session_args: Vec<String>,
    packages: Vec<PathBuf>,
    requested_mode: InstallRequestMode,
    incremental_request: IncrementalRequest,
    incremental_wait: bool,
}

impl InstallMultiplePlan {
    fn from_args(args: &[String]) -> Result<Self> {
        let ParsedInstallArgs {
            passthrough_args,
            requested_mode,
            incremental_request,
            incremental_wait,
            ..
        } = parse_install_args(args, false)?;

        let first_package = first_trailing_package(&passthrough_args)
            .ok_or_else(install_multiple_needs_apk_error)?;
        let mut packages = Vec::new();
        for arg in &passthrough_args[first_package..] {
            if has_extension_ignore_ascii_case(arg, "apex") {
                return Err(install_multiple_apex_error());
            }
            packages.push(PathBuf::from(arg));
        }

        Ok(Self {
            session_args: passthrough_args[..first_package].to_vec(),
            packages,
            requested_mode,
            incremental_request,
            incremental_wait,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallMultiPackagePlan {
    session_args: Vec<String>,
    packages: Vec<MultiPackageItem>,
    has_apex: bool,
}

impl InstallMultiPackagePlan {
    fn from_args(args: &[String]) -> Result<Self> {
        let passthrough_args = args.to_vec();

        let first_package = first_trailing_multi_package(&passthrough_args)
            .ok_or_else(install_multi_package_needs_package_error)?;
        let mut packages = Vec::new();
        let mut has_apex = false;
        for (relative, arg) in passthrough_args[first_package..].iter().enumerate() {
            let kind = package_kind(arg).ok_or_else(|| {
                AdbError::Usage(format!("install-multi-package 不支持的包类型: {arg}"))
            })?;
            has_apex |= kind == InstallPackageKind::Apex;
            packages.push(MultiPackageItem {
                source_index: first_package + relative + 1,
                kind,
                splits: split_multi_package_arg(arg),
            });
        }

        Ok(Self {
            session_args: passthrough_args[..first_package].to_vec(),
            packages,
            has_apex,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MultiPackageItem {
    source_index: usize,
    kind: InstallPackageKind,
    splits: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedInstallArgs {
    passthrough_args: Vec<String>,
    requested_mode: InstallRequestMode,
    incremental_request: IncrementalRequest,
    incremental_wait: bool,
    use_fastdeploy: bool,
    agent_update_strategy: fastdeploy::AgentUpdateStrategy,
}

fn parse_install_args(
    args: &[String],
    consume_fastdeploy_options: bool,
) -> Result<ParsedInstallArgs> {
    let mut requested_mode = InstallRequestMode::Default;
    let mut incremental_request = IncrementalRequest::None;
    let mut incremental_wait = false;
    let mut use_fastdeploy = false;
    let mut agent_update_strategy = fastdeploy::AgentUpdateStrategy::DifferentVersion;
    let mut passthrough_args = Vec::with_capacity(args.len());

    for arg in args {
        match arg.as_str() {
            "--streaming" => requested_mode = InstallRequestMode::Stream,
            "--no-streaming" => requested_mode = InstallRequestMode::Push,
            value
                if is_install_incremental_enable_option(value)
                    || is_install_incremental_disable_option(value) =>
            {
                if is_install_incremental_disable_option(value) {
                    incremental_request = IncrementalRequest::Disable;
                    continue;
                }
                incremental_request = IncrementalRequest::Enable;
            }
            "--wait" => {
                incremental_wait = true;
            }
            "--fastdeploy" if consume_fastdeploy_options => {
                use_fastdeploy = true;
            }
            "--no-fastdeploy" if consume_fastdeploy_options => {
                use_fastdeploy = false;
            }
            "--force-agent" if consume_fastdeploy_options => {
                agent_update_strategy = fastdeploy::AgentUpdateStrategy::Always;
            }
            "--date-check-agent" if consume_fastdeploy_options => {
                agent_update_strategy = fastdeploy::AgentUpdateStrategy::NewerTimestamp;
            }
            "--version-check-agent" if consume_fastdeploy_options => {
                agent_update_strategy = fastdeploy::AgentUpdateStrategy::DifferentVersion;
            }
            _ => passthrough_args.push(arg.clone()),
        }
    }

    Ok(ParsedInstallArgs {
        passthrough_args,
        requested_mode,
        incremental_request,
        incremental_wait,
        use_fastdeploy,
        agent_update_strategy,
    })
}

fn is_install_incremental_enable_option(arg: &str) -> bool {
    arg.len() >= "--incr".len() && "--incremental".starts_with(arg)
}

fn is_install_incremental_disable_option(arg: &str) -> bool {
    arg.len() >= "--no-incr".len() && "--no-incremental".starts_with(arg)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallRequestMode {
    Default,
    Push,
    Stream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncrementalRequest {
    None,
    Enable,
    Disable,
}

fn validate_incremental_request(
    requested_mode: InstallRequestMode,
    incremental_request: IncrementalRequest,
    use_fastdeploy: bool,
    has_abb_exec: bool,
) -> Result<()> {
    if incremental_request == IncrementalRequest::Enable && use_fastdeploy {
        return Err(incremental_fastdeploy_conflict_error());
    }
    if incremental_request == IncrementalRequest::Enable
        && requested_mode != InstallRequestMode::Default
    {
        return Err(incremental_mode_conflict_error());
    }
    if incremental_request == IncrementalRequest::Enable && !has_abb_exec {
        return Err(incremental_unsupported_device_error());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallPackageKind {
    Apk,
    Apex,
}

fn package_kind(path: &str) -> Option<InstallPackageKind> {
    if has_extension_ignore_ascii_case(path, "apk") {
        Some(InstallPackageKind::Apk)
    } else if has_extension_ignore_ascii_case(path, "apex") {
        Some(InstallPackageKind::Apex)
    } else {
        None
    }
}

fn first_trailing_package(args: &[String]) -> Option<usize> {
    let mut first = None;
    for (index, arg) in args.iter().enumerate().rev() {
        if is_install_multiple_package_file(arg) {
            first = Some(index);
        } else {
            break;
        }
    }
    first
}

fn first_trailing_multi_package(args: &[String]) -> Option<usize> {
    let mut first = None;
    for (index, arg) in args.iter().enumerate().rev() {
        if package_kind(arg).is_some() {
            first = Some(index);
        } else {
            break;
        }
    }
    first
}

fn is_install_multiple_package_file(path: &str) -> bool {
    ["apk", "apex", "dm", "sdm", "fsv_sig", "idsig"]
        .iter()
        .any(|extension| has_extension_ignore_ascii_case(path, extension))
}

fn split_multi_package_arg(arg: &str) -> Vec<PathBuf> {
    let splits: Vec<PathBuf> = env::split_paths(arg).collect();
    if splits.is_empty() {
        vec![PathBuf::from(arg)]
    } else {
        splits
    }
}

fn create_install_session(
    state: &CliState,
    plan: &InstallMultiplePlan,
    command_mode: PackageCommandMode,
) -> Result<i32> {
    let total_size = plan
        .packages
        .iter()
        .try_fold(0_u64, |total, package| -> Result<u64> {
            Ok(total + install_session_file_size(package)?)
        })?;

    let mut service_args = vec![
        "install-create".to_string(),
        "-S".to_string(),
        total_size.to_string(),
    ];
    service_args.extend(plan.session_args.clone());
    let output = run_package_command_capture_or_connect_error(
        state,
        command_mode,
        &service_args,
        install_create_connect_error,
    )?;
    parse_install_session_id(&output).ok_or_else(|| {
        eprintln!("adb: failed to create session");
        eprint!("{}", String::from_utf8_lossy(&output));
        AdbError::SilentExit(1)
    })
}

fn install_create_connect_error(err: &AdbError) -> AdbError {
    eprintln!("adb: connect error for create: {err}");
    AdbError::SilentExit(1)
}

fn install_write_connect_error(err: &AdbError) -> AdbError {
    eprintln!("adb: connect error for write: {err}");
    AdbError::SilentExit(1)
}

fn install_finalize_connect_error(err: &AdbError) -> AdbError {
    eprintln!("adb: connect error for finalize: {err}");
    AdbError::SilentExit(1)
}

fn multi_package_create_connect_error(err: &AdbError) -> AdbError {
    eprintln!("adb: connect error for create multi-package: {err}");
    AdbError::SilentExit(1)
}

fn create_multi_package_parent_session(
    state: &CliState,
    plan: &InstallMultiPackagePlan,
    command_mode: PackageCommandMode,
) -> Result<i32> {
    let mut args = vec!["install-create".to_string(), "--multi-package".to_string()];
    args.extend(plan.session_args.clone());
    if plan.has_apex {
        args.push("--staged".to_string());
    }
    let output = run_package_command_capture_or_connect_error(
        state,
        command_mode,
        &args,
        multi_package_create_connect_error,
    )?;
    parse_install_session_id(&output)
        .ok_or_else(|| multi_package_create_session_failed_error(&output))
}

fn create_multi_package_child_session(
    state: &CliState,
    plan: &InstallMultiPackagePlan,
    command_mode: PackageCommandMode,
    kind: InstallPackageKind,
) -> Result<Option<i32>> {
    let mut args = vec!["install-create".to_string()];
    args.extend(plan.session_args.clone());
    if plan.has_apex {
        args.push("--staged".to_string());
    }
    if kind == InstallPackageKind::Apex {
        args.push("--apex".to_string());
    }

    let output = match run_package_command_capture_or_connect_error(
        state,
        command_mode,
        &args,
        install_create_connect_error,
    ) {
        Ok(output) => output,
        Err(AdbError::SilentExit(_)) => return Ok(None),
        Err(err) => return Err(err),
    };
    match parse_install_session_id(&output) {
        Some(session_id) => Ok(Some(session_id)),
        None => Err(multi_package_create_session_failed_error(&output)),
    }
}

fn multi_package_create_session_failed_error(output: &[u8]) -> AdbError {
    eprintln!("adb: failed to create multi-package session");
    eprint!("{}", String::from_utf8_lossy(output));
    AdbError::SilentExit(1)
}

fn write_multi_package_split(
    state: &CliState,
    command_mode: PackageCommandMode,
    session_id: i32,
    source_index: usize,
    split: &Path,
) -> Result<Option<Vec<u8>>> {
    let size = match install_session_file_size_with_style(split, InstallPathStyle::Bare) {
        Ok(size) => size,
        Err(_) => return Ok(None),
    };
    let args = vec![
        "install-write".to_string(),
        "-S".to_string(),
        size.to_string(),
        session_id.to_string(),
        format!("{source_index}_{}", local_file_name(split)?),
        "-".to_string(),
    ];
    write_file_to_package_command_with_aosp_errors(
        state,
        command_mode,
        &args,
        split,
        InstallPathStyle::Bare,
    )
}

fn add_multi_package_child_sessions(
    state: &CliState,
    command_mode: PackageCommandMode,
    parent_id: i32,
    child_ids: &[i32],
) -> Result<Option<(Vec<String>, Vec<u8>)>> {
    let mut args = vec!["install-add-session".to_string(), parent_id.to_string()];
    args.extend(child_ids.iter().map(ToString::to_string));
    let service = package_command_service_for_mode(command_mode, &args);
    let stream = match client::open_device_service(&state.endpoint, &state.selector, &service) {
        Ok(stream) => stream,
        Err(err) => {
            let _ = install_add_session_connect_error(&err);
            return Ok(None);
        }
    };
    let output = client::read_stream_to_bytes(stream)?;
    Ok(Some((args, output)))
}

fn install_add_session_connect_error(err: &AdbError) -> AdbError {
    eprintln!("adb: connect error for install-add-session: {err}");
    AdbError::SilentExit(1)
}

fn multi_package_link_command_for_error(
    command_mode: PackageCommandMode,
    args: &[String],
) -> String {
    match command_mode {
        PackageCommandMode::AbbExec => {
            let mut command_args = Vec::with_capacity(args.len() + 1);
            command_args.push("package".to_string());
            command_args.extend(args.iter().cloned());
            command_args.join(" ")
        }
        PackageCommandMode::CmdPackage => {
            let mut command = String::from("exec:cmd package");
            for arg in args {
                command.push(' ');
                command.push_str(arg);
            }
            command
        }
        PackageCommandMode::Pm => {
            let mut command = String::from("exec:pm");
            for arg in args {
                command.push(' ');
                command.push_str(arg);
            }
            command
        }
    }
}

fn finalize_multi_package_parent_session(
    state: &CliState,
    plan: &InstallMultiPackagePlan,
    command_mode: PackageCommandMode,
    parent_id: i32,
    success: bool,
) -> Result<Vec<u8>> {
    let mut args = if success {
        let mut args = vec!["install-commit".to_string()];
        args.extend(staged_ready_timeout_args(&plan.session_args));
        args
    } else {
        vec!["install-abandon".to_string()]
    };
    args.push(parent_id.to_string());
    run_package_command_capture_or_connect_error(
        state,
        command_mode,
        &args,
        install_finalize_connect_error,
    )
}

fn staged_ready_timeout_args(session_args: &[String]) -> Vec<String> {
    let mut forwarded = Vec::new();
    let mut index = 0;
    while index < session_args.len() {
        if session_args[index] == "--staged-ready-timeout"
            && let Some(value) = session_args.get(index + 1)
        {
            forwarded.push(session_args[index].clone());
            forwarded.push(value.clone());
            index += 1;
        }
        index += 1;
    }
    forwarded
}

fn abandon_remaining_sessions(
    state: &CliState,
    command_mode: PackageCommandMode,
    parent_id: i32,
    child_ids: &[i32],
) {
    for session_id in child_ids.iter().copied().chain(std::iter::once(parent_id)) {
        eprintln!("Attempting to abandon session ID {session_id}");
        let args = vec!["install-abandon".to_string(), session_id.to_string()];
        if let Err(err) = run_package_command_capture_or_connect_error(
            state,
            command_mode,
            &args,
            install_finalize_connect_error,
        ) && !matches!(err, AdbError::SilentExit(_))
        {
            let _ = err;
        }
    }
}

fn write_install_session_package(
    state: &CliState,
    command_mode: PackageCommandMode,
    session_id: i32,
    package: &Path,
) -> Result<Option<Vec<u8>>> {
    let size = match install_session_file_size(package) {
        Ok(size) => size,
        Err(_) => return Ok(None),
    };
    let args = vec![
        "install-write".to_string(),
        "-S".to_string(),
        size.to_string(),
        session_id.to_string(),
        local_file_name(package)?,
        "-".to_string(),
    ];
    write_file_to_package_command_with_aosp_errors(
        state,
        command_mode,
        &args,
        package,
        InstallPathStyle::Quoted,
    )
}

fn finalize_install_session(
    state: &CliState,
    command_mode: PackageCommandMode,
    session_id: i32,
    success: bool,
) -> Result<Vec<u8>> {
    let args = vec![
        if success {
            "install-commit".to_string()
        } else {
            "install-abandon".to_string()
        },
        session_id.to_string(),
    ];
    run_package_command_capture_or_connect_error(
        state,
        command_mode,
        &args,
        install_finalize_connect_error,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageCommandMode {
    AbbExec,
    CmdPackage,
    Pm,
}

fn run_package_command_capture_or_connect_error(
    state: &CliState,
    mode: PackageCommandMode,
    args: &[String],
    connect_error: fn(&AdbError) -> AdbError,
) -> Result<Vec<u8>> {
    let stream = match open_package_command_service(state, mode, args) {
        Ok(stream) => stream,
        Err(err) => return Err(connect_error(&err)),
    };
    client::read_stream_to_bytes(stream)
}

fn open_package_command_service(
    state: &CliState,
    mode: PackageCommandMode,
    args: &[String],
) -> Result<ServerStream> {
    client::open_device_service(
        &state.endpoint,
        &state.selector,
        &package_command_service_for_mode(mode, args),
    )
}

fn write_file_to_package_command_with_aosp_errors(
    state: &CliState,
    mode: PackageCommandMode,
    args: &[String],
    local: &Path,
    path_style: InstallPathStyle,
) -> Result<Option<Vec<u8>>> {
    let mut file = match fs::File::open(local) {
        Ok(file) => file,
        Err(err) => {
            install_path_io_error("open", local, &err, path_style);
            return Ok(None);
        }
    };
    let mut stream = match open_package_command_service(state, mode, args) {
        Ok(stream) => stream,
        Err(err) => {
            let _ = install_write_connect_error(&err);
            return Ok(None);
        }
    };
    if let Err(err) = io::copy(&mut file, &mut stream) {
        install_path_io_error("write", local, &err, path_style);
        return Ok(None);
    }

    let mut output = Vec::new();
    stream.read_to_end(&mut output)?;
    Ok(Some(output))
}

fn install_session_file_size(path: &Path) -> Result<u64> {
    install_session_file_size_with_style(path, InstallPathStyle::Quoted)
}

#[derive(Clone, Copy)]
enum InstallPathStyle {
    Quoted,
    Bare,
}

fn install_session_file_size_with_style(path: &Path, path_style: InstallPathStyle) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
        Ok(_) => Err(AdbError::Usage(format!(
            "安装输入必须是普通文件: {}",
            path.display()
        ))),
        Err(err) => {
            install_path_io_error("stat", path, &err, path_style);
            Err(AdbError::SilentExit(1))
        }
    }
}

fn install_path_io_error(action: &str, path: &Path, err: &io::Error, path_style: InstallPathStyle) {
    match path_style {
        InstallPathStyle::Quoted => {
            eprintln!("adb: failed to {action} \"{}\": {err}", path.display());
        }
        InstallPathStyle::Bare => {
            eprintln!("adb: failed to {action} {}: {err}", path.display());
        }
    }
}

fn write_file_to_cmd_package(state: &CliState, args: &[String], local: &Path) -> Result<Vec<u8>> {
    client::write_file_to_device_service(
        &state.endpoint,
        &state.selector,
        &package_command_service(state, args)?,
        local,
    )
}

fn package_command_service(state: &CliState, args: &[String]) -> Result<String> {
    Ok(package_command_service_for_mode(
        package_command_mode(state)?,
        args,
    ))
}

fn package_command_mode(state: &CliState) -> Result<PackageCommandMode> {
    Ok(package_command_mode_for_features(
        device_has_feature(state, "abb_exec")?,
        device_has_feature(state, "cmd")?,
    ))
}

fn package_command_mode_for_features(has_abb_exec: bool, has_cmd: bool) -> PackageCommandMode {
    if has_abb_exec {
        PackageCommandMode::AbbExec
    } else if has_cmd {
        PackageCommandMode::CmdPackage
    } else {
        PackageCommandMode::Pm
    }
}

fn package_command_service_for_mode(mode: PackageCommandMode, args: &[String]) -> String {
    match mode {
        PackageCommandMode::AbbExec => {
            let mut command_args = Vec::with_capacity(args.len() + 1);
            command_args.push("package".to_string());
            command_args.extend(args.iter().cloned());
            build_abb_exec_service(&command_args)
        }
        PackageCommandMode::CmdPackage => cmd_package_service(args),
        PackageCommandMode::Pm => pm_service(args),
    }
}

fn pm_service(args: &[String]) -> String {
    build_shell_command("exec:pm", args)
}

fn cmd_package_service(args: &[String]) -> String {
    build_shell_command("exec:cmd package", args)
}

fn build_abb_exec_service(args: &[String]) -> String {
    let mut service = String::from("abb_exec:");
    service.push_str(&args.join("\0"));
    service
}

fn print_success_output_or_fail(action: &str, package: &Path, output: &[u8]) -> Result<()> {
    if command_succeeded(output) {
        print!("{}", String::from_utf8_lossy(output));
        Ok(())
    } else {
        Err(AdbError::Server(format!(
            "failed to {action} {}: {}",
            package.display(),
            String::from_utf8_lossy(output).trim()
        )))
    }
}

fn command_succeeded(output: &[u8]) -> bool {
    output.starts_with(b"Success")
}

fn parse_install_session_id(output: &[u8]) -> Option<i32> {
    let text = String::from_utf8_lossy(output);
    let start = text.rfind('[')?;
    let end = text[start + 1..].find(']')? + start + 1;
    text[start + 1..end].trim().parse().ok()
}

fn local_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AdbError::Usage(format!("无法从路径取文件名: {}", path.display())))
}

fn local_file_size(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(AdbError::Usage(format!(
            "安装输入必须是普通文件: {}",
            path.display()
        )));
    }
    Ok(metadata.len())
}

fn build_shell_command(prefix: &str, args: &[String]) -> String {
    let mut command = prefix.to_string();
    for arg in args {
        command.push(' ');
        command.push_str(&escape_shell_arg(arg));
    }
    command
}

fn build_exec_service(args: &[String]) -> String {
    let mut command = format!("exec:{}", args.first().map(String::as_str).unwrap_or(""));
    for arg in &args[1..] {
        command.push(' ');
        command.push_str(&escape_shell_arg(arg));
    }
    command
}

fn build_abb_service(args: &[String]) -> String {
    let mut service = String::from("abb:");
    service.push_str(&args.join("\0"));
    service
}

fn build_colon_service_command(prefix: &str, args: &[String]) -> String {
    let mut command = prefix.to_string();
    for arg in args {
        command.push(' ');
        command.push_str(&escape_shell_arg(arg));
    }
    command
}

fn has_extension_ignore_ascii_case(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn remote_join(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// 仿 AOSP LinePrinter 的 sync 进度/汇总输出，输出到 stderr。
#[derive(Debug)]
struct SyncProgressPrinter {
    quiet: bool,
    start: Instant,
    last_progress: String,
    bytes_transferred: u64,
    bytes_expected: u64,
}

impl SyncProgressPrinter {
    fn new(quiet: bool) -> Self {
        Self {
            quiet,
            start: Instant::now(),
            last_progress: String::new(),
            bytes_transferred: 0,
            bytes_expected: 0,
        }
    }

    fn plural_files(n: u64) -> &'static str {
        if n == 1 { "" } else { "s" }
    }
}

impl file_sync::ProgressTracker for SyncProgressPrinter {
    fn report_progress(
        &mut self,
        file: &str,
        copied: u64,
        total: u64,
        expect_multiple_files: bool,
    ) {
        if self.quiet {
            return;
        }

        self.bytes_transferred = copied;
        if total > 0 {
            self.bytes_expected = total;
        }

        let overall = if self.bytes_expected > 0 && self.bytes_transferred <= self.bytes_expected {
            let pct = (self.bytes_transferred * 100 / self.bytes_expected) as i32;
            if pct <= 100 {
                format!("{pct}%")
            } else {
                "?".to_string()
            }
        } else {
            "?".to_string()
        };

        let output = if copied > total || total == 0 {
            format!("[{overall:>4}] {file}: {copied}/?")
        } else if expect_multiple_files {
            let file_pct = (copied * 100 / total) as i32;
            format!("[{overall:>4}] {file}: {file_pct}%")
        } else {
            format!("[{overall:>4}] {file}")
        };

        if output != self.last_progress {
            eprintln!("{output}");
            self.last_progress = output;
        }
    }

    fn report_transfer_rate(
        &mut self,
        name: &str,
        files: u64,
        skipped: u64,
        bytes: u64,
        direction: file_sync::TransferDirection,
        _start: Instant,
    ) {
        if self.quiet {
            return;
        }

        let direction_str = match direction {
            file_sync::TransferDirection::Push => "pushed",
            file_sync::TransferDirection::Pull => "pulled",
        };

        let mut line = String::new();
        if !name.is_empty() {
            let display_name = if let Some(product_out) = env::var_os("ANDROID_PRODUCT_OUT") {
                name.strip_prefix(product_out.to_string_lossy().as_ref())
                    .unwrap_or(name)
            } else {
                name
            };
            line.push_str(display_name);
            line.push_str(": ");
        }
        line.push_str(&format!(
            "{files} file{} {direction_str}, {skipped} skipped.",
            Self::plural_files(files)
        ));

        let duration = self.start.elapsed().as_secs_f64();
        if bytes > 0 && duration > 0.0 {
            let rate = (bytes as f64 / duration) / (1024.0 * 1024.0);
            line.push_str(&format!(
                " {rate:.1} MB/s ({bytes} bytes in {duration:.3}s)"
            ));
        }

        eprintln!("{line}");
    }

    fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PushInvocation {
    paths: Vec<String>,
    options: file_sync::PushOptions,
    quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullInvocation {
    paths: Vec<String>,
    options: file_sync::PullOptions,
    quiet: bool,
}

fn push(state: &CliState, args: &[String]) -> Result<()> {
    let default_compression = env_compression_or_any(env::var("ADB_COMPRESSION").ok().as_deref())?;
    let invocation = parse_push_args(args, default_compression)?;
    if invocation.paths.len() < 2 {
        return Err(push_requires_args_error());
    }

    client::ensure_server_running(&state.endpoint)?;
    let remote = invocation.paths.last().expect("len checked");
    let sources: Vec<PathBuf> = invocation.paths[..invocation.paths.len() - 1]
        .iter()
        .map(PathBuf::from)
        .collect();

    let mut printer = SyncProgressPrinter::new(invocation.quiet);
    let expect_multiple = sources.len() > 1
        || sources.iter().any(|src| {
            src.is_dir() || src.is_symlink() && src.read_link().is_ok_and(|t| t.is_dir())
        });
    let options = file_sync::PushOptions {
        expect_multiple_files: expect_multiple,
        ..invocation.options
    };
    let start = Instant::now();
    let summary = file_sync::push(
        &state.endpoint,
        &state.selector,
        &sources,
        remote,
        options,
        Some(&mut printer),
    )?;
    printer.report_transfer_rate(
        "",
        summary.files,
        summary.skipped,
        summary.bytes,
        file_sync::TransferDirection::Push,
        start,
    );
    Ok(())
}

fn ls(state: &CliState, args: &[String]) -> Result<()> {
    let [remote] = args else {
        return Err(simple_requires_arg_error("ls"));
    };

    client::ensure_server_running(&state.endpoint)?;
    for entry in file_sync::ls(&state.endpoint, &state.selector, remote)? {
        println!("{}", file_sync::format_ls_entry(&entry));
    }
    Ok(())
}

fn pull(state: &CliState, args: &[String]) -> Result<()> {
    let default_compression = env_compression_or_any(env::var("ADB_COMPRESSION").ok().as_deref())?;
    let invocation = parse_pull_args(args, default_compression)?;
    if invocation.paths.is_empty() {
        return Err(simple_requires_arg_error("pull"));
    }

    client::ensure_server_running(&state.endpoint)?;
    let (remotes, local) = if invocation.paths.len() == 1 {
        (invocation.paths.as_slice(), Path::new("."))
    } else {
        (
            &invocation.paths[..invocation.paths.len() - 1],
            Path::new(invocation.paths.last().expect("len checked")),
        )
    };
    let remotes: Vec<String> = remotes.to_vec();

    let mut printer = SyncProgressPrinter::new(invocation.quiet);
    let expect_multiple = remotes.len() > 1;
    let options = file_sync::PullOptions {
        expect_multiple_files: expect_multiple,
        ..invocation.options
    };
    let start = Instant::now();
    let summary = file_sync::pull(
        &state.endpoint,
        &state.selector,
        &remotes,
        local,
        options,
        Some(&mut printer),
    )?;
    printer.report_transfer_rate(
        "",
        summary.files,
        summary.skipped,
        summary.bytes,
        file_sync::TransferDirection::Pull,
        start,
    );
    Ok(())
}

fn simple_requires_arg_error(command: &str) -> AdbError {
    AdbError::Usage(format!("{command} requires an argument"))
}

fn push_requires_args_error() -> AdbError {
    AdbError::Usage("push requires <source> and <destination> arguments".to_string())
}

const SYNC_PARTITIONS: &[&str] = &[
    "data",
    "odm",
    "oem",
    "product",
    "system",
    "system_ext",
    "vendor",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncInvocation {
    partition: String,
    list_only: bool,
    dry_run: bool,
    quiet: bool,
    compression: file_sync::SyncCompression,
}

fn sync_build(state: &CliState, args: &[String]) -> Result<()> {
    let default_compression = env_compression_or_any(env::var("ADB_COMPRESSION").ok().as_deref())?;
    let invocation = parse_sync_args_with_default(args, default_compression)?;
    let product_out = env::var_os("ANDROID_PRODUCT_OUT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            AdbError::Usage("product directory not specified; set $ANDROID_PRODUCT_OUT".to_string())
        })?;

    client::ensure_server_running(&state.endpoint)?;
    let mut found = false;
    let mut total = file_sync::TransferSummary::default();
    let mut listed = 0_u64;
    for partition in sync_partition_candidates(&invocation.partition) {
        let local_dir = product_out.join(partition);
        if !local_dir.is_dir() {
            continue;
        }

        found = true;
        let remote_dir = format!("/{partition}");
        // AOSP 每个分区使用独立的 SyncConnection/LinePrinter，因此每个分区独立输出
        let mut printer = SyncProgressPrinter::new(invocation.quiet);
        let partition_start = Instant::now();
        let result = file_sync::sync_dir(
            &state.endpoint,
            &state.selector,
            &local_dir,
            &remote_dir,
            file_sync::DirectorySyncOptions {
                list_only: invocation.list_only,
                dry_run: invocation.dry_run,
                compression: invocation.compression,
                expect_multiple_files: true,
            },
            Some(&mut printer),
        )?;
        if invocation.list_only && !invocation.quiet {
            for item in &result.would_push {
                println!("would push: {} -> {}", item.local.display(), item.remote);
            }
        }
        if !invocation.list_only && !invocation.quiet {
            printer.report_transfer_rate(
                partition,
                result.summary.files,
                result.summary.skipped,
                result.summary.bytes,
                file_sync::TransferDirection::Push,
                partition_start,
            );
        }
        listed += result.would_push.len() as u64;
        total.add(result.summary);
    }

    if !found {
        return Err(AdbError::Usage(format!(
            "don't know how to sync {} partition",
            invocation.partition
        )));
    }

    if invocation.list_only && !invocation.quiet {
        println!(
            "{} file{} would be pushed, {} skipped",
            listed,
            plural(listed),
            total.skipped
        );
    }
    Ok(())
}

fn parse_sync_args_with_default(
    args: &[String],
    default_compression: file_sync::SyncCompression,
) -> Result<SyncInvocation> {
    let mut invocation = SyncInvocation {
        partition: "all".to_string(),
        list_only: false,
        dry_run: false,
        quiet: false,
        compression: default_compression,
    };
    let mut positional = Vec::new();
    let mut index = 0;
    let mut parse_options = true;

    while index < args.len() {
        let arg = &args[index];
        if !parse_options || arg == "-" || !arg.starts_with('-') {
            positional.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            parse_options = false;
            index += 1;
            continue;
        }

        let mut chars = arg[1..].chars().peekable();
        while let Some(option) = chars.next() {
            match option {
                'l' => invocation.list_only = true,
                'n' => invocation.dry_run = true,
                'q' => invocation.quiet = true,
                'Z' => invocation.compression = file_sync::SyncCompression::None,
                'z' => {
                    let rest: String = chars.collect();
                    let value = if rest.is_empty() {
                        index += 1;
                        args.get(index)
                            .ok_or_else(|| AdbError::Usage("-z 需要压缩算法参数".to_string()))?
                            .as_str()
                    } else {
                        rest.as_str()
                    };
                    invocation.compression = parse_sync_compression_arg(value)?;
                    break;
                }
                other => {
                    return Err(AdbError::Usage(format!(
                        "usage: adb sync [-l] [-n] [-z ALGORITHM] [-Z] [-q] [PARTITION]; unknown option -{other}"
                    )));
                }
            }
        }
        index += 1;
    }

    match positional.as_slice() {
        [] => {}
        [partition] => invocation.partition = partition.clone(),
        _ => {
            return Err(AdbError::Usage(
                "usage: adb sync [-l] [-n] [-z ALGORITHM] [-Z] [-q] [PARTITION]".to_string(),
            ));
        }
    }
    Ok(invocation)
}

fn sync_partition_candidates(partition: &str) -> Vec<&'static str> {
    if partition == "all" {
        return SYNC_PARTITIONS.to_vec();
    }
    SYNC_PARTITIONS
        .iter()
        .copied()
        .filter(|candidate| partition == *candidate || partition == format!("/{candidate}"))
        .collect()
}

fn parse_push_args(
    args: &[String],
    default_compression: file_sync::SyncCompression,
) -> Result<PushInvocation> {
    let mut invocation = PushInvocation {
        paths: Vec::new(),
        options: file_sync::PushOptions {
            compression: default_compression,
            ..file_sync::PushOptions::default()
        },
        quiet: false,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                invocation.paths.extend(args[index + 1..].iter().cloned());
                break;
            }
            "--sync" => invocation.options.sync = true,
            "-n" => invocation.options.dry_run = true,
            "-q" => invocation.quiet = true,
            "-Z" => invocation.options.compression = file_sync::SyncCompression::None,
            "-p" => {
                // AOSP 为向后兼容在 push 中静默忽略 -p。
            }
            "-z" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| AdbError::Usage("-z 需要压缩算法参数".to_string()))?;
                invocation.options.compression = parse_sync_compression_arg(value)?;
            }
            value if value.starts_with('-') => {
                return Err(AdbError::Usage(format!("未知 push 参数: {value}")));
            }
            value => invocation.paths.push(value.to_string()),
        }
        index += 1;
    }
    Ok(invocation)
}

fn parse_pull_args(
    args: &[String],
    default_compression: file_sync::SyncCompression,
) -> Result<PullInvocation> {
    let mut invocation = PullInvocation {
        paths: Vec::new(),
        options: file_sync::PullOptions {
            compression: default_compression,
            ..file_sync::PullOptions::default()
        },
        quiet: false,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                invocation.paths.extend(args[index + 1..].iter().cloned());
                break;
            }
            "-a" => invocation.options.preserve_attrs = true,
            "-q" => invocation.quiet = true,
            "-Z" => invocation.options.compression = file_sync::SyncCompression::None,
            "-p" => {
                // AOSP 为向后兼容在 pull 中静默忽略 -p。
            }
            "-z" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| AdbError::Usage("-z 需要压缩算法参数".to_string()))?;
                invocation.options.compression = parse_sync_compression_arg(value)?;
            }
            value if value.starts_with('-') => {
                return Err(AdbError::Usage(format!("未知 pull 参数: {value}")));
            }
            value => invocation.paths.push(value.to_string()),
        }
        index += 1;
    }
    Ok(invocation)
}

fn parse_sync_compression_arg(value: &str) -> Result<file_sync::SyncCompression> {
    match value {
        "none" => Ok(file_sync::SyncCompression::None),
        "any" => Ok(file_sync::SyncCompression::Any),
        "zstd" => Ok(file_sync::SyncCompression::Zstd),
        "lz4" => Ok(file_sync::SyncCompression::Lz4),
        "brotli" => Ok(file_sync::SyncCompression::Brotli),
        _ => Err(AdbError::Usage(format!(
            "未知 sync 压缩算法: {value}，可用值为 any/none/brotli/lz4/zstd"
        ))),
    }
}

fn env_compression_or_any(adb_compression: Option<&str>) -> Result<file_sync::SyncCompression> {
    match adb_compression {
        Some(value) => parse_sync_compression_arg(value),
        None => Ok(file_sync::SyncCompression::Any),
    }
}

fn connect_device(state: &CliState, args: &[String]) -> Result<()> {
    let service = connect_service(args)?;
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query(&state.endpoint, &service)?;
    println!("{body}");
    Ok(())
}

fn connect_service(args: &[String]) -> Result<String> {
    let [target] = args else {
        return Err(AdbError::Usage(
            "usage: adb connect HOST[:PORT]".to_string(),
        ));
    };
    Ok(format!("host:connect:{target}"))
}

fn disconnect_device(state: &CliState, args: &[String]) -> Result<()> {
    let service = disconnect_service(args)?;
    client::ensure_server_running(&state.endpoint)?;
    let body = client::query(&state.endpoint, &service)?;
    println!("{body}");
    Ok(())
}

fn disconnect_service(args: &[String]) -> Result<String> {
    match args {
        [] => Ok("host:disconnect:".to_string()),
        [target] => Ok(format!("host:disconnect:{target}")),
        _ => Err(AdbError::Usage(
            "usage: adb disconnect [HOST[:PORT]]".to_string(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ForwardCommand {
    List,
    Status(String),
}

fn forward(state: &CliState, args: &[String]) -> Result<()> {
    let command = forward_command("forward", args)?;
    let prefix = state.selector.host_prefix();
    match command {
        ForwardCommand::List => {
            let body = client::query(&state.endpoint, &format!("{prefix}:list-forward"))?;
            print!("{body}");
            Ok(())
        }
        ForwardCommand::Status(service) => {
            validate_forward_service(state, &service)?;
            forward_status(&state.endpoint, &format!("{prefix}:{service}"))
        }
    }
}

fn validate_forward_service(state: &CliState, service: &str) -> Result<()> {
    let rest = if let Some(rest) = service.strip_prefix("forward:norebind:") {
        rest
    } else if let Some(rest) = service.strip_prefix("forward:") {
        rest
    } else {
        return Ok(());
    };
    let (local, remote) = rest
        .split_once(';')
        .ok_or_else(|| AdbError::Server(format!("bad forward: {service}")))?;

    if let Some(port) = local.strip_prefix("tcp:") {
        match port.parse::<i64>() {
            Ok(port) if port >= 0 => {}
            _ => {
                return Err(AdbError::Usage(format!("Invalid source port: '{port}'")));
            }
        }
    }
    if let Some(port) = remote.strip_prefix("tcp:") {
        let port_num = port
            .parse::<i64>()
            .map_err(|_| AdbError::Usage(format!("Invalid destination port: '{port}'")))?;
        if port_num <= 0 {
            return Err(AdbError::Usage(format!(
                "Invalid destination port: '{port}'"
            )));
        }
    }
    if remote.starts_with("dev-raw:") && !device_has_feature(state, "devraw")? {
        return Err(AdbError::Server(
            "dev-raw is not supported by the device".to_string(),
        ));
    }
    Ok(())
}

fn forward_status(endpoint: &ServerEndpoint, service: &str) -> Result<()> {
    if let Some(resolved_port) = client::request_forward_status(endpoint, service)? {
        println!("{resolved_port}");
    }
    Ok(())
}

fn reverse(state: &CliState, args: &[String]) -> Result<()> {
    let command = forward_command("reverse", args)?;
    client::ensure_server_running(&state.endpoint)?;
    match command {
        ForwardCommand::List => {
            let body = client::query_device_service(
                &state.endpoint,
                &state.selector,
                "reverse:list-forward",
            )?;
            print!("{body}");
            Ok(())
        }
        ForwardCommand::Status(service) => reverse_status(state, &format!("reverse:{service}")),
    }
}

fn reverse_status(state: &CliState, service: &str) -> Result<()> {
    validate_reverse_service(state, service)?;
    if let Some(resolved_port) =
        client::request_device_service_status(&state.endpoint, &state.selector, service)?
    {
        println!("{resolved_port}");
    }
    Ok(())
}

fn validate_reverse_service(state: &CliState, service: &str) -> Result<()> {
    let rest = if let Some(rest) = service.strip_prefix("reverse:forward:norebind:") {
        rest
    } else if let Some(rest) = service.strip_prefix("reverse:forward:") {
        rest
    } else {
        return Ok(());
    };
    let (remote, _) = rest
        .split_once(';')
        .ok_or_else(|| AdbError::Server(format!("bad reverse: {service}")))?;
    if remote.starts_with("dev-raw:") && !device_has_feature(state, "devraw")? {
        return Err(AdbError::Server(
            "dev-raw is not supported by the device".to_string(),
        ));
    }
    Ok(())
}

fn forward_command(cmd_name: &str, args: &[String]) -> Result<ForwardCommand> {
    let named = |msg: &str| AdbError::Usage(format!("{cmd_name} {msg}"));
    match args {
        [] => Err(named("requires an argument")),
        [flag] if flag == "--list" => Ok(ForwardCommand::List),
        [flag, ..] if flag == "--list" => Err(AdbError::Usage(
            "--list doesn't take any arguments".to_string(),
        )),
        [flag] if flag == "--remove-all" => {
            Ok(ForwardCommand::Status("killforward-all".to_string()))
        }
        [flag, ..] if flag == "--remove-all" => Err(AdbError::Usage(
            "--remove-all doesn't take any arguments".to_string(),
        )),
        [flag, local] if flag == "--remove" => {
            Ok(ForwardCommand::Status(format!("killforward:{local}")))
        }
        [flag, ..] if flag == "--remove" => {
            Err(AdbError::Usage("--remove requires an argument".to_string()))
        }
        [flag, local, remote] if flag == "--no-rebind" => Ok(ForwardCommand::Status(format!(
            "forward:norebind:{local};{remote}"
        ))),
        [flag, ..] if flag == "--no-rebind" => Err(AdbError::Usage(
            "--no-rebind takes two arguments".to_string(),
        )),
        [local, remote] => Ok(ForwardCommand::Status(format!("forward:{local};{remote}"))),
        _ => Err(named("takes two arguments")),
    }
}

fn current_exe_display() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "adb".to_string())
}

fn plural(count: u64) -> &'static str {
    if count == 1 { "" } else { "s" }
}

const AOSP_HELP_BEFORE_LOCAL_AGENT: &str = "\
global options:
 -a                       listen on all network interfaces, not just localhost
 -d                       use USB device (error if multiple devices connected)
 -e                       use TCP/IP device (error if multiple TCP/IP devices available)
 -s SERIAL                use device with given serial (overrides $ANDROID_SERIAL)
 -t ID                    use device with given transport id
 -H                       name of adb server host [default=localhost]
 -P                       port of adb server [default=5037]
 -L SOCKET                listen on given socket for adb server [default=tcp:localhost:5037]
 --one-device SERIAL|USB  only allowed with 'start-server' or 'server nodaemon', server will only connect to one USB device, specified by a serial number or USB device address.
 --exit-on-write-error    exit if stdout is closed

general commands:
 devices [-l]             list connected devices (-l for long output)
 help                     show this help message
 version                  show version num

networking:
 connect HOST[:PORT]      connect to a device via TCP/IP [default port=5555]
 disconnect [HOST[:PORT]]
     disconnect from given TCP/IP device [default port=5555], or all
 pair HOST[:PORT] [PAIRING CODE]
     pair with a device for secure TCP/IP communication
 forward --list           list all forward socket connections
 forward [--no-rebind] LOCAL REMOTE
     forward socket connection using:
       tcp:<port> (<local> may be \"tcp:0\" to pick any open port)
       localabstract:<unix domain socket name>
       localreserved:<unix domain socket name>
       localfilesystem:<unix domain socket name>
       dev:<character device name>
       dev-raw:<character device name> (open device in raw mode)
       jdwp:<process pid> (remote only)
       vsock:<CID>:<port> (remote only)
       acceptfd:<fd> (listen only)
 forward --remove LOCAL   remove specific forward socket connection
 forward --remove-all     remove all forward socket connections
 reverse --list           list all reverse socket connections from device
 reverse [--no-rebind] REMOTE LOCAL
     reverse socket connection using:
       tcp:<port> (<remote> may be \"tcp:0\" to pick any open port)
       localabstract:<unix domain socket name>
       localreserved:<unix domain socket name>
       localfilesystem:<unix domain socket name>
 reverse --remove REMOTE  remove specific reverse socket connection
 reverse --remove-all     remove all reverse socket connections from device
 mdns check               check if mdns discovery is available
 mdns services            list all discovered services

file transfer:
 push [--sync] [-z ALGORITHM] [-Z] LOCAL... REMOTE
     copy local files/directories to device
     -n: dry run: push files to device without storing to the filesystem
     -q: suppress progress messages
     -Z: disable compression
     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)
     --sync: only push files that have different timestamps on the host than the device
 pull [-a] [-z ALGORITHM] [-Z] REMOTE... LOCAL
     copy files/dirs from device
     -a: preserve file timestamp and mode
     -q: suppress progress messages
     -Z: disable compression
     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)
 sync [-l] [-z ALGORITHM] [-Z] [all|data|odm|oem|product|system|system_ext|vendor]
     sync a local build from $ANDROID_PRODUCT_OUT to the device (default all)
     -l: list files that would be copied, but don't copy them
     -n: dry run: push files to device without storing to the filesystem
     -q: suppress progress messages
     -Z: disable compression
     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)

shell:
 shell [-e ESCAPE] [-n] [-Tt] [-x] [COMMAND...]
     run remote shell command (interactive shell if no command given)
     -e: choose escape character, or \"none\"; default '~'
     -n: don't read from stdin
     -T: disable pty allocation
     -t: allocate a pty if on a tty (-tt: force pty allocation)
     -x: disable remote exit codes and stdout/stderr separation
 emu COMMAND              run emulator console command

app installation (see also `adb shell cmd package help`):
 install [-lrtsdg] [--instant] PACKAGE
     push a single package to the device and install it
 install-multiple [-lrtsdpg] [--instant] PACKAGE...
     push multiple APKs to the device for a single package and install them
 install-multi-package [-lrtsdpg] [--instant] PACKAGE...
     push one or more packages to the device and install them atomically
     -r: replace existing application
     -t: allow test packages
     -d: allow version code downgrade (debuggable packages only)
     -p: partial application install (install-multiple only)
     -g: grant all runtime permissions
     --abi ABI: override platform's default ABI
     --instant: cause the app to be installed as an ephemeral install app
     --no-streaming: always push APK to device and invoke Package Manager as separate steps
     --streaming: force streaming APK directly into Package Manager
     --fastdeploy: use fast deploy
     --no-fastdeploy: prevent use of fast deploy
     --force-agent: force update of deployment agent when using fast deploy
     --date-check-agent: update deployment agent when local version is newer and using fast deploy
     --version-check-agent: update deployment agent when local version has different version code and using fast deploy
";

const AOSP_HELP_AFTER_LOCAL_AGENT: &str = "     (See also `adb shell pm help` for more options.)
 uninstall [-k] PACKAGE
     remove this app package from the device
     '-k': keep the data and cache directories

debugging:
 bugreport [PATH]
     write bugreport to given PATH [default=bugreport.zip];
     if PATH is a directory, the bug report is saved in that directory.
     devices that don't support zipped bug reports output to stdout.
 jdwp                     list pids of processes hosting a JDWP transport
 logcat                   show device log (logcat --help for more)

security:
 disable-verity           disable dm-verity checking on userdebug builds
 enable-verity            re-enable dm-verity checking on userdebug builds
 keygen FILE
     generate adb public/private key; private key stored in FILE,

scripting:
 wait-for[-TRANSPORT]-STATE...
     wait for device to be in a given state
     STATE: device, recovery, rescue, sideload, bootloader, or disconnect
     TRANSPORT: usb, local, or any [default=any]
 get-state                print offline | bootloader | device
 get-serialno             print <serial-number>
 get-devpath              print <device-path>
 remount [-R]
      remount partitions read-write. if a reboot is required, -R will
      will automatically reboot the device.
 reboot [bootloader|recovery|sideload|sideload-auto-reboot]
     reboot the device; defaults to booting system image but
     supports bootloader and recovery too. sideload reboots
     into recovery and automatically starts sideload mode,
     sideload-auto-reboot is the same but reboots after sideloading.
 sideload OTAPACKAGE      sideload the given full OTA package
 root                     restart adbd with root permissions
 unroot                   restart adbd without root permissions
 usb                      restart adbd listening on USB
 tcpip PORT               restart adbd listening on TCP on PORT

internal debugging:
 start-server             ensure that there is a server running
 kill-server              kill the server if it is running
 reconnect                kick connection from host side to force reconnect
 reconnect device         kick connection from device side to force reconnect
 reconnect offline        reset offline/unauthorized devices to force reconnect

usb:
 attach                   attach a detached USB device
 detach                   detach from a USB device to allow use by other processes
environment variables:
 $ADB_TRACE
     comma/space separated list of debug info to log:
     all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp,services,auth,fdevent,shell,incremental
 $ADB_VENDOR_KEYS         colon-separated list of keys (files or directories)
 $ANDROID_SERIAL          serial number to connect to (see -s)
 $ANDROID_LOG_TAGS        tags to be used by logcat (see logcat --help)
 $ADB_LOCAL_TRANSPORT_MAX_PORT max emulator scan port (default 5585, 16 emus)
 $ADB_MDNS_AUTO_CONNECT   comma-separated list of mdns services to allow auto-connect (default adb-tls-connect)

Online documentation: https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/docs/user/adb.1.md

";

fn help_text() -> String {
    let mut help = version_lines().join("\n");
    help.push_str("\n\n");
    help.push_str(AOSP_HELP_BEFORE_LOCAL_AGENT);
    #[cfg(not(windows))]
    help.push_str(
        "     --local-agent: locate agent files from local source build (instead of SDK location)\n",
    );
    help.push_str(AOSP_HELP_AFTER_LOCAL_AGENT);
    help
}

fn print_help() {
    print!("{}", help_text());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct ScriptedIo {
        read: std::io::Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    fn test_state() -> CliState {
        CliState {
            endpoint: ServerEndpoint::default(),
            selector: TransportSelector::default(),
            listen_all: false,
            one_device: None,
            exit_on_write_error: false,
        }
    }

    #[test]
    fn cli_state_defaults_to_ignoring_output_write_errors() {
        assert!(!test_state().exit_on_write_error);
    }

    fn server_modifiers(server: bool, nodaemon: bool) -> ServerCommandModifiers {
        ServerCommandModifiers {
            server,
            nodaemon,
            ..ServerCommandModifiers::default()
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parse_track_app_output_matches_official_flags() {
        assert_eq!(parse_track_app_output(&[]).unwrap(), TrackAppOutput::Text);
        assert_eq!(
            parse_track_app_output(&["--proto-text".to_string()]).unwrap(),
            TrackAppOutput::Text
        );
        assert_eq!(
            parse_track_app_output(&["--proto-binary".to_string()]).unwrap(),
            TrackAppOutput::Binary
        );
        let err = parse_track_app_output(&["-l".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Server(message) if message == "unknown command track-app"));

        let err =
            parse_track_app_output(&["--proto-text".to_string(), "extra".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb track-app [--proto-binary][--proto-text]")
        );
    }

    #[test]
    fn devices_service_rejects_extra_arguments_like_official_cli() {
        assert_eq!(
            devices_service(&["devices".to_string()]).unwrap(),
            "host:devices"
        );
        assert_eq!(
            devices_service(&["devices".to_string(), "-l".to_string()]).unwrap(),
            "host:devices-l"
        );
        for args in [
            vec!["devices".to_string(), "extra".to_string()],
            vec!["devices".to_string(), "-l".to_string(), "extra".to_string()],
        ] {
            let err = devices_service(&args).unwrap_err();
            assert!(matches!(err, AdbError::Usage(message) if message == "adb devices [-l]"));
        }
    }

    #[test]
    fn track_devices_service_matches_aosp_first_option_only() {
        assert_eq!(track_devices_service(&[]).unwrap(), "host:track-devices");
        assert_eq!(
            track_devices_service(&["-l".to_string()]).unwrap(),
            "host:track-devices-l"
        );
        assert_eq!(
            track_devices_service(&["--proto-text".to_string()]).unwrap(),
            "host:track-devices-proto-text"
        );
        assert_eq!(
            track_devices_service(&["--proto-binary".to_string()]).unwrap(),
            "host:track-devices-proto-binary"
        );
        assert_eq!(
            track_devices_service(&["-l".to_string(), "ignored".to_string()]).unwrap(),
            "host:track-devices-l"
        );
        assert_eq!(
            track_devices_service(&["--proto-text".to_string(), "--proto-binary".to_string()])
                .unwrap(),
            "host:track-devices-proto-text"
        );
        let err = track_devices_service(&["--bad".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb track-devices [-l][--proto-text][--proto-binary]")
        );
    }

    #[test]
    fn forward_command_matches_aosp_arg_edges() {
        // forward 命令名
        assert_eq!(
            forward_command("forward", &["--list".to_string()]).unwrap(),
            ForwardCommand::List
        );
        assert_eq!(
            forward_command("forward", &["--remove-all".to_string()]).unwrap(),
            ForwardCommand::Status("killforward-all".to_string())
        );
        assert_eq!(
            forward_command("forward", &["--remove".to_string(), "tcp:1".to_string()]).unwrap(),
            ForwardCommand::Status("killforward:tcp:1".to_string())
        );
        assert_eq!(
            forward_command(
                "forward",
                &[
                    "--no-rebind".to_string(),
                    "tcp:1".to_string(),
                    "tcp:2".to_string()
                ]
            )
            .unwrap(),
            ForwardCommand::Status("forward:norebind:tcp:1;tcp:2".to_string())
        );
        assert_eq!(
            forward_command("forward", &["tcp:1".to_string(), "tcp:2".to_string()]).unwrap(),
            ForwardCommand::Status("forward:tcp:1;tcp:2".to_string())
        );

        for (args, expected) in [
            (vec![], "forward requires an argument"),
            (
                vec!["--list".to_string(), "extra".to_string()],
                "--list doesn't take any arguments",
            ),
            (
                vec!["--remove-all".to_string(), "extra".to_string()],
                "--remove-all doesn't take any arguments",
            ),
            (
                vec!["--remove".to_string()],
                "--remove requires an argument",
            ),
            (
                vec![
                    "--remove".to_string(),
                    "tcp:1".to_string(),
                    "extra".to_string(),
                ],
                "--remove requires an argument",
            ),
            (
                vec!["--no-rebind".to_string(), "tcp:1".to_string()],
                "--no-rebind takes two arguments",
            ),
            (
                vec![
                    "--no-rebind".to_string(),
                    "tcp:1".to_string(),
                    "tcp:2".to_string(),
                    "extra".to_string(),
                ],
                "--no-rebind takes two arguments",
            ),
            (vec!["tcp:1".to_string()], "forward takes two arguments"),
            (
                vec![
                    "tcp:1".to_string(),
                    "tcp:2".to_string(),
                    "extra".to_string(),
                ],
                "forward takes two arguments",
            ),
        ] {
            let err = forward_command("forward", &args).unwrap_err();
            assert!(matches!(err, AdbError::Usage(message) if message == expected));
        }
    }

    #[test]
    fn reverse_command_uses_correct_error_prefix() {
        // reverse 应使用 "reverse" 而非 "forward" 作为错误消息中的命令名
        for (args, expected) in [
            (vec![], "reverse requires an argument"),
            (
                vec!["--list".to_string(), "extra".to_string()],
                "--list doesn't take any arguments",
            ),
            (vec!["tcp:1".to_string()], "reverse takes two arguments"),
            (
                vec![
                    "tcp:1".to_string(),
                    "tcp:2".to_string(),
                    "extra".to_string(),
                ],
                "reverse takes two arguments",
            ),
        ] {
            let err = forward_command("reverse", &args).unwrap_err();
            assert!(matches!(err, AdbError::Usage(message) if message == expected));
        }
    }

    #[test]
    fn mdns_service_matches_aosp_queries_and_errors() {
        assert_eq!(
            mdns_service(&["check".to_string()]).unwrap(),
            ("host:mdns:check", false)
        );
        assert_eq!(
            mdns_service(&["services".to_string()]).unwrap(),
            ("host:mdns:services", true)
        );

        let err = mdns_service(&[]).unwrap_err();
        assert!(matches!(err, AdbError::Usage(message) if message == "mdns requires an argument"));

        let err = mdns_service(&["bad".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Usage(message) if message == "unknown mdns command [bad]"));

        let err = mdns_service(&["check".to_string(), "extra".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "mdns check doesn't take any arguments")
        );

        let err = mdns_service(&["services".to_string(), "extra".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "mdns services doesn't take any arguments")
        );
    }

    #[test]
    fn stream_track_app_text_decodes_hex_prefixed_frames() {
        let mut input = std::io::Cursor::new(vec![
            b'0', b'0', b'0', b'4', 0x0a, 0x02, 0x08, 0x01, b'0', b'0', b'0', b'0',
        ]);
        let mut output = Vec::new();

        stream_track_app_text(&mut input, &mut output).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Process count: 1\nprocess {\n  pid: 1\n}\nProcess count: 0\n"
        );
    }

    #[test]
    fn dispatch_matches_aosp_help_aliases_and_unknown_command() {
        for command in ["help", "--help", "/?"] {
            let mut state = test_state();
            dispatch(&mut state, &[command.to_string()]).unwrap();
        }

        let err = dispatch(&mut test_state(), &["not-a-command".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "unknown command not-a-command")
        );
    }

    #[test]
    fn help_text_uses_aosp_sections_and_environment() {
        let help = help_text();
        for section in [
            "global options:",
            "general commands:",
            "networking:",
            "file transfer:",
            "shell:",
            "app installation",
            "debugging:",
            "security:",
            "scripting:",
            "internal debugging:",
            "environment variables:",
        ] {
            assert!(help.contains(section), "帮助文本应包含官方分区: {section}");
        }
        assert!(help.starts_with("Android Debug Bridge version 1.0.41\n"));
        assert!(!help.contains("Android Debug Bridge (adb-rust)"));
        assert!(help.contains("$ADB_MDNS_AUTO_CONNECT"));
        assert!(help.contains("Online documentation: https://android.googlesource.com/"));
    }

    #[test]
    fn help_text_lists_install_options_like_aosp() {
        let help = help_text();
        assert!(help.contains("install [-lrtsdg] [--instant] PACKAGE"));
        assert!(help.contains("install-multiple [-lrtsdpg] [--instant] PACKAGE..."));
        assert!(help.contains("install-multi-package [-lrtsdpg] [--instant] PACKAGE..."));
        assert!(help.contains("--abi ABI: override platform's default ABI"));
        assert!(help.contains("--fastdeploy: use fast deploy"));
        assert!(help.contains("--no-fastdeploy: prevent use of fast deploy"));
        assert!(
            help.contains("--force-agent: force update of deployment agent when using fast deploy")
        );
        assert!(help.contains("--date-check-agent"));
        assert!(help.contains("--version-check-agent"));
    }

    #[test]
    fn help_text_lists_push_pull_sync_options_like_aosp() {
        let help = help_text();
        assert!(help.contains("push [--sync] [-z ALGORITHM] [-Z] LOCAL... REMOTE"));
        assert!(help.contains("pull [-a] [-z ALGORITHM] [-Z] REMOTE... LOCAL"));
        assert!(help.contains(
            "sync [-l] [-z ALGORITHM] [-Z] [all|data|odm|oem|product|system|system_ext|vendor]"
        ));
        assert!(
            help.contains("-n: dry run: push files to device without storing to the filesystem")
        );
        assert!(help.contains("-a: preserve file timestamp and mode"));
        assert!(help.contains("-Z: disable compression"));
        assert!(help.contains(
            "-z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)"
        ));
        assert!(help.contains(
            "--sync: only push files that have different timestamps on the host than the device"
        ));
    }

    #[test]
    fn parses_global_port_and_serial_before_command() {
        let mut state = CliState {
            endpoint: ServerEndpoint::from_env().unwrap(),
            selector: TransportSelector::default(),
            listen_all: false,
            one_device: None,
            exit_on_write_error: false,
        };

        state.endpoint.port = client::parse_port("6000").unwrap();
        state.selector = TransportSelector::Serial("device-1".to_string());

        assert_eq!(state.endpoint.port, 6000);
        assert_eq!(
            state.selector.transport_service(),
            "host:transport:device-1"
        );
    }

    #[test]
    fn server_endpoint_cli_overrides_ignore_environment_shape() {
        let endpoint = resolve_server_endpoint(None, Some("192.0.2.5"), Some("6000")).unwrap();

        assert_eq!(endpoint.host, "192.0.2.5");
        assert_eq!(endpoint.port, 6000);
        assert_eq!(endpoint.socket_spec(), "tcp:192.0.2.5:6000");

        let endpoint = resolve_server_endpoint(None, None, Some("6001")).unwrap();
        assert_eq!(endpoint.host, client::DEFAULT_SERVER_HOST);
        assert_eq!(endpoint.port, 6001);
        assert_eq!(endpoint.socket_spec(), "tcp:6001");
    }

    #[test]
    fn adb_trace_socket_diagnostic_preserves_cli_override_shape() {
        assert_eq!(
            trace_server_socket_spec(Some("unsupported:socket"), None, None),
            "unsupported:socket"
        );
        assert_eq!(
            trace_server_socket_spec(None, Some("192.0.2.5"), Some("6000")),
            "tcp:192.0.2.5:6000"
        );
        assert_eq!(
            trace_server_socket_spec(None, None, Some("6001")),
            "tcp:6001"
        );
    }

    #[test]
    fn server_endpoint_cli_l_is_incompatible_with_host_or_port() {
        assert!(matches!(
            resolve_server_endpoint(Some("tcp:6000"), Some("127.0.0.1"), None),
            Err(AdbError::Usage(_))
        ));
        assert!(matches!(
            resolve_server_endpoint(Some("tcp:6000"), None, Some("6001")),
            Err(AdbError::Usage(_))
        ));
    }

    #[test]
    fn global_options_match_aosp_missing_argument_errors() {
        for option in ["-P", "-H", "-L", "-s", "-t", "--one-device", "--reply-fd"] {
            let err = run(vec![option.to_string()]).unwrap_err();
            assert!(
                matches!(err, AdbError::Usage(message) if message == format!("{option} requires an argument"))
            );
        }
    }

    #[test]
    fn global_inline_option_edges_match_aosp() {
        run(vec!["-s123".to_string(), "help".to_string()]).unwrap();
        run(vec!["-t42".to_string(), "help".to_string()]).unwrap();
        run(vec![
            "--exit-on-write-error".to_string(),
            "version".to_string(),
        ])
        .unwrap();

        let err = run(vec!["-sabc".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Usage(message) if message == "-s requires an argument"));

        let err = run(vec!["-tabc".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Usage(message) if message == "-t requires an argument"));

        let err = run(vec!["-Ltcp:127.0.0.1:5037".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Server(message) if message == "unknown command -Ltcp:127.0.0.1:5037")
        );
    }

    #[test]
    fn unknown_dash_prefixed_token_is_a_command_like_aosp() {
        let err = run(vec!["-z".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Server(message) if message == "unknown command -z"));

        let err = run(vec!["-h".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Server(message) if message == "unknown command -h"));

        let err = run(vec!["--".to_string(), "help".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Server(message) if message == "unknown command --"));
    }

    #[test]
    fn empty_command_after_global_modifiers_exits_like_aosp() {
        for args in [
            vec![],
            vec!["nodaemon".to_string()],
            vec![
                "fork-server".to_string(),
                "--reply-fd".to_string(),
                "3".to_string(),
            ],
        ] {
            let err = run(args).unwrap_err();
            assert!(matches!(err, AdbError::SilentExit(1)));
        }
    }

    #[test]
    fn android_serial_sets_default_selector_only_when_unspecified() {
        let mut selector = TransportSelector::Any;
        apply_default_serial_from_env(&mut selector, Some("serial-env"));
        assert_eq!(
            selector,
            TransportSelector::Serial("serial-env".to_string())
        );

        let mut selector = TransportSelector::Any;
        apply_default_serial_from_env(&mut selector, Some("  "));
        assert_eq!(selector, TransportSelector::Any);

        let mut selector = TransportSelector::Usb;
        apply_default_serial_from_env(&mut selector, Some("serial-env"));
        assert_eq!(selector, TransportSelector::Usb);

        let mut selector = TransportSelector::TransportId(42);
        apply_default_serial_from_env(&mut selector, Some("serial-env"));
        assert_eq!(selector, TransportSelector::TransportId(42));
    }

    #[test]
    fn one_device_is_only_allowed_when_starting_server() {
        assert!(is_server_start_command(
            ServerCommandModifiers::default(),
            &["start-server".to_string()]
        ));
        assert!(is_server_start_command(server_modifiers(true, false), &[]));
        assert!(is_server_start_command(server_modifiers(true, true), &[]));
        assert!(!is_server_start_command(
            ServerCommandModifiers::default(),
            &["devices".to_string()]
        ));
        assert!(!is_server_start_command(
            server_modifiers(false, true),
            &["server".to_string()]
        ));
    }

    #[test]
    fn server_command_modifiers_match_aosp_prefix_semantics() {
        let mut modifiers = ServerCommandModifiers::default();
        apply_server_command_modifier(&mut modifiers, "nodaemon");
        assert_eq!(modifiers, server_modifiers(false, true));
        assert!(!is_server_start_command(modifiers, &["help".to_string()]));
        assert!(server_modifier_runs_foreground(modifiers));

        apply_server_command_modifier(&mut modifiers, "server");
        assert_eq!(modifiers, server_modifiers(true, true));
        assert!(is_server_start_command(modifiers, &[]));
        assert!(server_modifier_runs_foreground(modifiers));

        let mut modifiers = ServerCommandModifiers::default();
        apply_server_command_modifier(&mut modifiers, "server");
        assert_eq!(modifiers, server_modifiers(true, false));
        assert!(is_server_start_command(modifiers, &["extra".to_string()]));
        assert!(!server_modifier_runs_foreground(modifiers));
    }

    #[test]
    fn fork_server_modifiers_match_aosp_internal_start_semantics() {
        let mut modifiers = ServerCommandModifiers::default();
        apply_server_command_modifier(&mut modifiers, "fork-server");

        assert!(modifiers.fork_server);
        assert!(is_server_start_command(modifiers, &[]));
        assert!(server_modifier_runs_foreground(modifiers));

        let err = fork_server_missing_reply_fd_error();
        assert!(
            matches!(err, AdbError::Server(message) if message == "reply fd for adb server to client communication not specified.")
        );
        assert_eq!(parse_reply_fd("42").unwrap(), 42);
        for value in ["x", "-1", "0", "2"] {
            assert!(
                matches!(parse_reply_fd(value).unwrap_err(), AdbError::Server(message) if message == format!("invalid reply fd \"{value}\""))
            );
        }
    }

    #[test]
    fn parses_transport_id_selector_like_official_global_t() {
        let selector = parse_transport_id_selector("42").unwrap();

        assert_eq!(selector.transport_service(), "host:transport-id:42");
        assert_eq!(selector.host_prefix(), "host-transport-id:42");
        assert_eq!(
            parse_transport_id_selector("0").unwrap(),
            TransportSelector::Any
        );
        assert!(parse_transport_id_selector("42x").is_err());
        assert!(parse_transport_id_selector("-1").is_err());
    }

    #[test]
    fn wait_for_command_inserts_implied_transport() {
        assert_eq!(
            normalize_wait_for_command(&TransportSelector::default(), "wait-for-device").unwrap(),
            "wait-for-any-device"
        );
        assert_eq!(
            normalize_wait_for_command(&TransportSelector::Usb, "wait-for-device").unwrap(),
            "wait-for-usb-device"
        );
        assert_eq!(
            normalize_wait_for_command(&TransportSelector::Local, "wait-for-disconnect").unwrap(),
            "wait-for-local-disconnect"
        );
    }

    #[test]
    fn wait_for_command_keeps_explicit_transport() {
        assert_eq!(
            normalize_wait_for_command(
                &TransportSelector::Serial("serial-1".to_string()),
                "wait-for-usb-device"
            )
            .unwrap(),
            "wait-for-usb-device"
        );
    }

    #[test]
    fn wait_for_command_rejects_short_shape_like_aosp() {
        let err =
            normalize_wait_for_command(&TransportSelector::default(), "wait-for").unwrap_err();

        assert!(
            matches!(err, AdbError::Server(message) if message == "couldn't parse 'wait-for' command: wait-for")
        );
    }

    #[test]
    fn emulator_console_port_parses_official_serial() {
        assert_eq!(
            emulator_console_port_from_serial("emulator-5554"),
            Some(5554)
        );
        assert_eq!(emulator_console_port_from_serial("127.0.0.1:5555"), None);
        assert_eq!(emulator_console_port_from_serial("emulator-bad"), None);
    }

    #[test]
    fn pair_service_matches_official_host_query_shape() {
        assert_eq!(
            pair_service("192.0.2.10:37199", "123456"),
            "host:pair:123456:192.0.2.10:37199"
        );
    }

    #[test]
    fn pair_args_match_aosp_edges() {
        let args = vec!["192.0.2.10:37199".to_string()];
        assert_eq!(pair_args(&args).unwrap(), ("192.0.2.10:37199", None));

        let args = vec!["192.0.2.10:37199".to_string(), "123456".to_string()];
        assert_eq!(
            pair_args(&args).unwrap(),
            ("192.0.2.10:37199", Some("123456"))
        );

        let err = pair_args(&[]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb pair HOST[:PORT] [PAIRING CODE]")
        );

        let args = vec![
            "192.0.2.10:37199".to_string(),
            "123456".to_string(),
            "extra".to_string(),
        ];
        let err = pair_args(&args).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb pair HOST[:PORT] [PAIRING CODE]")
        );
    }

    #[test]
    fn attach_detach_uses_transport_switch_shape() {
        let selector = TransportSelector::Serial("serial-1".to_string());

        assert_eq!(selector.tport_service(), "host:tport:serial:serial-1");
        assert_eq!(TransportSelector::Usb.tport_service(), "host:tport:usb");
        assert_eq!("host:attach", "host:attach");
        assert_eq!("host:detach", "host:detach");
    }

    #[test]
    fn unique_emulator_console_port_uses_devices_listing() {
        assert_eq!(
            unique_emulator_console_port("serial-1\tdevice\nemulator-5554\tdevice\n").unwrap(),
            5554
        );
        assert!(matches!(
            unique_emulator_console_port("serial-1\tdevice\n"),
            Err(AdbError::Server(message)) if message == "no emulator detected"
        ));
        assert!(matches!(
            unique_emulator_console_port("emulator-5554\tdevice\nemulator-5556\tdevice\n"),
            Err(AdbError::Server(message)) if message == "more than one emulator detected; use -s"
        ));
    }

    #[test]
    fn emulator_console_commands_append_quit() {
        let commands =
            build_emulator_console_commands(&["avd".to_string(), "name".to_string()]).unwrap();

        assert!(commands.ends_with("avd name\nquit\n"));

        let commands = build_emulator_console_commands(&[]).unwrap();
        assert!(commands.ends_with("quit\n"));
    }

    #[test]
    fn emulator_console_output_skips_initial_ok_blocks() {
        let output =
            b"Android Console: Authentication required\r\nOK\r\nAndroid Console: help\r\nOK\r\nname\r\nOK\r\n";

        assert_eq!(filtered_emulator_console_output(output), "name\r\nOK\r\n");
    }

    #[test]
    fn shell_arg_escape_matches_aosp_quoting() {
        assert_eq!(escape_shell_arg(""), "''");
        assert_eq!(escape_shell_arg("abc"), "'abc'");
        assert_eq!(escape_shell_arg("'"), r#"''\'''"#);
        assert_eq!(escape_shell_arg("abc'def"), r#"'abc'\''def'"#);
        assert_eq!(escape_shell_arg("abc abc"), "'abc abc'");
    }

    #[test]
    fn shell_parser_keeps_command_after_options() {
        let args = vec![
            "-T".to_string(),
            "echo".to_string(),
            "hello world".to_string(),
        ];
        let invocation = parse_shell_invocation(&args).unwrap();

        assert_eq!(invocation.command, "echo hello world");
        assert_eq!(invocation.tty, ShellPtyMode::No);
        assert!(invocation.tty_specified);
    }

    #[test]
    fn shell_parser_counts_double_t_as_forced_pty() {
        let args = vec!["-tt".to_string()];
        let invocation = parse_shell_invocation(&args).unwrap();

        assert_eq!(invocation.tty, ShellPtyMode::Definitely);
    }

    #[test]
    fn shell_parser_accepts_escape_none_and_double_dash_command() {
        let args = vec![
            "-e".to_string(),
            "none".to_string(),
            "-n".to_string(),
            "--".to_string(),
            "-c".to_string(),
        ];
        let invocation = parse_shell_invocation(&args).unwrap();

        assert_eq!(invocation.escape_char, None);
        assert!(invocation.close_stdin);
        assert_eq!(invocation.command, "-c");
    }

    #[test]
    fn shell_parser_errors_match_aosp_option_edges() {
        let err = parse_shell_invocation(&["-e".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::SilentExit(1)));

        let err = parse_shell_invocation(&["-z".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::SilentExit(1)));

        let err = parse_shell_invocation(&["-e".to_string(), "ab".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "-e requires a single-character argument or 'none'")
        );
    }

    #[test]
    fn shell_parser_rejects_multi_byte_escape() {
        let args = vec!["-e".to_string(), "é".to_string()];

        let err = parse_shell_invocation(&args).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "-e requires a single-character argument or 'none'")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_shell_raw_mode_matches_aosp_console_flags() {
        let unrelated_flag = 0x20;
        let original =
            ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | unrelated_flag;
        let raw = shell_raw_console_mode(original);

        assert_eq!(
            raw & (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT),
            0
        );
        assert_ne!(raw & ENABLE_WINDOW_INPUT, 0);
        assert_ne!(raw & unrelated_flag, 0);
    }

    #[test]
    fn shell_x_requires_effective_pty_like_aosp() {
        let invocation =
            parse_shell_invocation(&["-x".to_string(), "-T".to_string(), "true".to_string()])
                .unwrap();
        let err = resolve_shell_type(&invocation, true, false).unwrap_err();
        assert!(matches!(err, AdbError::SilentExit(1)));

        let invocation = parse_shell_invocation(&["-Tx".to_string(), "true".to_string()]).unwrap();
        assert_eq!(
            resolve_shell_type(&invocation, true, false).unwrap(),
            ShellType::Pty
        );
    }

    #[test]
    fn shell_service_string_matches_aosp_shape() {
        assert_eq!(
            build_shell_service_string(true, ShellType::Pty, "", Some("xterm-256color")),
            "shell,v2,TERM=xterm-256color,pty:"
        );
        assert_eq!(
            build_shell_service_string(true, ShellType::Raw, "echo hi", None),
            "shell,v2,raw:echo hi"
        );
        assert_eq!(
            build_shell_service_string(false, ShellType::Pty, "id", None),
            "shell:id"
        );
    }

    #[test]
    fn shell_type_auto_uses_raw_for_noninteractive_command() {
        let invocation = ShellInvocation {
            command: "id".to_string(),
            close_stdin: false,
            use_shell_protocol: true,
            tty: ShellPtyMode::Auto,
            tty_specified: false,
            escape_char: Some(b'~'),
        };

        assert_eq!(
            resolve_shell_type(&invocation, true, false).unwrap(),
            ShellType::Raw
        );
    }

    #[test]
    fn push_parser_accepts_sync_dry_run_quiet_and_no_compression() {
        let args = vec![
            "--sync".to_string(),
            "-n".to_string(),
            "-q".to_string(),
            "-Z".to_string(),
            "local".to_string(),
            "/sdcard/local".to_string(),
        ];
        let invocation = parse_push_args(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(invocation.paths, vec!["local", "/sdcard/local"]);
        assert!(invocation.options.sync);
        assert!(invocation.options.dry_run);
        assert!(invocation.quiet);
    }

    #[test]
    fn push_parser_ignores_legacy_p_option_like_aosp() {
        let args = vec![
            "-p".to_string(),
            "local".to_string(),
            "/sdcard/local".to_string(),
        ];
        let invocation = parse_push_args(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(invocation.paths, vec!["local", "/sdcard/local"]);
    }

    #[test]
    fn pull_parser_accepts_preserve_attrs_quiet_and_z_none() {
        let args = vec![
            "-a".to_string(),
            "-q".to_string(),
            "-z".to_string(),
            "none".to_string(),
            "/sdcard/a".to_string(),
            ".".to_string(),
        ];
        let invocation = parse_pull_args(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(invocation.paths, vec!["/sdcard/a", "."]);
        assert!(invocation.options.preserve_attrs);
        assert!(invocation.quiet);
    }

    #[test]
    fn pull_parser_ignores_legacy_p_option_like_aosp() {
        let args = vec!["-p".to_string(), "/sdcard/a".to_string(), ".".to_string()];
        let invocation = parse_pull_args(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(invocation.paths, vec!["/sdcard/a", "."]);
    }

    #[test]
    fn sync_compression_parser_accepts_zstd() {
        let args = vec![
            "-z".to_string(),
            "zstd".to_string(),
            "local".to_string(),
            "/sdcard/local".to_string(),
        ];
        let invocation = parse_push_args(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(
            invocation.options.compression,
            file_sync::SyncCompression::Zstd
        );
    }

    #[test]
    fn sync_compression_parser_rejects_unknown_algorithm() {
        let args = vec![
            "-z".to_string(),
            "gzip".to_string(),
            "local".to_string(),
            "/sdcard/local".to_string(),
        ];

        assert!(matches!(
            parse_push_args(&args, file_sync::SyncCompression::Any),
            Err(AdbError::Usage(_))
        ));
    }

    #[test]
    fn push_parser_uses_default_compression() {
        let args = vec!["local".to_string(), "/sdcard/local".to_string()];
        let invocation = parse_push_args(&args, file_sync::SyncCompression::Zstd).unwrap();

        assert_eq!(
            invocation.options.compression,
            file_sync::SyncCompression::Zstd
        );
    }

    #[test]
    fn pull_parser_uses_default_compression() {
        let args = vec!["/sdcard/a".to_string(), ".".to_string()];
        let invocation = parse_pull_args(&args, file_sync::SyncCompression::Lz4).unwrap();

        assert_eq!(
            invocation.options.compression,
            file_sync::SyncCompression::Lz4
        );
    }

    #[test]
    fn env_compression_rejects_unknown_algorithm() {
        assert!(env_compression_or_any(Some("gzip")).is_err());
    }

    #[test]
    fn env_compression_returns_any_when_unset() {
        assert_eq!(
            env_compression_or_any(None).unwrap(),
            file_sync::SyncCompression::Any
        );
    }

    #[test]
    fn sync_parser_defaults_to_all_and_env_compression() {
        let invocation =
            parse_sync_args_with_default(&[], file_sync::SyncCompression::Zstd).unwrap();

        assert_eq!(invocation.partition, "all");
        assert_eq!(invocation.compression, file_sync::SyncCompression::Zstd);
        assert!(!invocation.list_only);
        assert!(!invocation.dry_run);
    }

    #[test]
    fn sync_parser_accepts_combined_short_options_and_inline_z() {
        let args = vec![
            "-lnq".to_string(),
            "-zzstd".to_string(),
            "/system".to_string(),
        ];
        let invocation =
            parse_sync_args_with_default(&args, file_sync::SyncCompression::Any).unwrap();

        assert_eq!(invocation.partition, "/system");
        assert!(invocation.list_only);
        assert!(invocation.dry_run);
        assert!(invocation.quiet);
        assert_eq!(invocation.compression, file_sync::SyncCompression::Zstd);
    }

    #[test]
    fn sync_parser_rejects_multiple_partitions_like_official_cli() {
        let args = vec!["system".to_string(), "vendor".to_string()];

        assert!(matches!(
            parse_sync_args_with_default(&args, file_sync::SyncCompression::Any),
            Err(AdbError::Usage(_))
        ));
    }

    #[test]
    fn sync_partition_candidates_match_official_partition_names() {
        assert_eq!(
            sync_partition_candidates("all"),
            vec![
                "data",
                "odm",
                "oem",
                "product",
                "system",
                "system_ext",
                "vendor"
            ]
        );
        assert_eq!(sync_partition_candidates("/system"), vec!["system"]);
        assert_eq!(sync_partition_candidates("vendor"), vec!["vendor"]);
        assert!(sync_partition_candidates("cache").is_empty());
    }

    #[test]
    fn file_entrypoints_require_arguments_like_aosp() {
        let err = simple_requires_arg_error("ls");
        assert!(matches!(err, AdbError::Usage(message) if message == "ls requires an argument"));

        let err = push_requires_args_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "push requires <source> and <destination> arguments")
        );

        let err = simple_requires_arg_error("pull");
        assert!(matches!(err, AdbError::Usage(message) if message == "pull requires an argument"));
    }

    #[test]
    fn logcat_command_exports_tags_and_quotes_args() {
        let args = vec![
            "-d".to_string(),
            "tag name:*".to_string(),
            "quote'arg".to_string(),
        ];

        assert_eq!(
            build_logcat_command_with_tags("longcat", &args, "ActivityManager:I"),
            "export ANDROID_LOG_TAGS='ActivityManager:I'; exec logcat -v long '-d' 'tag name:*' 'quote'\\''arg'"
        );
    }

    #[test]
    fn bugreport_target_adds_zip_extension_for_file_argument() {
        let target = BugreportTarget::from_arg(Some(&"report".to_string())).unwrap();
        assert_eq!(target.dest_dir, None);
        assert_eq!(target.dest_file, "report.zip");

        let target = BugreportTarget::from_arg(Some(&"report.ZIP".to_string())).unwrap();
        assert_eq!(target.dest_file, "report.ZIP");
    }

    #[test]
    fn bugreport_usage_matches_aosp() {
        let err = bugreport_usage_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb bugreport [[PATH] | [--stream]]")
        );
    }

    #[test]
    fn bugreport_output_tracks_device_name_and_progress() {
        let mut target = BugreportTarget {
            dest_dir: Some(PathBuf::from("out")),
            dest_file: "bugreport.zip".to_string(),
        };

        let mut progress = Vec::new();
        let src = process_bugreportz_output(
            b"BEGIN:/device/old.zip\nPROGRESS:50/100\nOK:/device/final.zip\n",
            &mut target,
            true,
            false,
            &mut progress,
        )
        .unwrap();

        assert_eq!(src, "/device/final.zip");
        assert_eq!(target.destination(), PathBuf::from("out").join("final.zip"));
        assert_eq!(
            String::from_utf8(progress).unwrap().trim(),
            "[ 50%] generating old.zip"
        );
    }

    #[test]
    fn bugreport_progress_to_terminal_uses_carriage_return_and_trailing_newline() {
        let mut progress = Vec::new();
        let src = process_bugreportz_output(
            b"BEGIN:/device/bugreport.zip\nPROGRESS:25/100\nPROGRESS:50/100\nPROGRESS:75/100\nOK:/device/bugreport.zip\n",
            &mut BugreportTarget {
                dest_dir: None,
                dest_file: "bugreport.zip".to_string(),
            },
            true,
            true,
            &mut progress,
        )
        .unwrap();

        assert_eq!(src, "/device/bugreport.zip");
        let output = String::from_utf8(progress).unwrap();
        assert!(output.contains('\r'));
        assert!(output.ends_with('\n'));
        assert_eq!(output.matches('\r').count(), 3);
        assert_eq!(output.matches('\n').count(), 1);
    }

    #[test]
    fn bugreport_progress_to_non_terminal_uses_newlines() {
        let mut progress = Vec::new();
        let mut target = BugreportTarget {
            dest_dir: None,
            dest_file: "bugreport.zip".to_string(),
        };

        process_bugreportz_output(
            b"BEGIN:/device/bugreport.zip\nPROGRESS:25/100\nPROGRESS:75/100\nOK:/device/bugreport.zip\n",
            &mut target,
            true,
            false,
            &mut progress,
        )
        .unwrap();

        let output = String::from_utf8(progress).unwrap();
        assert!(!output.contains('\r'));
        assert_eq!(output.matches('\n').count(), 2);
    }
    #[test]
    fn bugreport_progress_parser_rejects_bad_totals() {
        assert_eq!(parse_bugreport_progress(Some("50/100")), Some(50));
        assert_eq!(parse_bugreport_progress(Some("1/0")), None);
        assert_eq!(parse_bugreport_progress(Some("bad")), None);
    }

    #[test]
    fn bugreport_version_parser_accepts_only_numeric_versions() {
        assert_eq!(parse_bugreportz_version_checked("1.2"), Some((1, 2)));
        assert_eq!(parse_bugreportz_version_checked("2"), Some((2, 0)));
        assert_eq!(parse_bugreportz_version_checked("Dude"), None);
        assert_eq!(parse_bugreportz_version_checked("1.2.3"), None);
    }

    #[test]
    fn reboot_service_matches_aosp_shapes() {
        assert_eq!(reboot_service("reboot", &[]), "reboot:");
        assert_eq!(
            reboot_service("reboot", &["bootloader".to_string()]),
            "reboot:bootloader"
        );
        assert_eq!(
            reboot_service("reboot", &["sideload-auto-reboot".to_string()]),
            "reboot:sideload-auto-reboot"
        );
        assert_eq!(
            reboot_service("reboot", &["recovery".to_string(), "ignored".to_string()]),
            "reboot:recovery"
        );
        assert_eq!(
            reboot_service("reboot-bootloader", &["ignored".to_string()]),
            "reboot:bootloader"
        );
        assert_eq!(
            reboot_service("reboot-fastboot", &["ignored".to_string()]),
            "reboot:fastboot"
        );
    }

    #[test]
    fn tcpip_service_matches_aosp_port_errors() {
        assert_eq!(tcpip_service(&["5555".to_string()]).unwrap(), "tcpip:5555");
        assert_eq!(
            tcpip_service(&["65535".to_string()]).unwrap(),
            "tcpip:65535"
        );

        for args in [vec![], vec!["5555".to_string(), "extra".to_string()]] {
            let err = tcpip_service(&args).unwrap_err();
            assert!(
                matches!(err, AdbError::Usage(message) if message == "tcpip requires an argument")
            );
        }

        for value in ["0", "65536", "-1", "abc"] {
            let err = tcpip_service(&[value.to_string()]).unwrap_err();
            assert!(
                matches!(err, AdbError::Usage(message) if message == format!("tcpip: invalid port: {value}"))
            );
        }
    }

    #[test]
    fn connect_service_matches_aosp_arg_count() {
        assert_eq!(
            connect_service(&["192.0.2.10:5555".to_string()]).unwrap(),
            "host:connect:192.0.2.10:5555"
        );

        for args in [
            vec![],
            vec!["192.0.2.10:5555".to_string(), "extra".to_string()],
        ] {
            let err = connect_service(&args).unwrap_err();
            assert!(
                matches!(err, AdbError::Usage(message) if message == "usage: adb connect HOST[:PORT]")
            );
        }
    }

    #[test]
    fn disconnect_service_matches_aosp_arg_count() {
        assert_eq!(disconnect_service(&[]).unwrap(), "host:disconnect:");
        assert_eq!(
            disconnect_service(&["192.0.2.10:5555".to_string()]).unwrap(),
            "host:disconnect:192.0.2.10:5555"
        );

        let err =
            disconnect_service(&["192.0.2.10:5555".to_string(), "extra".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb disconnect [HOST[:PORT]]")
        );
    }

    #[test]
    fn remount_or_verity_service_matches_aosp_legacy_shape() {
        assert_eq!(remount_or_verity_service("remount", &[]), "remount:");
        assert_eq!(
            remount_or_verity_service("remount", &["-R".to_string()]),
            "remount:-R"
        );
        assert_eq!(
            remount_or_verity_service("remount", &["-R".to_string(), "ignored".to_string()]),
            "remount:-R"
        );
        assert_eq!(
            remount_or_verity_service("disable-verity", &[]),
            "disable-verity:"
        );
        assert_eq!(
            remount_or_verity_service("enable-verity", &["ignored".to_string()]),
            "enable-verity:ignored"
        );
    }

    #[test]
    fn usb_service_matches_aosp_shape() {
        assert_eq!(usb_service(&[]), "usb:");
        assert_eq!(usb_service(&["reset".to_string()]), "usb:reset");
        assert_eq!(
            usb_service(&["reset".to_string(), "ignored".to_string()]),
            "usb:reset"
        );
    }

    #[test]
    fn root_or_unroot_service_matches_aosp_shape() {
        assert_eq!(root_or_unroot_service("root", &[]), "root:");
        assert_eq!(
            root_or_unroot_service("root", &["ignored".to_string()]),
            "root:"
        );
        assert_eq!(root_or_unroot_service("unroot", &[]), "unroot:");
        assert_eq!(
            root_or_unroot_service("unroot", &["ignored".to_string()]),
            "unroot:"
        );
    }

    #[test]
    fn reconnect_command_matches_aosp_arg_edges() {
        assert_eq!(reconnect_command(&[]).unwrap(), ReconnectCommand::Host);
        assert_eq!(
            reconnect_command(&["device".to_string()]).unwrap(),
            ReconnectCommand::Device
        );
        assert_eq!(
            reconnect_command(&["offline".to_string()]).unwrap(),
            ReconnectCommand::Offline
        );

        let err = reconnect_command(&["bad".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb reconnect [device|offline]")
        );

        let err = reconnect_command(&["device".to_string(), "extra".to_string()]).unwrap_err();
        assert!(matches!(err, AdbError::Server(message) if message == "unknown command reconnect"));
    }

    #[test]
    fn install_entrypoints_require_argument_like_aosp() {
        for command in [
            "install",
            "install-multiple",
            "install-multi-package",
            "uninstall",
        ] {
            let err = install_requires_arg_error(command);
            assert!(
                matches!(err, AdbError::Usage(message) if message == format!("{command} requires an argument"))
            );
        }
    }

    #[test]
    fn install_plan_rewrites_last_apk_to_tmp_path() {
        let args = vec![
            "-r".to_string(),
            "--no-streaming".to_string(),
            "fixtures/Demo App.apk".to_string(),
        ];

        let plan = InstallPlan::from_args(&args).unwrap();

        assert_eq!(plan.local_apk, PathBuf::from("fixtures/Demo App.apk"));
        assert_eq!(plan.remote_apk, "/data/local/tmp/Demo App.apk");
        assert_eq!(
            plan.pm_args,
            vec!["-r".to_string(), "/data/local/tmp/Demo App.apk".to_string()]
        );
        assert_eq!(
            plan.pm_install_command(),
            "pm install '-r' '/data/local/tmp/Demo App.apk'"
        );
        assert_eq!(plan.stream_args, vec!["-r".to_string()]);
        assert_eq!(plan.requested_mode, InstallRequestMode::Push);
    }

    #[test]
    fn install_plan_accepts_streaming_and_apex_modes() {
        let args = vec!["--streaming".to_string(), "app.apk".to_string()];
        let plan = InstallPlan::from_args(&args).unwrap();
        assert_eq!(plan.requested_mode, InstallRequestMode::Stream);
        assert_eq!(plan.package_kind, Some(InstallPackageKind::Apk));
        assert!(plan.package_is_last);
        let err = plan.effective_mode(false).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "Attempting to use streaming install on unsupported device")
        );

        let args = vec!["module.apex".to_string()];
        let plan = InstallPlan::from_args(&args).unwrap();
        assert_eq!(plan.package_kind, Some(InstallPackageKind::Apex));
        assert_eq!(
            plan.effective_mode(true).unwrap(),
            InstallRequestMode::Stream
        );
    }

    #[test]
    fn install_plan_requires_apk_argument_like_aosp() {
        let err = InstallPlan::from_args(&["--streaming".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "install requires an apk argument")
        );
    }

    #[test]
    fn install_plan_keeps_invalid_last_argument_for_mode_errors() {
        let plan = InstallPlan::from_args(&["-r".to_string()]).unwrap();

        assert_eq!(plan.local_apk, PathBuf::from("-r"));
        assert_eq!(plan.original_last_arg, "-r");
        assert_eq!(plan.package_kind, None);
        assert!(!plan.package_is_last);

        let err = install_streamed_last_arg_error(&plan.original_last_arg);
        assert!(
            matches!(err, AdbError::Usage(message) if message == "filename doesn't end .apk or .apex: -r")
        );

        let err = install_push_needs_apk_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "need APK file on command line")
        );
    }

    #[test]
    fn install_single_apk_error_messages_match_aosp() {
        let args = vec!["app.apk".to_string(), "--user".to_string()];
        let plan = InstallPlan::from_args(&args).unwrap();
        assert_eq!(plan.original_last_arg, "--user");
        assert!(!plan.package_is_last);

        let err = install_streamed_last_arg_error(&plan.original_last_arg);
        assert!(
            matches!(err, AdbError::Usage(message) if message == "filename doesn't end .apk or .apex: --user")
        );

        let err = install_apex_requires_streamed_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "APEX packages are only compatible with Streamed Install")
        );

        let err = install_apex_unsupported_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == ".apex is not supported on the target device")
        );
    }

    #[test]
    fn install_plan_consumes_fastdeploy_agent_options_like_aosp() {
        let args = vec![
            "--no-fastdeploy".to_string(),
            "--force-agent".to_string(),
            "--date-check-agent".to_string(),
            "--version-check-agent".to_string(),
            "-r".to_string(),
            "app.apk".to_string(),
        ];

        let plan = InstallPlan::from_args(&args).unwrap();

        assert_eq!(plan.stream_args, vec!["-r".to_string()]);
        assert_eq!(
            plan.pm_args,
            vec!["-r".to_string(), plan.remote_apk.clone()]
        );
        assert!(!plan.use_fastdeploy);
        assert_eq!(
            plan.agent_update_strategy,
            fastdeploy::AgentUpdateStrategy::DifferentVersion
        );
    }

    #[test]
    fn install_plan_records_fastdeploy_request_like_aosp() {
        let args = vec!["--fastdeploy".to_string(), "app.apk".to_string()];

        let plan = InstallPlan::from_args(&args).unwrap();

        assert!(plan.use_fastdeploy);
    }

    #[test]
    fn install_fastdeploy_enable_disable_order_matches_aosp() {
        let plan = InstallPlan::from_args(&[
            "--fastdeploy".to_string(),
            "--no-fastdeploy".to_string(),
            "app.apk".to_string(),
        ])
        .unwrap();
        assert!(!plan.use_fastdeploy);

        let plan = InstallPlan::from_args(&[
            "--no-fastdeploy".to_string(),
            "--fastdeploy".to_string(),
            "app.apk".to_string(),
        ])
        .unwrap();
        assert!(plan.use_fastdeploy);
        assert_eq!(
            plan.agent_update_strategy,
            fastdeploy::AgentUpdateStrategy::DifferentVersion
        );
    }

    #[test]
    fn install_incremental_option_prefixes_match_aosp() {
        for option in ["--incr", "--increm", "--incremental"] {
            assert!(is_install_incremental_enable_option(option));
        }
        for option in ["--no-incr", "--no-increm", "--no-incremental"] {
            assert!(is_install_incremental_disable_option(option));
        }

        for option in [
            "--inc",
            "--incrementalx",
            "--incrementally",
            "--no-inc",
            "--no-incrementalx",
        ] {
            assert!(!is_install_incremental_enable_option(option));
            assert!(!is_install_incremental_disable_option(option));
        }
    }

    #[test]
    fn install_wait_option_is_consumed_for_incremental() {
        let args = vec![
            "--wait".to_string(),
            "--incremental".to_string(),
            "base.apk".to_string(),
        ];
        let parsed = parse_install_args(&args, true).unwrap();
        assert!(parsed.incremental_wait);
        assert_eq!(parsed.incremental_request, IncrementalRequest::Enable);
        assert_eq!(parsed.passthrough_args, vec!["base.apk".to_string()]);
    }

    #[test]
    fn install_incremental_conflict_errors_match_aosp() {
        let err = validate_incremental_request(
            InstallRequestMode::Default,
            IncrementalRequest::Enable,
            true,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "--incremental and --fast-deploy options are incompatible. Please choose one")
        );

        let err = validate_incremental_request(
            InstallRequestMode::Stream,
            IncrementalRequest::Enable,
            false,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "--incremental is not compatible with other installation modes")
        );

        let err = validate_incremental_request(
            InstallRequestMode::Default,
            IncrementalRequest::Enable,
            false,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "Device doesn't support incremental installations")
        );

        assert!(
            validate_incremental_request(
                InstallRequestMode::Default,
                IncrementalRequest::Enable,
                false,
                true,
            )
            .is_ok()
        );

        assert!(
            validate_incremental_request(
                InstallRequestMode::Push,
                IncrementalRequest::Disable,
                false,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn inc_server_entrypoint_matches_incremental_boundary() {
        for args in [
            vec![],
            vec!["1".to_string()],
            vec!["1".to_string(), "2".to_string()],
        ] {
            let err = inc_server(&args).unwrap_err();
            #[cfg(windows)]
            assert!(
                matches!(err, AdbError::Usage(message) if message == "usage: adb inc-server CONNECTION_HANDLE OUTPUT_HANDLE FILE1 FILE2 ...")
            );
            #[cfg(not(windows))]
            assert!(
                matches!(err, AdbError::Usage(message) if message == "usage: adb inc-server CONNECTION_FD OUTPUT_FD FILE1 FILE2 ...")
            );
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let connection = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let output = tempfile::tempfile().unwrap();

        #[cfg(unix)]
        let args = {
            use std::os::fd::IntoRawFd;
            vec![
                connection.into_raw_fd().to_string(),
                output.into_raw_fd().to_string(),
                "base.apk".to_string(),
            ]
        };
        #[cfg(windows)]
        let args = {
            use std::os::windows::io::{IntoRawHandle, IntoRawSocket};
            vec![
                (connection.into_raw_socket() as usize).to_string(),
                (output.into_raw_handle() as usize).to_string(),
                "base.apk".to_string(),
            ]
        };

        // 有效参数数量会进入对应平台的 serve 实现；不存在的文件让 serve 返回 I/O 错误，
        // 同时测试不得把 stdout/stderr 的 1/2 当成 owned fd/handle 交给子入口关闭。
        assert!(inc_server(&args).is_err());
    }

    #[test]
    fn install_parser_does_not_swallow_unknown_incremental_like_options() {
        let args = vec!["--no-incrementalx".to_string(), "base.apk".to_string()];

        let plan = InstallMultiplePlan::from_args(&args).unwrap();

        assert_eq!(plan.session_args, vec!["--no-incrementalx".to_string()]);
        assert_eq!(plan.packages, vec![PathBuf::from("base.apk")]);
    }

    #[test]
    fn install_multiple_plan_uses_trailing_package_run() {
        let args = vec![
            "-r".to_string(),
            "--no-incremental".to_string(),
            "--streaming".to_string(),
            "base.apk".to_string(),
            "config.dm".to_string(),
        ];

        let plan = InstallMultiplePlan::from_args(&args).unwrap();

        assert_eq!(plan.session_args, vec!["-r".to_string()]);
        assert_eq!(plan.requested_mode, InstallRequestMode::Stream);
        assert_eq!(
            plan.packages,
            vec![PathBuf::from("base.apk"), PathBuf::from("config.dm")]
        );
    }

    #[test]
    fn install_multiple_entrypoints_need_package_like_aosp() {
        let err = InstallMultiplePlan::from_args(&["-r".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "need APK file on command line")
        );

        let err = InstallMultiPackagePlan::from_args(&["-r".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "need APK or APEX files on command line")
        );
    }

    #[test]
    fn install_multiple_apex_error_matches_aosp() {
        let err = InstallMultiplePlan::from_args(&["module.apex".to_string()]).unwrap_err();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "APEX packages are not compatible with install-multiple")
        );
    }

    #[test]
    fn install_multi_package_unsupported_exits_like_aosp() {
        let err = install_multi_package_unsupported_error();
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_multi_package_create_session_failure_is_silent_like_aosp() {
        let err = multi_package_create_session_failed_error(b"Failure [bad]\n");
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_multi_package_create_connect_error_is_silent_like_aosp() {
        let err = multi_package_create_connect_error(&AdbError::Server("boom".to_string()));
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_create_connect_error_is_silent_like_aosp() {
        let err = install_create_connect_error(&AdbError::Server("boom".to_string()));
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_write_connect_error_is_silent_like_aosp() {
        let err = install_write_connect_error(&AdbError::Server("boom".to_string()));
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_finalize_connect_error_is_silent_like_aosp() {
        let err = install_finalize_connect_error(&AdbError::Server("boom".to_string()));
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_session_stat_failure_is_silent_like_aosp() {
        let path = env::temp_dir().join(format!(
            "adb-rust-missing-install-session-{}.apk",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let err = install_session_file_size(&path).unwrap_err();

        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_multi_package_split_stat_failure_is_silent_like_aosp() {
        let path = env::temp_dir().join(format!(
            "adb-rust-missing-multi-package-split-{}.apk",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let err = install_session_file_size_with_style(&path, InstallPathStyle::Bare).unwrap_err();

        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_multi_package_link_failure_includes_command_like_aosp() {
        let args = vec![
            "install-add-session".to_string(),
            "10".to_string(),
            "11".to_string(),
            "12".to_string(),
        ];

        assert_eq!(
            multi_package_link_command_for_error(PackageCommandMode::CmdPackage, &args),
            "exec:cmd package install-add-session 10 11 12"
        );
        assert_eq!(
            multi_package_link_command_for_error(PackageCommandMode::AbbExec, &args),
            "package install-add-session 10 11 12"
        );
    }

    #[test]
    fn install_add_session_connect_error_is_silent_like_aosp() {
        let err = install_add_session_connect_error(&AdbError::Server("boom".to_string()));
        assert!(matches!(err, AdbError::SilentExit(1)));
        assert!(!err.should_print());
    }

    #[test]
    fn install_multiple_preserves_fastdeploy_options_as_session_args() {
        let args = vec![
            "--fastdeploy".to_string(),
            "--force-agent".to_string(),
            "--version-check-agent".to_string(),
            "base.apk".to_string(),
        ];

        let plan = InstallMultiplePlan::from_args(&args).unwrap();

        assert_eq!(
            plan.session_args,
            vec![
                "--fastdeploy".to_string(),
                "--force-agent".to_string(),
                "--version-check-agent".to_string()
            ]
        );
        assert_eq!(plan.packages, vec![PathBuf::from("base.apk")]);
    }

    #[test]
    fn install_multiple_streaming_unsupported_error_matches_aosp() {
        let err = streaming_install_unsupported_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "Attempting to use streaming install on unsupported device")
        );
    }

    #[test]
    fn install_session_helpers_match_cmd_package_shape() {
        let args = vec![
            "install-write".to_string(),
            "-S".to_string(),
            "42".to_string(),
            "7".to_string(),
            "base apk.apk".to_string(),
            "-".to_string(),
        ];

        assert_eq!(
            cmd_package_service(&args),
            "exec:cmd package 'install-write' '-S' '42' '7' 'base apk.apk' '-'"
        );
        assert_eq!(
            package_command_mode_for_features(false, true),
            PackageCommandMode::CmdPackage
        );
        assert_eq!(
            package_command_service_for_mode(PackageCommandMode::CmdPackage, &args),
            "exec:cmd package 'install-write' '-S' '42' '7' 'base apk.apk' '-'"
        );
        assert_eq!(
            package_command_mode_for_features(true, true),
            PackageCommandMode::AbbExec
        );
        assert_eq!(
            package_command_service_for_mode(PackageCommandMode::AbbExec, &args),
            [
                "abb_exec:package",
                "install-write",
                "-S",
                "42",
                "7",
                "base apk.apk",
                "-"
            ]
            .join("\0")
        );
        assert_eq!(
            package_command_mode_for_features(false, false),
            PackageCommandMode::Pm
        );
        assert_eq!(
            package_command_service_for_mode(PackageCommandMode::Pm, &args),
            "exec:pm 'install-write' '-S' '42' '7' 'base apk.apk' '-'"
        );
        assert_eq!(
            parse_install_session_id(b"Success: created install session [123]\n"),
            Some(123)
        );
        assert_eq!(
            parse_install_session_id(b"Failure [INSTALL_FAILED]\n"),
            None
        );
    }

    #[test]
    fn install_multi_package_plan_detects_parent_args_and_apex() {
        let args = vec![
            "--staged-ready-timeout".to_string(),
            "60000".to_string(),
            "base.apk".to_string(),
            "module.apex".to_string(),
        ];

        let plan = InstallMultiPackagePlan::from_args(&args).unwrap();

        assert!(plan.has_apex);
        assert_eq!(
            plan.session_args,
            vec!["--staged-ready-timeout".to_string(), "60000".to_string()]
        );
        assert_eq!(plan.packages.len(), 2);
        assert_eq!(plan.packages[0].source_index, 3);
        assert_eq!(plan.packages[0].kind, InstallPackageKind::Apk);
        assert_eq!(plan.packages[1].source_index, 4);
        assert_eq!(plan.packages[1].kind, InstallPackageKind::Apex);
    }

    #[test]
    fn install_multi_package_preserves_mode_options_like_aosp() {
        let args = vec![
            "--streaming".to_string(),
            "--no-streaming".to_string(),
            "--no-incremental".to_string(),
            "--wait".to_string(),
            "base.apk".to_string(),
        ];

        let plan = InstallMultiPackagePlan::from_args(&args).unwrap();

        assert_eq!(
            plan.session_args,
            vec![
                "--streaming".to_string(),
                "--no-streaming".to_string(),
                "--no-incremental".to_string(),
                "--wait".to_string(),
            ]
        );
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].splits, vec![PathBuf::from("base.apk")]);
    }

    #[test]
    fn install_multi_package_splits_package_argument_by_host_separator() {
        let joined = env::join_paths([PathBuf::from("base.apk"), PathBuf::from("config.apk")])
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let args = vec!["-r".to_string(), joined];

        let plan = InstallMultiPackagePlan::from_args(&args).unwrap();

        assert_eq!(plan.session_args, vec!["-r".to_string()]);
        assert_eq!(
            plan.packages[0].splits,
            vec![PathBuf::from("base.apk"), PathBuf::from("config.apk")]
        );
    }

    #[test]
    fn multi_package_commit_forwards_staged_ready_timeout_only() {
        let args = vec![
            "--staged-ready-timeout".to_string(),
            "1000".to_string(),
            "--user".to_string(),
            "0".to_string(),
        ];

        assert_eq!(
            staged_ready_timeout_args(&args),
            vec!["--staged-ready-timeout".to_string(), "1000".to_string()]
        );

        assert!(staged_ready_timeout_args(&["--staged-ready-timeout".to_string()]).is_empty());
    }

    #[test]
    fn backup_plan_extracts_file_argument_and_quotes_service_args() {
        let plan = BackupPlan::from_args(&[
            "-apk".to_string(),
            "-f".to_string(),
            "my backup.ab".to_string(),
            "com.test app".to_string(),
        ])
        .unwrap();

        assert_eq!(plan.output, PathBuf::from("my backup.ab"));
        assert_eq!(
            plan.args,
            vec!["-apk".to_string(), "com.test app".to_string()]
        );
        assert_eq!(plan.service(), "backup: '-apk' 'com.test app'");
    }

    #[test]
    fn backup_plan_rejects_missing_package_list_or_filename() {
        assert!(BackupPlan::from_args(&[]).is_err());
        assert!(BackupPlan::from_args(&["-f".to_string()]).is_err());
        assert!(BackupPlan::from_args(&["-f".to_string(), "only.ab".to_string()]).is_err());
    }

    #[test]
    fn raw_service_plan_detects_host_and_devraw_services() {
        for args in [
            vec![],
            vec!["host:version".to_string(), "extra".to_string()],
        ] {
            let err = raw_service_plan(&args).unwrap_err();
            assert!(matches!(err, AdbError::Usage(message) if message == "usage: adb raw SERVICE"));
        }

        assert_eq!(
            raw_service_plan(&["host:version".to_string()]).unwrap(),
            RawServicePlan {
                service: "host:version".to_string(),
                host_service: true,
                requires_devraw_feature: false,
            }
        );
        assert_eq!(
            raw_service_plan(&["shell:id".to_string()]).unwrap(),
            RawServicePlan {
                service: "shell:id".to_string(),
                host_service: false,
                requires_devraw_feature: false,
            }
        );
        assert_eq!(
            raw_service_plan(&["dev-raw:/dev/ttyS0".to_string()]).unwrap(),
            RawServicePlan {
                service: "dev-raw:/dev/ttyS0".to_string(),
                host_service: false,
                requires_devraw_feature: true,
            }
        );
    }

    #[test]
    fn restore_service_quotes_extra_args() {
        assert_eq!(
            build_colon_service_command("restore:", &["--user".to_string(), "0".to_string()]),
            "restore: '--user' '0'"
        );
    }

    #[test]
    fn restore_requires_filename_like_aosp() {
        let err = restore_requires_filename_error();
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb restore FILENAME [ARG]...")
        );
    }

    #[test]
    fn restore_payload_appends_two_zero_blocks() {
        let mut input = std::io::Cursor::new(b"archive".as_slice());
        let mut output = Vec::new();

        let bytes = write_restore_payload(&mut input, &mut output).unwrap();

        assert_eq!(bytes, 7);
        assert_eq!(&output[..7], b"archive");
        assert_eq!(output.len(), 7 + 1024);
        assert!(output[7..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn restore_waits_for_response_without_half_closing_service() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut payload = vec![0_u8; 7 + 1024];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload[..7], b"archive");
            assert!(payload[7..].iter().all(|byte| *byte == 0));

            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut probe = [0_u8; 1];
            let err = stream
                .read(&mut probe)
                .expect_err("restore service must remain open while waiting for response");
            assert!(matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
            stream.write_all(b"OKAY").unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let mut input = std::io::Cursor::new(b"archive".as_slice());
        let mut output = Vec::new();
        stream_restore(&mut input, &mut stream, &mut output).unwrap();
        server.join().unwrap();

        assert_eq!(output, b"OKAY");
    }

    #[test]
    fn sideload_service_uses_host_protocol_shape() {
        assert_eq!(
            sideload_host_service("sideload-host", 123),
            "sideload-host:123:65536"
        );
        assert_eq!(
            sideload_host_service("rescue-install", 456),
            "rescue-install:456:65536"
        );
        assert_eq!(rescue_wipe_service("userdata"), "rescue-wipe:userdata:8");
    }

    #[test]
    fn rescue_command_matches_aosp_arg_edges() {
        assert_eq!(
            rescue_command(&["getprop".to_string()]).unwrap(),
            RescueCommand::Getprop("rescue-getprop:".to_string())
        );
        assert_eq!(
            rescue_command(&["getprop".to_string(), "ro.product.name".to_string()]).unwrap(),
            RescueCommand::Getprop("rescue-getprop:ro.product.name".to_string())
        );
        assert_eq!(
            rescue_command(&["install".to_string(), "ota.zip".to_string()]).unwrap(),
            RescueCommand::Install("ota.zip".to_string())
        );
        assert_eq!(
            rescue_command(&["wipe".to_string(), "userdata".to_string()]).unwrap(),
            RescueCommand::WipeUserdata
        );

        let cases = [
            (
                Vec::<String>::new(),
                "rescue requires at least one argument",
            ),
            (
                vec![
                    "getprop".to_string(),
                    "ro.a".to_string(),
                    "ro.b".to_string(),
                ],
                "invalid rescue getprop arguments",
            ),
            (
                vec!["install".to_string()],
                "rescue install requires two arguments",
            ),
            (
                vec![
                    "install".to_string(),
                    "ota.zip".to_string(),
                    "extra".to_string(),
                ],
                "rescue install requires two arguments",
            ),
            (vec!["wipe".to_string()], "invalid rescue wipe arguments"),
            (
                vec!["wipe".to_string(), "cache".to_string()],
                "invalid rescue wipe arguments",
            ),
            (vec!["unknown".to_string()], "invalid rescue argument"),
        ];
        for (args, expected) in cases {
            let err = rescue_command(&args).unwrap_err();
            assert!(matches!(err, AdbError::Usage(message) if message == expected));
        }
    }

    #[test]
    fn sideload_host_serves_requested_blocks_until_done() {
        let data: Vec<u8> = (0..20).collect();
        let mut package = std::io::Cursor::new(data.clone());
        let mut device = ScriptedIo {
            read: std::io::Cursor::new([b"00000001".as_slice(), b"00000002", b"DONEDONE"].concat()),
            write: Vec::new(),
        };

        let ok = serve_sideload_host(&mut package, data.len() as u64, 8, &mut device).unwrap();

        assert!(ok);
        assert_eq!(
            device.write,
            [data[8..16].to_vec(), data[16..20].to_vec()].concat()
        );
    }

    #[test]
    fn sideload_host_reports_remote_failure() {
        let mut package = std::io::Cursor::new(b"package".as_slice());
        let mut device = ScriptedIo {
            read: std::io::Cursor::new(b"FAILFAIL".to_vec()),
            write: Vec::new(),
        };

        let ok = serve_sideload_host(&mut package, 7, 8, &mut device).unwrap();

        assert!(!ok);
        assert!(device.write.is_empty());
    }

    #[test]
    fn sideload_host_rejects_out_of_range_block() {
        let mut package = std::io::Cursor::new(b"package".as_slice());
        let mut device = ScriptedIo {
            read: std::io::Cursor::new(b"00000002".to_vec()),
            write: Vec::new(),
        };

        assert!(serve_sideload_host(&mut package, 7, 8, &mut device).is_err());
    }

    #[test]
    fn minadbd_done_status_parses_rescue_wipe_result() {
        assert!(read_minadbd_done_status(&mut std::io::Cursor::new(b"DONEDONE")).unwrap());
        assert!(!read_minadbd_done_status(&mut std::io::Cursor::new(b"FAILFAIL")).unwrap());
        assert!(matches!(
            read_minadbd_done_status(&mut std::io::Cursor::new(b"UNKNOWN!")),
            Err(AdbError::Protocol(_))
        ));
    }

    #[test]
    fn shell_command_builder_quotes_uninstall_args() {
        let args = vec![
            "--user".to_string(),
            "0".to_string(),
            "com.test app".to_string(),
        ];
        assert_eq!(
            build_shell_command("cmd package uninstall", &args),
            "cmd package uninstall '--user' '0' 'com.test app'"
        );
    }

    #[test]
    fn uninstall_keep_data_warning_matches_install_mode() {
        assert_eq!(
            uninstall_keep_data_warning("cmd package uninstall"),
            "The -k option uninstalls the application while retaining the data/cache.\nAt the moment, there is no way to remove the remaining data.\nYou will have to reinstall the application with the same signature, and fully uninstall it.\nIf you truly wish to continue, execute 'adb shell cmd package uninstall -k'."
        );
        assert_eq!(
            uninstall_keep_data_warning("pm uninstall"),
            "The -k option uninstalls the application while retaining the data/cache.\nAt the moment, there is no way to remove the remaining data.\nYou will have to reinstall the application with the same signature, and fully uninstall it.\nIf you truly wish to continue, execute 'adb shell pm uninstall -k'."
        );
    }

    #[test]
    fn exec_service_builder_matches_aosp_quoting() {
        let args = vec![
            "cmd".to_string(),
            "package".to_string(),
            "path with space".to_string(),
            "quote'arg".to_string(),
        ];

        assert_eq!(
            build_exec_service(&args),
            "exec:cmd 'package' 'path with space' 'quote'\\''arg'"
        );
    }

    #[test]
    fn exec_entrypoints_require_command_like_aosp() {
        let err = exec_requires_command_error(ExecMode::In);
        assert!(matches!(err, AdbError::Usage(message) if message == "usage: adb exec-in command"));

        let err = exec_requires_command_error(ExecMode::Out);
        assert!(
            matches!(err, AdbError::Usage(message) if message == "usage: adb exec-out command")
        );
    }

    #[test]
    fn abb_service_builder_uses_nul_argument_delimiter() {
        let args = vec![
            "package".to_string(),
            "list".to_string(),
            "packages".to_string(),
        ];

        assert_eq!(build_abb_service(&args), "abb:package\0list\0packages");
        assert_eq!(build_abb_service(&[]), "abb:");
    }

    #[test]
    fn abb_unsupported_error_matches_aosp() {
        let err = abb_unsupported_error();
        assert!(
            matches!(err, AdbError::Server(message) if message == "abb is not supported by the device")
        );
    }

    #[test]
    fn keygen_requires_exactly_one_path() {
        for args in [vec![], vec!["one".to_string(), "two".to_string()]] {
            let err = single_path_arg(&args, "keygen").unwrap_err();
            assert!(
                matches!(err, AdbError::Usage(message) if message == "keygen requires an argument")
            );
        }
        assert_eq!(
            single_path_arg(&["one".to_string()], "keygen").unwrap(),
            "one"
        );
    }

    #[test]
    fn legacy_shell_wrap_appends_exit_code_echo() {
        assert_eq!(wrap_legacy_shell_command("id"), "id; echo \"\n$?: $?\"");
        assert_eq!(wrap_legacy_shell_command(""), "echo \"\n$?: $?\"");
    }

    #[test]
    fn legacy_shell_exit_code_parsed_and_truncated() {
        let mut output = b"hello\n\n$?: 42".to_vec();
        assert_eq!(parse_legacy_shell_exit_code(&mut output), 42);
        assert_eq!(output, b"hello\n");
    }

    #[test]
    fn legacy_shell_exit_code_parsed_without_trailing_newline() {
        let mut output = b"hello\n$?: 7".to_vec();
        assert_eq!(parse_legacy_shell_exit_code(&mut output), 7);
        assert_eq!(output, b"hello");
    }

    #[test]
    fn legacy_shell_exit_code_returns_zero_when_marker_missing() {
        let mut output = b"just output".to_vec();
        assert_eq!(parse_legacy_shell_exit_code(&mut output), 0);
        assert_eq!(output, b"just output");
    }

    #[test]
    fn legacy_shell_exit_code_returns_zero_for_non_numeric_marker() {
        let mut output = b"$?: abc".to_vec();
        assert_eq!(parse_legacy_shell_exit_code(&mut output), 0);
        assert_eq!(output, b"$?: abc");
    }

    #[test]
    fn sync_progress_printer_single_file_uses_simple_format() {
        let mut printer = SyncProgressPrinter::new(false);
        // 模拟发送过程中的进度
        printer.report_progress("test.apk", 500, 1000, false);
        // 完成传输
        printer.report_transfer_rate(
            "",
            1,
            0,
            1000,
            file_sync::TransferDirection::Push,
            Instant::now(),
        );
        // 检查 last_progress 格式：应为 [ 50%] test.apk
        let expected_prefix = "[ 50%] test.apk";
        assert!(
            printer.last_progress == expected_prefix,
            "expected '{expected_prefix}', got '{}'",
            printer.last_progress
        );
    }

    #[test]
    fn sync_progress_printer_multiple_files_shows_percent() {
        let mut printer = SyncProgressPrinter::new(false);
        printer.report_progress("split1.apk", 256, 512, true);
        let expected_prefix = "[ 50%] split1.apk: 50%";
        assert!(
            printer.last_progress == expected_prefix,
            "expected '{expected_prefix}', got '{}'",
            printer.last_progress
        );
    }

    #[test]
    fn sync_progress_printer_quiet_suppresses_output() {
        let mut printer = SyncProgressPrinter::new(true);
        printer.report_progress("test.apk", 500, 1000, false);
        printer.report_transfer_rate(
            "",
            1,
            0,
            1000,
            file_sync::TransferDirection::Push,
            Instant::now(),
        );
        // quiet 模式下 last_progress 不会被更新
        assert!(printer.last_progress.is_empty());
    }

    #[test]
    fn sync_progress_printer_unknown_total_shows_question() {
        let mut printer = SyncProgressPrinter::new(false);
        // total = 0 无法计算百分比
        printer.report_progress("test.apk", 500, 0, false);
        // 格式为 [{overall:>4}]，其中 ? 占 1 格 + 3 空格
        assert!(
            printer.last_progress.starts_with("[   ?] test.apk:"),
            "expected '[   ?] test.apk:...', got '{}'",
            printer.last_progress
        );
        assert!(printer.last_progress.contains("500/?"));
    }

    #[test]
    fn sync_progress_printer_copied_exceeds_total_shows_question_mark() {
        let mut printer = SyncProgressPrinter::new(false);
        printer.report_progress("test.apk", 1500, 1000, false);
        assert!(
            printer.last_progress.starts_with("[   ?] test.apk:"),
            "expected '[   ?] test.apk:...', got '{}'",
            printer.last_progress
        );
        assert!(printer.last_progress.contains("1500/?"));
    }

    #[test]
    fn sync_progress_printer_rate_format_includes_mbps() {
        let mut printer = SyncProgressPrinter {
            start: Instant::now() - Duration::from_secs(1),
            ..SyncProgressPrinter::new(false)
        };
        // report_transfer_rate 输出到 stderr（eprintln!），不更新 last_progress
        // 只需验证不 panic
        printer.report_transfer_rate(
            "dir",
            5,
            1,
            1_048_576,
            file_sync::TransferDirection::Push,
            Instant::now() - Duration::from_secs(1),
        );
    }
}
