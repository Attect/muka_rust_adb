use std::path::Path;
use std::process::{Command, Output};

struct CliCase {
    name: &'static str,
    args: &'static [&'static str],
}

const LOCAL_CLI_CASES: &[CliCase] = &[
    CliCase {
        name: "未知短选项作为命令",
        args: &["-h"],
    },
    CliCase {
        name: "裸双横线作为命令",
        args: &["--"],
    },
    CliCase {
        name: "未知命令",
        args: &["not-a-command"],
    },
    CliCase {
        name: "-H 缺少参数",
        args: &["-H"],
    },
    CliCase {
        name: "-P 缺少参数",
        args: &["-P"],
    },
    CliCase {
        name: "-L 缺少参数",
        args: &["-L"],
    },
    CliCase {
        name: "-s 缺少参数",
        args: &["-s"],
    },
    CliCase {
        name: "-t 缺少参数",
        args: &["-t"],
    },
    CliCase {
        name: "--one-device 缺少参数",
        args: &["--one-device"],
    },
    CliCase {
        name: "本地命令仍校验 --one-device 限制",
        args: &["--one-device", "serial", "version"],
    },
    CliCase {
        name: "本地命令仍校验 -L 与 -P 互斥",
        args: &["-L", "tcp:12345", "-P", "12346", "version"],
    },
    CliCase {
        name: "帮助命令仍校验 -L 与 -H 互斥",
        args: &["-L", "unsupported:socket", "-H", "localhost", "help"],
    },
    CliCase {
        name: "本地命令仍校验零 server port",
        args: &["-P", "0", "version"],
    },
    CliCase {
        name: "版本别名仍校验非法 server port",
        args: &["-P", "not-a-port", "--version"],
    },
    CliCase {
        name: "devices 非法参数",
        args: &["devices", "--bad"],
    },
    CliCase {
        name: "track-devices 非法参数",
        args: &["track-devices", "--bad"],
    },
    CliCase {
        name: "connect 缺少参数",
        args: &["connect"],
    },
    CliCase {
        name: "connect 参数过多",
        args: &["connect", "host", "extra"],
    },
    CliCase {
        name: "disconnect 参数过多",
        args: &["disconnect", "host", "extra"],
    },
    CliCase {
        name: "pair 缺少参数",
        args: &["pair"],
    },
    CliCase {
        name: "pair 参数过多",
        args: &["pair", "host", "code", "extra"],
    },
    CliCase {
        name: "forward 缺少参数",
        args: &["forward"],
    },
    CliCase {
        name: "forward list 参数过多",
        args: &["forward", "--list", "extra"],
    },
    CliCase {
        name: "forward remove 缺少端点",
        args: &["forward", "--remove"],
    },
    CliCase {
        name: "forward remove-all 参数过多",
        args: &["forward", "--remove-all", "extra"],
    },
    CliCase {
        name: "forward no-rebind 参数不足",
        args: &["forward", "--no-rebind", "tcp:1"],
    },
    CliCase {
        name: "reverse 缺少参数",
        args: &["reverse"],
    },
    CliCase {
        name: "mdns 缺少参数",
        args: &["mdns"],
    },
    CliCase {
        name: "mdns 未知命令",
        args: &["mdns", "bad"],
    },
    CliCase {
        name: "mdns 参数过多",
        args: &["mdns", "check", "extra"],
    },
    CliCase {
        name: "bugreport 参数过多",
        args: &["bugreport", "one", "two"],
    },
    CliCase {
        name: "exec-in 缺少命令",
        args: &["exec-in"],
    },
    CliCase {
        name: "exec-out 缺少命令",
        args: &["exec-out"],
    },
    CliCase {
        name: "restore 缺少文件",
        args: &["restore"],
    },
    CliCase {
        name: "rescue 缺少命令",
        args: &["rescue"],
    },
    CliCase {
        name: "rescue getprop 参数过多",
        args: &["rescue", "getprop", "prop", "extra"],
    },
    CliCase {
        name: "rescue install 缺少文件",
        args: &["rescue", "install"],
    },
    CliCase {
        name: "rescue wipe 参数非法",
        args: &["rescue", "wipe", "cache"],
    },
    CliCase {
        name: "keygen 缺少文件",
        args: &["keygen"],
    },
    CliCase {
        name: "keygen 参数过多",
        args: &["keygen", "one", "two"],
    },
    CliCase {
        name: "pubkey 缺少文件",
        args: &["pubkey"],
    },
    CliCase {
        name: "pubkey 参数过多",
        args: &["pubkey", "one", "two"],
    },
    CliCase {
        name: "install 缺少参数",
        args: &["install"],
    },
    CliCase {
        name: "install-multiple 缺少参数",
        args: &["install-multiple"],
    },
    CliCase {
        name: "install-multi-package 缺少参数",
        args: &["install-multi-package"],
    },
    CliCase {
        name: "install-multi-package 先校验 APK/APEX 类型",
        args: &["install-multi-package", "not-a-package.txt"],
    },
    CliCase {
        name: "uninstall 缺少参数",
        args: &["uninstall"],
    },
    CliCase {
        name: "ls 缺少参数",
        args: &["ls"],
    },
    CliCase {
        name: "push 缺少参数",
        args: &["push"],
    },
    CliCase {
        name: "pull 缺少参数",
        args: &["pull"],
    },
    CliCase {
        name: "raw 缺少 service",
        args: &["raw"],
    },
    CliCase {
        name: "raw 参数过多",
        args: &["raw", "shell:id", "extra"],
    },
    CliCase {
        name: "tcpip 缺少端口",
        args: &["tcpip"],
    },
    CliCase {
        name: "tcpip 非法端口",
        args: &["tcpip", "0"],
    },
    CliCase {
        name: "tcpip 参数过多",
        args: &["tcpip", "5555", "extra"],
    },
    CliCase {
        name: "reconnect 未知子命令",
        args: &["reconnect", "bad"],
    },
    CliCase {
        name: "reconnect 参数过多",
        args: &["reconnect", "device", "extra"],
    },
    CliCase {
        name: "sideload 缺少参数",
        args: &["sideload"],
    },
    CliCase {
        name: "forward no-rebind 参数过多",
        args: &["forward", "--no-rebind", "tcp:1", "tcp:2", "extra"],
    },
    CliCase {
        name: "reverse list 参数过多",
        args: &["reverse", "--list", "extra"],
    },
    CliCase {
        name: "reverse remove 缺少端点",
        args: &["reverse", "--remove"],
    },
    CliCase {
        name: "reverse remove-all 参数过多",
        args: &["reverse", "--remove-all", "extra"],
    },
    CliCase {
        name: "reverse no-rebind 参数不足",
        args: &["reverse", "--no-rebind", "tcp:1"],
    },
];

#[test]
fn local_cli_errors_match_official_adb() {
    let Some(official) = std::env::var_os("ADB_OFFICIAL_BINARY") else {
        eprintln!("未设置 ADB_OFFICIAL_BINARY，跳过官方 adb CLI 差分测试");
        return;
    };
    let rust_adb = Path::new(env!("CARGO_BIN_EXE_adb"));
    let official = Path::new(&official);
    assert!(
        official.is_file(),
        "官方 adb 不存在: {}",
        official.display()
    );

    for case in LOCAL_CLI_CASES {
        let rust = run_case(rust_adb, case.args);
        let aosp = run_case(official, case.args);
        assert_case_matches(case, rust_adb, &rust, official, &aosp);
    }
}

#[test]
fn help_body_matches_official_adb() {
    let Some(official) = std::env::var_os("ADB_OFFICIAL_BINARY") else {
        eprintln!("未设置 ADB_OFFICIAL_BINARY，跳过官方 adb help 差分测试");
        return;
    };
    let rust_adb = Path::new(env!("CARGO_BIN_EXE_adb"));
    let official = Path::new(&official);

    for alias in ["help", "--help", "/?"] {
        let rust = run_case(rust_adb, &[alias]);
        let aosp = run_case(official, &[alias]);
        assert_eq!(rust.status.code(), aosp.status.code(), "alias={alias}");
        assert_eq!(rust.stderr, aosp.stderr, "alias={alias}");
        assert_eq!(
            help_body(&rust.stdout),
            help_body(&aosp.stdout),
            "alias={alias}"
        );
    }
}

#[test]
fn server_port_environment_precedence_matches_official_adb() {
    let official =
        std::env::var_os("ADB_OFFICIAL_BINARY").map(|path| Path::new(&path).to_path_buf());
    let Some(official) = official else {
        eprintln!("未设置 ADB_OFFICIAL_BINARY，跳过 server port 环境差分测试");
        return;
    };
    let rust_adb = Path::new(env!("CARGO_BIN_EXE_adb"));
    let case = CliCase {
        name: "server port 环境变量优先级",
        args: &["version"],
    };

    let invalid_port_rust =
        run_case_with_env(rust_adb, case.args, &[("ANDROID_ADB_SERVER_PORT", "0")]);
    let invalid_port_official =
        run_case_with_env(&official, case.args, &[("ANDROID_ADB_SERVER_PORT", "0")]);
    assert_eq!(
        invalid_port_rust.status.code(),
        invalid_port_official.status.code(),
        "{} 退出码不一致",
        case.name
    );
    assert_eq!(
        normalize_output(&invalid_port_rust.stderr, rust_adb),
        normalize_output(&invalid_port_official.stderr, &official),
        "{} 错误输出不一致",
        case.name
    );

    let socket_precedence_rust = run_case_with_env(
        rust_adb,
        case.args,
        &[
            ("ADB_SERVER_SOCKET", "invalid:socket"),
            ("ANDROID_ADB_SERVER_PORT", "0"),
        ],
    );
    let socket_precedence_official = run_case_with_env(
        &official,
        case.args,
        &[
            ("ADB_SERVER_SOCKET", "invalid:socket"),
            ("ANDROID_ADB_SERVER_PORT", "0"),
        ],
    );
    assert_eq!(
        socket_precedence_rust.status.code(),
        socket_precedence_official.status.code(),
        "ADB_SERVER_SOCKET 优先级退出码不一致"
    );
    assert_eq!(
        normalize_output(&socket_precedence_rust.stderr, rust_adb),
        normalize_output(&socket_precedence_official.stderr, &official),
        "ADB_SERVER_SOCKET 优先级错误输出不一致"
    );
}

#[test]
fn adb_trace_startup_diagnostics_match_official_boundaries() {
    let Some(official) = std::env::var_os("ADB_OFFICIAL_BINARY") else {
        eprintln!("未设置 ADB_OFFICIAL_BINARY，跳过 ADB_TRACE 启动差分测试");
        return;
    };
    let rust_adb = Path::new(env!("CARGO_BIN_EXE_adb"));
    let official = Path::new(&official);
    for setting in ["1", "all", "adb", "adb,sockets"] {
        let rust = run_case_with_env(rust_adb, &["version"], &[("ADB_TRACE", setting)]);
        let aosp = run_case_with_env(official, &["version"], &[("ADB_TRACE", setting)]);
        assert_eq!(
            rust.status.code(),
            aosp.status.code(),
            "ADB_TRACE={setting}"
        );
        let rust_stderr = normalize_output(&rust.stderr, rust_adb);
        let aosp_stderr = normalize_output(&aosp.stderr, official);
        assert!(
            rust_stderr.contains("Using server socket:"),
            "Rust ADB_TRACE={setting} 缺少 socket 启动诊断: {rust_stderr:?}"
        );
        assert!(
            aosp_stderr.contains("Using server socket:"),
            "官方 ADB_TRACE={setting} 缺少可比较的 socket 启动诊断: {aosp_stderr:?}"
        );
    }

    for setting in ["sockets", "mdns"] {
        let rust = run_case_with_env(rust_adb, &["version"], &[("ADB_TRACE", setting)]);
        let aosp = run_case_with_env(official, &["version"], &[("ADB_TRACE", setting)]);
        assert_eq!(
            rust.status.code(),
            aosp.status.code(),
            "ADB_TRACE={setting}"
        );
        assert!(
            !normalize_output(&rust.stderr, rust_adb).contains("Using server socket:"),
            "Rust ADB_TRACE={setting} 意外输出启动诊断"
        );
        assert!(
            !normalize_output(&aosp.stderr, official).contains("Using server socket:"),
            "官方 ADB_TRACE={setting} 意外输出启动诊断"
        );
    }

    let rust = run_case_with_env(rust_adb, &["version"], &[("ADB_TRACE", "unknown")]);
    let aosp = run_case_with_env(official, &["version"], &[("ADB_TRACE", "unknown")]);
    assert_eq!(rust.status.code(), aosp.status.code());
    assert!(normalize_output(&rust.stderr, rust_adb).contains("Unknown trace flag: unknown"));
    assert!(normalize_output(&aosp.stderr, official).contains("Unknown trace flag: unknown"));
}

fn run_case(executable: &Path, args: &[&str]) -> Output {
    run_case_with_env(executable, args, &[])
}

fn run_case_with_env(executable: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(executable);
    command
        .args(args)
        .env_remove("ADB_SERVER_SOCKET")
        .env_remove("ANDROID_ADB_SERVER_ADDRESS")
        .env_remove("ANDROID_ADB_SERVER_PORT")
        .env_remove("ANDROID_SERIAL")
        .env_remove("ADB_TRACE");
    for (name, value) in envs {
        command.env(name, value);
    }
    command
        .output()
        .unwrap_or_else(|err| panic!("无法运行 {}: {err}", executable.display()))
}

fn assert_case_matches(
    case: &CliCase,
    rust_path: &Path,
    rust: &Output,
    official_path: &Path,
    official: &Output,
) {
    let rust_stdout = normalize_output(&rust.stdout, rust_path);
    let rust_stderr = normalize_output(&rust.stderr, rust_path);
    let official_stdout = normalize_output(&official.stdout, official_path);
    let official_stderr = normalize_output(&official.stderr, official_path);

    assert_eq!(
        rust.status.code(),
        official.status.code(),
        "{} {:?} 退出码不一致\nRust stderr: {rust_stderr:?}\nAOSP stderr: {official_stderr:?}",
        case.name,
        case.args
    );
    assert_eq!(
        rust_stdout, official_stdout,
        "{} {:?} stdout 不一致",
        case.name, case.args
    );
    assert_eq!(
        rust_stderr, official_stderr,
        "{} {:?} stderr 不一致",
        case.name, case.args
    );
}

fn normalize_output(bytes: &[u8], executable: &Path) -> String {
    let program = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("adb");
    String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .lines()
        .map(|line| {
            line.strip_prefix(program)
                .and_then(|line| line.strip_prefix(':'))
                .map_or_else(|| line.to_string(), |line| format!("adb:{line}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn help_body(bytes: &[u8]) -> String {
    let text = std::str::from_utf8(bytes).expect("help 输出必须是 UTF-8");
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let index = text
        .find("global options:\n")
        .expect("help 输出缺少 global options 分区");
    text[index..].to_string()
}
