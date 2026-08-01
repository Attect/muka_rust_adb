# Muka Rust ADB

可替代官方实现的 Rust 版 Android Debug Bridge（ADB）主机端程序。编译产出单一 `adb` 可执行文件，wire format、smart-socket 协议、CLI 参数解析与错误文案均对齐 AOSP `packages/modules/adb`。

- 项目网站：https://muka.cool/rust_adb
- 代码仓库：https://github.com/Attect/muka_rust_adb
- 许可证：MIT

## 核心特性

- **无缝替换官方 `adb`**：smart-socket 长度前缀协议、`OKAY`/`FAIL` 状态解析、apacket 头部编解码（magic 校验、checksum 兼容）均按 AOSP 实现；已连接官方 adb server 时可直接复用其设备能力，否则自动启动内置 server。
- **CLI 行为对齐 AOSP**：全局参数、usage 与错误文案、错误退出码均与官方一致；错误前缀使用当前可执行文件名（Windows `adb.exe:`、Unix `adb:`）。
- **单文件发行**：libusb、AWS-LC、Brotli/LZ4/Zstd 等第三方 C 依赖全部以 vendored 源码静态编入，不依赖 `AdbWinApi.dll`、`libusb-1.0.dll`、`VCRUNTIME140.dll` 等私有/运行库。
- **跨平台**：Windows（x86_64 MSVC）、Linux（musl/gnu）、macOS；平台相关逻辑以 `#[cfg(...)]` 隔离。

## 功能概览

### 设备连接与认证

- TCP transport：`host:connect` CNXN/AUTH 握手，`A_STLS` TLS 1.3 升级。
- USB transport：vendored libusb 枚举注册，支持插拔重扫、`attach`/`detach` 生命周期、Windows 睡眠恢复后重扫。
- Emulator 自动扫描：本机 `5555..5585` 奇数端口，`ADB_EMU=0` 可禁用。
- mDNS 发现：`mdns check/services`、known-host 过滤、断线退避自动恢复。
- 认证：自动生成 `~/.android/adbkey`、`keygen`/`pubkey`、`ADB_VENDOR_KEYS` 扫描、RSA TOKEN 签名。
- 无线配对 `pair`：TLS 1.3 双向证书、SPAKE2、HKDF-SHA256、AES-128-GCM PeerInfo 交换，写入 `adb_known_hosts.pb`。

### Shell 与进程服务

- `shell`：shell v2 stdout/stderr/exit code 解帧，交互模式支持 pty/raw、stdin packet、窗口尺寸变化和 `-e/-n/-T/-t/-x` 选项，旧设备回退 legacy。
- `exec-in`/`exec-out`（`exec:` service）、`abb`（`abb:` service）。
- `logcat`、`bugreport`（含 `--stream`）、`jdwp`/`track-jdwp`、`track-app`。

### 文件传输（`sync:` v1/v2）

- `ls`、`push`、`pull`、`sync [PARTITION]`，按设备 feature 自动选择 v2 `LST2/LIS2/SND2/RCV2` 或 v1 协议。
- 目录递归、空目录保留、符号链接处理、目录 mode/mtime best-effort 恢复。
- `push --sync/-n/-q`、`pull -a/-q`、`sync -l/-n/-q`、`ANDROID_PRODUCT_OUT` 分区映射。
- Brotli/LZ4/Zstd 压缩（`-z any|none|brotli|lz4|zstd`）。

### 应用安装

- `install`（streamed/legacy）、`install-multiple`、`install-multi-package`、`uninstall`；包管理 service 按官方优先级选择 `abb_exec:package` / `exec:cmd package` / `exec:pm`。
- fastdeploy：二进制 AndroidManifest 解析、`APKDump` protobuf、ZIP central-directory MD5 边界 `FASTDEPLOY` patch、内嵌 deployagent 三种更新策略。
- incremental（`--incremental`）：`.idsig` 解析、`install-incremental`、跨平台 `inc-server` 子进程、fs-verity 块按需传输、优先级块与 LZ4 压缩；不满足条件时按官方规则降级。

### 转发与网络

- `forward`：host `tcp:`/Unix `localfilesystem:`/Linux `localabstract:`/`vsock:` 监听，`--list/--remove/--remove-all/--no-rebind`，`tcp:0` 动态端口回显。
- `reverse`：设备端 `reverse:*` service，host 侧 per-transport allowlist 连接 TCP/Unix/vsock 目标。

### 设备控制与其他

- `reboot [TARGET]`、`reboot-bootloader`、`reboot-fastboot`、`tcpip`、`usb`、`root`/`unroot`、`remount`、`disable-verity`/`enable-verity`。
- `sideload`、`rescue getprop|install|wipe`、`backup`/`restore`、`emu`。
- `devices [-l]`、`track-devices [-l|--proto-text|--proto-binary]`、`wait-for-*`、`features`/`host-features`、`get-state`/`get-serialno`/`get-devpath`/`transport-id`、`connect`/`disconnect`、`reconnect`、`server-status`。

### 内置 Server

- host service：`host:version`、`host:devices[-l]`、`host:track-devices[-proto-*]`、`host:wait-for-*`、`host:connect/disconnect`、`host:list-forward`、`host:server-status`（含 keystore/known_hosts 路径）、`host:mdns:*` 等。
- 启动方式：`start-server`、`kill-server`、`server nodaemon`、`fork-server server --reply-fd FD`（含官方 `OK\n` ACK）。
- 设备选择器：`-s SERIAL`、`-t ID`、`-d`、`-e`、`--one-device`、`ANDROID_SERIAL`。
- server socket spec：Windows `tcp:`；Unix 额外支持 `local:`/`localfilesystem:`/`acceptfd:`；Linux 额外支持 `localabstract:`/`vsock:`。

## 构建

开发调试：

```bash
cargo build
```

单文件发行（发布会剥离调试符号并检查动态依赖）：

```powershell
# Windows（x86_64 MSVC，静态 CRT）
./scripts/build-standalone.ps1
# 产出 target/dist/x86_64-pc-windows-msvc/adb.exe
```

```bash
# Linux（默认 musl 静态）/ macOS
./scripts/build-standalone.sh
# 产出 target/dist/<target>/adb
```

各平台发行约束与依赖检查的详细说明见 [docs/windows-usb.md](docs/windows-usb.md)。

## 使用

命令与官方 `adb` 一致：

```bash
adb start-server
adb devices -l
adb shell echo hello
adb push ./local.txt /sdcard/local.txt
adb pull /sdcard/local.txt .
adb install ./app.apk
adb kill-server
```

常用环境变量：`ADB_SERVER_SOCKET`、`ANDROID_ADB_SERVER_ADDRESS`/`ANDROID_ADB_SERVER_PORT`、`ANDROID_SERIAL`、`ADB_TRACE`、`ADB_VENDOR_KEYS`、`ADB_MDNS_AUTO_CONNECT`、`ADB_BURST_MODE`。

## 验证

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

- 与官方二进制的 CLI 差分验证：设置 `ADB_OFFICIAL_BINARY=<path>` 后运行 `cargo test --test aosp_cli_diff`。
- AOSP 真机门禁：`./scripts/run-aosp-device-gate.ps1 -Serial <SERIAL>`，前置条件与诊断开关见 [docs/aosp-device-gate.md](docs/aosp-device-gate.md)。

## 项目结构

```text
src/            主机端实现（cli / client / server / transport / protocol / sync / auth / pairing / mdns / fastdeploy / incremental / usb ...）
tests/          集成测试与差分验证（含 tests/data 测试数据）
scripts/        单文件发行构建/检查脚本与 AOSP 真机门禁
docs/           协议、路线图、真机门禁、Windows USB 说明
assets/         fastdeploy 内嵌 agent
reference/      少量 AOSP 官方源码副本（仅离线对照，不参与编译）
```

## AOSP 兼容性参照

协议行为以 AOSP `packages/modules/adb` 为准，优先参照：

- `docs/dev/protocol.md`、`docs/dev/services.md`
- `adb.h`、`adb.cpp`
- `client/adb_client.cpp`、`client/commandline.cpp`
- `services.cpp`

本仓库的协议要点整理见 [docs/protocol.md](docs/protocol.md)，功能规划见 [docs/roadmap.md](docs/roadmap.md)。

## 作者

- 作者：Attect
- 项目网站：https://muka.cool/rust_adb
- 本项目使用 AI 实现。
- 许可证：MIT，见 [LICENSE](LICENSE)。
