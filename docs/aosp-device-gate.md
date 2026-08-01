# AOSP 真机差分门禁

`scripts/run-aosp-device-gate.ps1` 直接加载本机 AOSP `packages/modules/adb/test_device.py`，用于验证当前 Windows 单文件 `adb.exe` 和本项目 server。适配层只补充 AOSP 构建环境原本生成的 Python device wrapper 与 `adb_host.proto` 描述，不复制或改写官方测试方法。

## 前置条件

- AOSP 源码默认位于 `\\wsl.localhost\Debian\mnt\wsl\PhysicalDrive5\Android\aosp\packages\modules\adb`，其他位置通过 `-AospAdbDir` 指定。
- Windows Python 已安装 `google.protobuf`。
- 5037 端口运行待测 server，`-Adb` 指向与该 server 相同构建的客户端；默认使用 SDK `platform-tools\adb.exe`。
- 指定设备当前状态必须为 `device`，并且运行前全局 forward 与该设备 reverse 规则必须为空。
- 官方 `test_forward_old_protocol` 固定连接 `localhost:5037`，因此门禁不接受其他 server 端口。

## 默认安全门禁

```powershell
./scripts/run-aosp-device-gate.ps1 -Serial 10AE9X3HES001TF
```

默认测试只执行可逆 host 工作流：适用时执行 `AbbTest`，并执行 `ForwardReverseTest`、稳定的 shell/shell-v2/参数转义方法、tracker protobuf text/binary 和限时 JDWP snapshot。缺少 `abb` feature 时会明确跳过 `AbbTest`；多设备环境会等待设备列表首个 active serial 连续稳定，再让每个 `DevicesListing` 方法在独立 Python 进程中执行官方 tracker 首设备断言。单个方法超过 45 秒时，适配器会终止完整 Python/adb 子进程树，避免官方测试在 tracker 断言失败后因 `Popen` context manager 等待长驻子进程而永久挂起；超时仍作为门禁失败，不会改写或跳过官方断言。若指定设备当前存在 JDWP process，门禁要求裸 `jdwp` 与 `track-jdwp` service 都输出相同的数字 PID；`track-jdwp` 按官方协议解析 `hex4 + payload` frame。若没有活动进程则明确跳过 tracker snapshot。部分设备上的 `jdwp` 即使输出完成也不会主动 EOF，门禁会在两秒后终止本轮只读客户端，这一行为已用官方 37.0.0 native server 对照复现。

2026-07-20 在 API 34 OnePlus 5 `c57e1c6a` 上启动 debuggable `com.limelight.debug` 后，默认安全门禁 20/20 和 tracker proto text/binary 通过，`jdwp` 与 `track-jdwp` 都报告 PID `27990`；另通过临时 `forward tcp:0 jdwp:27990` 完成原始 `JDWP-Handshake` 往返并清理 forward 规则。

脚本会把指定 `adb.exe` 复制到独立临时目录，确保 AOSP 子进程不会命中其他 PATH 条目；结束时恢复 `PATH`、`PYTHONPATH`、`ADB_SERVER_SOCKET`、`ANDROID_SERIAL` 并清理本轮 forward/reverse 规则。

## 文件传输门禁

```powershell
./scripts/run-aosp-device-gate.ps1 -Serial 10AE9X3HES001TF -FileOperations
```

该模式会在 `/data/local/tmp` 创建并清理 AOSP 测试文件，覆盖单文件与 32 文件目录 push/pull、空目录和 Unicode 路径。uncompressed 总是执行；Brotli、LZ4、Zstd 按设备声明的 `sendrecv_v2_*` feature 选择。即使测试中途失败，脚本也会 best-effort 删除固定的 `adb_test_file`、`adb_test_dir` 和 `adb-test-*` 路径。

## 条件测试

- `-IncludeServerStatus` 运行官方固定行号断言；若启动环境强制 mDNS backend 并额外输出 `mdns_backend_forced`，应在清理该环境后运行。
- `-Extended` 运行 `SocketTest.test_socket_flush` 与 `FramebufferTest.test_framebuffer`。当前 Rust standalone 的 socket flush 已在 API 34/36 通过；framebuffer 在这两台设备上仍返回 0 字节，但官方 37.0.0 server 对同一设备也返回 `Bad file descriptor` 和 0 字节，因此 framebuffer 只用于设备能力诊断，不属于默认硬门禁。

门禁失败时必须先判断官方二进制在同一设备、驱动、server 环境下是否同样失败；只有 Rust 独有且可复现的差异才进入兼容修复。
