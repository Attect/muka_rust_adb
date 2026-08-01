# 项目协作约定

本仓库目标是用 Rust 实现可替换官方 `adb` 的 Android Debug Bridge 主机端程序，并逐步补齐官方功能。

## 代码约定

- 源码、测试、文档中的注释和说明使用中文；公开协议名称、命令名、错误 wire format 保持官方英文。
- 优先复用 AOSP `packages/modules/adb/docs/dev` 中记录的协议行为，涉及兼容性时以本机 AOSP 源码为准。
- 本机 AOSP 源码位于 WSL2 `/mnt/wsl/PhysicalDrive5/Android/aosp`；本仓库的 `reference/aosp-adb/` 只保存少量官方源码副本用于离线对照，不参与编译。
- 任何新增功能必须先落到可测试的协议或服务边界，避免把 CLI、server、transport 逻辑耦合在一起。
- 手写代码保持跨平台；平台相关逻辑必须用 `#[cfg(...)]` 隔离。

## 验证约定

- 基础门禁：`cargo fmt --check`、`cargo test`、`cargo clippy --all-targets -- -D warnings`。
- 可用官方二进制时设置 `ADB_OFFICIAL_BINARY=<path>` 并运行 `cargo test --test aosp_cli_diff`，对无需设备的 CLI 边界执行差分验证。
- 改动 smart-socket 或 apacket wire format 时，必须补充单元测试。
- 改动 CLI 行为时，尽量用官方 ADB 文档或 AOSP 源码中的命令行为作参照，并在文档中记录差异。

## 当前阶段边界

- 已建立主机端 CLI、smart-socket client 和最小 server 骨架。
- 当前 server 已实现手动 `host:connect` 的 TCP CNXN/AUTH 初始握手、默认用户 `adbkey` 自动生成、`keygen FILE` 显式密钥生成、`pubkey FILE` 公钥输出、Android `.pub` 编码、RSA TOKEN 签名、`ADB_VENDOR_KEYS` 扫描、registry，以及基于后台读线程和 stream registry 的基础 `A_OPEN/A_WRTE/A_CLSE` 多路复用桥接；CLI 已对 `shell COMMAND` 实现 shell v2 stdout/stderr/exit code 解帧并保留 legacy 回退，交互 `shell` 已接入 `shell,v2,pty/raw:`、stdin packet、`CLOSE_STDIN`、初始窗口尺寸、持续窗口尺寸变化和 `-e/-n/-T/-t/-x` 基础选项，`exec-in`/`exec-out` 已接入 `exec:` service，`abb` 已接入 `abb:` service，并已接入基础 `sync:` v1/v2 `ls`/`push`/`pull`/`sync` 文件传输，支持目录列表、目录递归、空目录保留、v2 `STAT/LIST` 扩展字段解析保存、Unix host push/sync 保留符号链接、pull 跟随远端符号链接、pull 按实际接收字节完成、目录 push best-effort mode/mtime 恢复、`push --sync`、`push -n`、`push -q`、`pull -a`（v2 64 位 mtime 优先）、`pull -q`、`adb sync -l/-n/-q`、`ANDROID_PRODUCT_OUT` 分区映射和 Brotli/LZ4/Zstd 压缩，还已接入 streamed/legacy/fastdeploy `install`、`install-multiple`、`install-multi-package` 和 `uninstall`，其中 streamed/session 包管理子命令会按官方优先使用 `abb_exec:package`；server 已支持基础 host `tcp:<port>` forward 监听、Unix `localfilesystem:<path>` forward、Linux `localabstract:<name>` forward、Linux `vsock:<port>` forward、官方 forward/killforward 参数校验和规则管理、`server-status` protobuf 响应（含 keystore/known_hosts 路径字段）、mDNS 真实发现表与 `mdns check/services`、`host:connect:<mDNS 实例>` 名称解析、known-host 自动连接和断线退避恢复、host TCP transport `A_STLS` TLS 1.3 升级、`host-features` 官方 `push_sync`/`libusb` host-only feature、`host:disconnect` 官方空目标/指定目标响应语义、host 侧 `reconnect` 官方响应语义、`host-serial`/`-s` 官方 target 匹配、`track-devices` protobuf 输出、`wait-for-*` 官方唯一目标/歧义失败/`disconnect` 边界语义、`get-state/get-serialno/get-devpath/get-transport-id` host-prefix 查询、`host:transport-id`/`host-transport-id` 选择器；CLI 已支持设备端 `reverse:*` service；已支持基础 `track-devices [-l|--proto-text|--proto-binary]`、`wait-for-*`、`features/host-features`、`server-status`、`mdns`、`pair`、`raw`、`jdwp/track-jdwp`、`logcat`、`bugreport`、`backup/restore`、`sideload`、`tcpip`、`usb`、`root/unroot`、`remount/verity`、`reconnect`；pair 已完成 TLS 1.3 双向证书、TLS exporter 绑定、SPAKE2/AES-128-GCM PeerInfo 交换、`adb_known_hosts.pb` 写入和当前 mDNS connect 实例的 best-effort 自动连接；mDNS create/update 会按 `ADB_MDNS_AUTO_CONNECT` 和 `adb_known_hosts.pb` 过滤并去重连接，server 重启或自然断线后按 AOSP 250ms/3s/20 次策略恢复，显式 `disconnect` 取消恢复；SELinux label、xattr 和 capabilities 由设备端 `adbd` 根据目标路径处理，不计为 host adb 的独立缺口。
- single APK install 已按 AOSP 实现 fastdeploy 主流程：`--fastdeploy`/`--no-fastdeploy` 按参数顺序生效，`--force-agent`、`--date-check-agent`、`--version-check-agent` 分别选择 always/newer timestamp/different version 更新策略；host 从二进制 `AndroidManifest.xml` 提取 package，执行 `deployagent dump 3 PACKAGE` 并解析 `APKDump` protobuf，以 ZIP central-directory record MD5 和 local file entry 为边界生成 `FASTDEPLOY` little-endian patch，streamed 路径流入 `apply - -pm`，legacy push 路径流入 `apply - -o`；shell v2 apply packet 会作为完整 frame 单次写入，设备缺包返回码 3 时回退普通安装，agent 版本错误返回码 4 时重部署 AOSP agent 后重试，agent apply 非零退出时回退普通 streamed/push 安装，API 低于 24 时按官方提示忽略。fastdeploy 与 incremental 的冲突检查保持 AOSP 顺序；Unix 平台已实现 `install --incremental` 的端到端流程：解析 `.idsig`、构造 `abb_exec:package install-incremental` service、spawn `inc-server` 子进程并传递连接 fd，inc-server 会按 AOSP 协议发送 `OKAY` 握手、按需发送 fs-verity 树块与数据块，数据块在 Unix 平台已接入 LZ4 压缩（压缩后小于原大小 95% 时启用），并已按 AOSP `PriorityBlocksForFile` 实现 ZIP/APK 签名块、central directory、classes.dex、resources.arsc、AndroidManifest.xml 及 `lib/*.so` 的优先级块发送，prefetch 策略已与 AOSP 对齐：移除初始自动全量预取，改为等待设备 `PREFETCH` 请求并去重，仅在 `BLOCK_MISSING` 真正发出块后追加后续 7 个相邻块预取，并响应设备的 `PREFETCH`/`BLOCK_MISSING`/`SERVING_COMPLETE`/`DESTROY` 请求；父进程在识别到 `Success` 或完整 `Failure[...]` 后即退出，`inc-server` 子进程继续在后台完成剩余块传输，与 AOSP `install_app` 生命周期一致；`--wait` 会额外等待 `inc-server` 子进程结束后再退出。Windows 平台已实现 socket handle 继承与匿名 pipe 的 `inc-server` 子进程传递，进入与 Unix 相同的增量安装主流程。fastdeploy 已在 API 28 的 `8b876adb` 和 API 34 的 `c57e1c6a` 真机完成 APK 更新、设备哈希校验与清理；incremental 已在具备 `android.software.incremental_delivery=2` 的 API 36 设备 `10AE9X3HES001TF` 完成 v4 `.idsig` 基线到 incremental 更新、`Success` 响应和设备哈希校验；更多平台和设备矩阵仍需继续验证。
- install 的 `--incremental`/`--no-incremental` 识别按 AOSP 前缀缩写规则：`--incr...` 必须是 `--incremental` 的前缀，`--no-incr...` 必须是 `--no-incremental` 的前缀；`--no-incrementalx` 这类未知选项不能被 host 侧吞掉。
- 显式 `--incremental` 在 Unix 平台已可进入增量安装主流程；在 `.idsig` 缺失等不满足增量条件时自动降级为普通 push/stream 安装。设备缺少 `abb_exec` 时报告 `Device doesn't support incremental installations`，与 `--fastdeploy` 或 `--streaming`/`--no-streaming` 冲突时按 AOSP 顺序返回相应错误。Windows 平台已实现增量安装主流程，不再返回未实现。
- `reboot [TARGET]`、`reboot-bootloader`、`reboot-fastboot` 已按 AOSP 映射到 `reboot:`、`reboot:<target>`、`reboot:bootloader`、`reboot:fastboot`，其中 `sideload-auto-reboot` 作为官方 target 字符串透传。
- `tcpip PORT` 已按 AOSP 校验端口范围 `1..65535`，并对缺参、多参、非法端口返回官方 CLI 错误文案。
- 旧式 `remount`/`disable-verity`/`enable-verity` device service 已按 AOSP 只取第一个附加参数拼接到冒号后；新设备 `remount_shell` 路径仍走 shell 命令。
- `server`/`nodaemon`/`fork-server` 要按 AOSP 作为前置 modifier 解析：`adb server` 后台启动，`adb server nodaemon` 和 `adb nodaemon server` 前台启动；`fork-server server --reply-fd FD` 走前台 server main，并在 bind、初始 emulator/USB 扫描完成后向 reply fd 写官方启动 ACK `OK\n`；`start-server` 只负责确保 server 已启动，不能再额外发送 `host:start-server` 到已存在 server；`fork-server` 缺少 `--reply-fd` 固定返回 `reply fd for adb server to client communication not specified.`，`--reply-fd` 缺参固定返回 `--reply-fd requires an argument`，非整数或 `<=2` 固定返回 `invalid reply fd "<value>"`；`--one-device` 允许用于 `start-server` 和这些 server 启动 modifier 组合。
- `usb` device service 已按 AOSP 支持可选首个附加参数，映射为 `usb:` 或 `usb:<arg>`。
- `root`/`unroot` device service 已按 AOSP 固定映射为 `root:`/`unroot:`，附加参数不参与 service 构造。
- `connect`/`disconnect` CLI 参数数量已按 AOSP 对齐：`connect` 必须恰好一个 `HOST[:PORT]`，`disconnect` 最多一个目标，多参不会被静默忽略。
- `forward`/`reverse` 参数校验在连接 server 前完成，错误文案与 AOSP 共享同一套固定英文：`forward requires an argument`、`--list doesn't take any arguments`、`--remove-all doesn't take any arguments`、`--remove requires an argument`、`--no-rebind takes two arguments`、`forward takes two arguments`。server 侧 forward listener 要按 AOSP `adb_listeners.cpp` 以 local 端点全局唯一管理：重复 `forward` 会把同一 local 重绑定到新的 remote/transport，`--no-rebind` 对任意已有 local 返回 `cannot rebind existing socket`，`killforward:LOCAL` 在 selector 能选中 transport 后按 local 删除，不再按 serial 过滤；transport 关闭、手动 `disconnect`、offline reconnect 或同 serial transport 替换时，关联 listener 必须随 transport 生命周期移除。
- `adb transport-id` 已按 AOSP 专用路径先执行当前 transport switch，再发送 `host:features` 并打印切换阶段拿到的 transport id；本项目 server 支持已选 transport 后的 `host:features`。
- `transport-id`、`server-status`、`jdwp`、`track-jdwp` 与 AOSP 当前 CLI 一样不检查尾随参数，新增校验前必须先对照 `commandline.cpp`。
- `attach`/`detach` 与 AOSP 一样不检查尾随参数，并且不是 host-prefix 查询；CLI 必须先切当前 transport，再发送裸 `host:attach`/`host:detach`。本项目已建模官方 `detached` 连接状态：列表文本为 `detached`，protobuf 状态值为 `5`/`DETACHED`，wait-active 判定中视为非 active，普通 device service 对 detached/offline transport 返回 `device offline (transport offline)`。server 已按 AOSP 对齐 libusb USB transport 的 detach 生命周期和 `ADB_LIBUSB_START_DETACHED=1` 启动策略：未显式 attach 的 libusb 设备会注册 detached 占位，周期枚举会按 serial/devpath 移除已拔出的占位；`detach` 会释放当前 transport、移除关联 forward listener、从 attached registry 移除 serial 并注册 detached 占位；`attach` 会先写入 attached registry，再按 serial/devpath 重新枚举并复用原 transport id。Windows server 监听 `PBT_APMRESUMEAUTOMATIC`，恢复后关闭全部旧 USB transport、移除关联 forward、保留 attached registry 并立即重扫。`Transport::close()` 会关闭底层连接以打断 reader 并释放 USB claim。非 detachable transport 的 detach 入口分别返回 `attach/detach not supported` 和 `attach/detach not supported!`。
- `track-devices` 与 AOSP 一样只消费第一个选项，`-l`、`--proto-text`、`--proto-binary` 后的尾随参数会被忽略。
- `devices` 非法参数固定返回 `adb devices [-l]`；`track-devices` 首个选项非法固定返回 `usage: adb track-devices [-l][--proto-text][--proto-binary]`。
- `wait-for-*` 要先在本地补 implied transport/校验短格式，再连接或启动 server；短格式错误固定为 AOSP 的 `couldn't parse 'wait-for' command: <command>`，transport/state 错误由 server 返回 `bad wait-for- ...`。
- `reconnect` 单个未知子命令返回 `usage: adb reconnect [device|offline]`，两个及以上附加参数与 AOSP 一样落到 `unknown command reconnect`。
- `mdns check|services` 的缺参、未知子命令、多余参数错误文案按 AOSP `commandline.cpp` 固定，service builder 有单测覆盖。
- `pair` 缺少 host 或参数过多固定返回 AOSP 的 `usage: adb pair HOST[:PORT] [PAIRING CODE]`；只有 host 时才提示 `Enter pairing code: ` 并读取 stdin，空配对码固定返回 `No pairing code provided`。
- server 侧 `host:pair:<password>:<host>` 要按 AOSP `host_service_to_socket("pair:")` 用第一个冒号切分 password/host；缺少分隔冒号返回 `unknown host service 'pair:<payload>'`；显式地址先校验 `HOST:PORT`，mDNS pairing 实例名走 `_adb-tls-pairing._tcp` 解析；pairing client 按 AOSP 使用 TLS 1.3 双向证书、`adb-label` exporter、SPAKE2、HKDF-SHA256、AES-128-GCM 和固定 8192 字节 PeerInfo，成功后追加设备 GUID 到 `adb_known_hosts.pb`。
- `emu` 与 AOSP 一样不做缺参 usage 检查；无 console 子命令时仍会连接 emulator console 并只发送 `quit\n`。
- `bugreport` 参数多于一个时固定返回 AOSP 的 `usage: adb bugreport [[PATH] | [--stream]]`。
- `exec-in`/`exec-out` 缺参固定返回 `usage: adb exec-in command` / `usage: adb exec-out command`；`restore` 缺参固定返回 `usage: adb restore FILENAME [ARG]...`。
- `abb` 缺少设备 feature `abb` 时固定返回 AOSP 英文 `abb is not supported by the device`，不要走中文 `Unsupported` 包装。
- `rescue` 参数校验要在连接 server 前完成，错误文案固定为 AOSP 的 `rescue requires at least one argument`、`invalid rescue getprop arguments`、`rescue install requires two arguments`、`invalid rescue wipe arguments`、`invalid rescue argument`。
- `keygen`/`pubkey` 缺参或多参的错误文案固定为 AOSP 的 `keygen requires an argument` / `pubkey requires an argument`。
- `install`、`install-multiple`、`install-multi-package`、`uninstall` 缺参入口固定返回 AOSP 的 `<command> requires an argument`，不要替换成中文 usage。
- single `install` 参数解析后若没有任何候选安装文件（例如只剩已消费的 `--streaming`/`--no-streaming`）固定返回 AOSP 的 `install requires an apk argument`；若存在候选但没有合法 APK/APEX，streamed 路径固定返回 `filename doesn't end .apk or .apex: <arg>`，push 路径固定返回 `need APK file on command line`。
- single `install` 的 streamed 路径要求原始最后一个参数是 APK/APEX，错误文案固定为 `filename doesn't end .apk or .apex: <arg>`；push 路径遇到 APEX 固定返回 `APEX packages are only compatible with Streamed Install`；目标不支持 APEX 固定返回 `.apex is not supported on the target device`。
- single `install --streaming` 和 `install-multiple --streaming` 在旧设备缺少 streaming/cmd 能力时固定返回 AOSP 的 `Attempting to use streaming install on unsupported device`，不要走中文 `Unsupported` 包装。
- `install-multiple` 解析后没有 trailing APK 时固定返回 `need APK file on command line`，遇到 `.apex` 固定返回 `APEX packages are not compatible with install-multiple`；`install-multi-package` 解析后没有 trailing APK/APEX 时固定返回 `need APK or APEX files on command line`。
- `install-multiple` 创建 session 时打开 service 失败固定打印 `adb: connect error for create: <error>` 并静默退出 1；已有 session 后 `install-write` 打开 service 失败固定打印 `adb: connect error for write: <error>`，finalize/abandon 打开 service 失败固定打印 `adb: connect error for finalize: <error>`，都不要走 `error:` 包装。
- `install-multiple` 的 trailing 文件 stat/open/write 失败要按 AOSP 打印 `adb: failed to stat/open/write "<file>": <error>`；session 已创建后这些失败仍要转入 finalize/abandon。
- `install-multi-package` 在旧设备缺少 `cmd`/streaming 能力时按 AOSP 向 stderr 打印 `adb: multi-package install is not supported on this device` 并以 1 静默退出，不要走 `Unsupported` 包装。
- `install-multiple` 的 session 包管理 service 要按 AOSP 优先级选择：`abb_exec:package`、`exec:cmd package`、旧设备 fallback `exec:pm`；不要因为缺少 `cmd` feature 直接拒绝。
- `install-multi-package` 的父/子 session、write、add-session、commit/abandon 也要按实际 feature 选择 `abb_exec:package` 或 `exec:cmd package`；错误展示里的 link command 要匹配该 service。
- `install-multi-package` 父 session 打开 service 失败固定打印 `adb: connect error for create multi-package: <error>`；子 session 打开 service 失败固定打印 `adb: connect error for create: <error>` 并进入 finalize/abandon；write service 失败固定打印 `adb: connect error for write: <error>`；finalize/剩余 session abandon service 失败固定打印 `adb: connect error for finalize: <error>`。
- `install-multi-package` split 文件 stat/open/write 失败要按 AOSP 打印无引号路径形式 `adb: failed to stat/open/write <file>: <error>`，且父 session 已创建后要转入 finalize/abandon。
- `install-multi-package` 不调用 AOSP 的 install mode parser；`--streaming`、`--no-streaming`、`--incremental`、`--no-incremental`、`--wait` 等字符串要作为 session 参数原样透传。
- `install-multi-package` 父 session 和子 session 创建失败都固定打印 `adb: failed to create multi-package session`，不要区分 `child session`。
- `install-multi-package` 执行 `install-add-session` 返回非 Success 时，错误行要包含匹配实际 service 的完整命令形态，例如 `exec:cmd package install-add-session <parent> <child...>` 或 `package install-add-session <parent> <child...>`。
- `install-multi-package` 打开 `install-add-session` service 失败时按 AOSP 打印 `adb: connect error for install-add-session: <error>` 并静默退出 1。
- `install-multi-package` commit 阶段只转发成对出现的 `--staged-ready-timeout VALUE`；孤立 `--staged-ready-timeout` 不进入 `install-commit` 参数。
- `uninstall -k` 的拒绝提示要按 AOSP 当前 install mode 区分：streamed/cmd 路径提示 `adb shell cmd package uninstall -k`，legacy/pm 路径提示 `adb shell pm uninstall -k`。
- `ls`、`push`、`pull` 缺参入口固定按 AOSP 返回 `ls requires an argument`、`push requires <source> and <destination> arguments`、`pull requires an argument`。
- 单文件 `push --sync` 要按 AOSP `sync_send` 只比较远端 `lstat` mtime；`adb sync` 目录同步才按 size/mtime 判定是否跳过。
- `raw` 缺参或多参的错误文案固定为 AOSP 的 `usage: adb raw SERVICE`，`dev-raw:` 仍需先检查设备 feature `devraw`。
- `track-app` 先按 AOSP 检查设备 feature `track_app`；feature 可用后，无参数、`--proto-text`、`--proto-binary` 正常，单个未知参数落到 `unknown command track-app`，两个及以上附加参数返回 `usage: adb track-app [--proto-binary][--proto-text]`。
- `help`、`--help`、`/?` 均按 AOSP 作为帮助命令；未知命令返回官方英文形态 `unknown command <name>`，顶层错误打印要用当前可执行文件名作为前缀（Windows `adb.exe: ...`、Unix `adb: ...`），可打印 CLI/usage/server 错误退出码固定为 1，不要再走中文“暂未支持”、固定 `error:` 包装或 clap 风格 usage 退出码 2。
- `shell -e` 缺参固定由 shell 子命令直接打印 `adb shell: option requires an argument -- e` 并静默退出 1；未知 shell 短选项固定打印 `adb shell: unknown option -- <char>` 并静默退出 1；`-e` 多字符或非 ASCII 固定返回 `-e requires a single-character argument or 'none'`；`-x` 最终没有分配 pty 时固定直接打印 `error: -x only supports allocating a pty` 并静默退出 1，`-Tx` 这种后续 `x` 重新强制 pty 的顺序应保持成功。
- `adb shell COMMAND...` 主入口要按 AOSP/ssh 风格把剩余 argv 用空格 join，不调用 `escape_arg`；只有本项目内部构造远端 shell 命令（例如 install、sync、logcat 等）时才对参数做单引号 shell quote。
- 全局参数缺参文案按 AOSP 固定为 `<option> requires an argument`。`--exit-on-write-error` 按官方作为无参数全局选项消费；`-sSERIAL` 和 `-tID` 只有第三个字符是数字时才作为内联参数；`-sabc`/`-tabc` 返回缺参错误。`-L` 不支持内联 `-Ltcp:...`，这类 token 会作为普通命令落到 `unknown command ...`。`-h` 不是官方帮助别名，应落到 `unknown command -h`；裸 `--` 也不是官方全局分隔符，应落到 `unknown command --`；全局 modifier 消费完后若没有实际命令，应打印帮助并失败退出。
- CLI 可以在已有官方 server 运行时复用官方 server 的设备能力；没有官方 server 时会启动本项目的最小 server。
- TCP/emulator transport 的 read timeout 只能用于 CNXN/AUTH 初始握手；握手完成后后台 reader 必须清回阻塞读，避免空闲 10 秒被误判为断线并从 registry 移除。
- 设备 service `A_OPEN` payload 必须按 AOSP 保留尾随 NUL；host 仅在 `ADB_BURST_MODE=1` 时声明并启用 `delayed_ack`，双方协商成功后 `A_OPEN.arg1` 必须是 32 MiB 初始 credit，host 对远端 `A_WRTE` 的 `A_OKAY` 必须携带 4 字节 little-endian 已写入字节数。设备主动发起 reverse `A_OPEN` 时必须先通过 per-transport allowlist；host connector 支持 TCP、Unix filesystem、Linux abstract/vsock socket，`localreserved:` 与 `acceptfd:` 保持官方不可连接语义。
- server listener 可以用 nonblocking accept，但 accept 出来的 smart-socket client 必须恢复 blocking 模式，避免 Windows 继承 nonblocking 后 `read_protocol_string` 把 10035 `WouldBlock` 当致命错误。设备端 `A_WRTE` 写回已关闭 smart client 失败时，只能对该 stream 回 `A_CLSE` 并移除 stream，不能关闭整个 transport。
- server smart-socket 要保留 AOSP socket spec：Windows 支持 `tcp:`；Unix 支持 filesystem namespace 的 `local:`/`localfilesystem:` 与仅监听的 `acceptfd:`；Linux 额外支持 `localabstract:`/`vsock:`。`tcp:0` 只作为动态 listener 端口，`tcp:HOST` 使用默认端口 5555；filesystem server 启动时清除残留节点，退出后与 AOSP 一样保留节点。上层 shell/sync/install 必须通过统一 `ServerStream` 工作，不能重新假定 server connection 一定是 `TcpStream`。
- libusb bulk-in reader 可使用短 read timeout 轮询显式 close 标志，但 timeout 本身不能被当作断线；`Transport::close()` 必须调用底层 `AdbConnection::close_connection()`，确保 TCP shutdown、libusb release interface、WinAdbApi close handle 都能打断后台 reader 并释放资源。底层 packet 写失败也必须关闭整个 transport，不能只让当前 service 线程退出并留下 zombie handle；bulk-out 写入仍可保留有限 timeout。
- `sync:` 连接关闭要按 AOSP `SyncConnection` 析构语义 best-effort 发送 `QUIT`，且显式 `quit()` 必须幂等；stub daemon 测试不得假设一个 `A_WRTE` 等于一个 sync frame，必须按字节流累计。
