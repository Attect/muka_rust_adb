from pathlib import Path
import os
import signal
import subprocess
import sys
import time
import unittest


CHILD_ENV = "ADB_RUST_DEVICES_LISTING_CHILD"


def load_case(source_path):
    source = source_path.read_text(encoding="utf-8")
    first_part = source.split("\ndef invoke(", 1)[0]
    namespace = {
        "__file__": str(source_path),
        "__name__": "aosp_devices_listing_subset",
    }
    exec(compile(first_part, source_path, "exec"), namespace)
    return namespace["DevicesListing"]


def first_active_serial():
    output = subprocess.check_output(["adb", "devices"], text=True)
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            return fields[0]
    raise RuntimeError("没有 active device 可用于 DevicesListing")


def stable_first_active_serial():
    previous = None
    for _ in range(20):
        current = first_active_serial()
        if current == previous:
            return current
        previous = current
        time.sleep(0.1)
    raise RuntimeError("设备列表首项在 2 秒内没有稳定")


def terminate_process_tree(process):
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def run_child(source_path, test_name, serial):
    env = os.environ.copy()
    env[CHILD_ENV] = "1"
    env["ANDROID_SERIAL"] = serial
    kwargs = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    process = subprocess.Popen(
        [sys.executable, __file__, str(source_path), test_name],
        env=env,
        **kwargs,
    )
    try:
        return process.wait(timeout=45)
    except subprocess.TimeoutExpired:
        terminate_process_tree(process)
        print(f"{test_name} 超过 45 秒，已终止 Python/adb 子进程树", file=sys.stderr)
        return 124


source_path = Path(sys.argv[1])
test_names = sys.argv[2:]
if os.environ.get(CHILD_ENV) == "1":
    case = load_case(source_path)
    suite = unittest.TestSuite(case(name) for name in test_names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)

for test_name in test_names:
    serial = stable_first_active_serial()
    print(f"DevicesListing {test_name}: first active serial={serial}")
    result = run_child(source_path, test_name, serial)
    if result != 0:
        raise SystemExit(result)
