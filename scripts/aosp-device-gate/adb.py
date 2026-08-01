import subprocess
import sys


class ShellError(RuntimeError):
    pass


class _Device:
    def __init__(self):
        self.adb_cmd = ["adb"]
        self.linesep = "\n"

    def _check_output(self, args):
        return subprocess.check_output(self.adb_cmd + args).decode("utf-8")

    def _simple_call(self, args):
        try:
            return subprocess.check_output(
                self.adb_cmd + args,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as error:
            sys.stderr.buffer.write(error.output)
            raise

    def forward_list(self):
        return self._check_output(["forward", "--list"])

    def forward(self, local, remote):
        return self._check_output(["forward", local, remote])

    def forward_no_rebind(self, local, remote):
        return self._check_output(["forward", "--no-rebind", local, remote])

    def forward_remove(self, local):
        return self._check_output(["forward", "--remove", local])

    def forward_remove_all(self):
        return self._check_output(["forward", "--remove-all"])

    def reverse_list(self):
        return self._check_output(["reverse", "--list"])

    def reverse(self, remote, local):
        return self._check_output(["reverse", remote, local])

    def reverse_no_rebind(self, remote, local):
        return self._check_output(["reverse", "--no-rebind", remote, local])

    def reverse_remove(self, remote):
        return self._check_output(["reverse", "--remove", remote])

    def reverse_remove_all(self):
        return self._check_output(["reverse", "--remove-all"])

    def has_shell_protocol(self):
        return "shell_v2" in self._check_output(["features"]).splitlines()

    def shell_nocheck(self, args):
        proc = subprocess.run(
            self.adb_cmd + ["shell"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def shell(self, args):
        result = self.shell_nocheck(args)
        if result[0] != 0:
            raise ShellError(result)
        return result[1], result[2]

    def push(self, local, remote, sync=False):
        local_paths = local if isinstance(local, list) else [local]
        args = ["push"]
        if sync:
            args.append("--sync")
        return self._simple_call(args + local_paths + [remote])

    def pull(self, remote, local):
        remote_paths = remote if isinstance(remote, list) else [remote]
        return self._simple_call(["pull"] + remote_paths + [local])

    def sync(self, partition):
        return self._simple_call(["sync", partition])


def get_device():
    return _Device()
