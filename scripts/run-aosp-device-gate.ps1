[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Serial,

    [string]$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",

    [string]$AospAdbDir = "\\wsl.localhost\Debian\mnt\wsl\PhysicalDrive5\Android\aosp\packages\modules\adb",

    [string]$Python = "python",

    [ValidateScript({
        if ($_ -notmatch '^tcp:127\.0\.0\.1:(\d+)$' -or
            [int]$Matches[1] -lt 1 -or
            [int]$Matches[1] -gt 65535) {
            throw "ServerSocket must be tcp:127.0.0.1:<port>, port range 1..65535"
        }
        $true
    })]
    [string]$ServerSocket = "tcp:127.0.0.1:5037",

    [switch]$Extended,

    [switch]$FileOperations,

    [switch]$IncludeServerStatus
)

$ErrorActionPreference = "Stop"

function Invoke-PythonChecked([string[]]$Arguments) {
    & $script:PythonCommand @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "AOSP Python test failed with exit code $LASTEXITCODE"
    }
}

function Restore-EnvironmentValue([string]$Name, $Value) {
    if ($null -eq $Value) {
        Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
    } else {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

function Read-JdwpSnapshot(
    [string]$AdbPath,
    [string]$DeviceSerial,
    [string]$Command,
    [string]$OutputDirectory,
    [int]$TimeoutMilliseconds = 2000
) {
    $stdout = Join-Path $OutputDirectory "$Command.stdout.txt"
    $stderr = Join-Path $OutputDirectory "$Command.stderr.txt"
    $process = Start-Process -FilePath $AdbPath `
        -ArgumentList @("-s", $DeviceSerial, $Command) `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru
    try {
        $exited = $process.WaitForExit($TimeoutMilliseconds)
        if (-not $exited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit()
        }
        if ($Command -eq "track-jdwp") {
            $bytes = [IO.File]::ReadAllBytes($stdout)
            $offset = 0
            $lines = @()
            while ($offset -lt $bytes.Length) {
                if ($bytes.Length - $offset -lt 4) {
                    throw "track-jdwp returned a truncated hex4 frame header"
                }
                $lengthText = [Text.Encoding]::ASCII.GetString($bytes, $offset, 4)
                if ($lengthText -notmatch "^[0-9a-fA-F]{4}$") {
                    throw "track-jdwp returned an invalid hex4 frame header: $lengthText"
                }
                $length = [Convert]::ToInt32($lengthText, 16)
                $offset += 4
                if ($bytes.Length - $offset -lt $length) {
                    throw "track-jdwp returned a truncated payload"
                }
                $payload = [Text.Encoding]::UTF8.GetString($bytes, $offset, $length)
                $lines += @(
                    $payload -split "\r?\n" |
                        ForEach-Object { $_.Trim() } |
                        Where-Object { $_.Length -gt 0 }
                )
                $offset += $length
            }
        } else {
            $lines = @(
                Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_.Length -gt 0 }
            )
        }
        $errors = (Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue | Out-String).Trim()
        if ($exited -and $process.ExitCode -ne 0) {
            throw "$Command failed with exit code $($process.ExitCode): $errors"
        }
        return $lines
    } finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$adbPath = (Resolve-Path -LiteralPath $Adb -ErrorAction Stop).ProviderPath
$aospPath = (Resolve-Path -LiteralPath $AospAdbDir -ErrorAction Stop).ProviderPath
$testDevice = Join-Path $aospPath "test_device.py"
if (-not (Test-Path -LiteralPath $testDevice -PathType Leaf)) {
    throw "AOSP test_device.py not found: $testDevice"
}

if (Test-Path -LiteralPath $Python -PathType Leaf) {
    $script:PythonCommand = (Resolve-Path -LiteralPath $Python).ProviderPath
} else {
    $script:PythonCommand = (Get-Command $Python -ErrorAction Stop).Source
}

$shimDir = Join-Path $PSScriptRoot "aosp-device-gate"
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempBase "adb-rust-aosp-device-gate-$PID"
$tempFull = [IO.Path]::GetFullPath($tempDir)
if (-not $tempFull.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw "temporary directory escaped system temp: $tempFull"
}
New-Item -ItemType Directory -Path $tempFull -Force | Out-Null
$gateAdb = Join-Path $tempFull "adb.exe"
Copy-Item -LiteralPath $adbPath -Destination $gateAdb -Force

$oldPath = [Environment]::GetEnvironmentVariable("PATH", "Process")
$oldPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
$oldServerSocket = [Environment]::GetEnvironmentVariable("ADB_SERVER_SOCKET", "Process")
$oldSerial = [Environment]::GetEnvironmentVariable("ANDROID_SERIAL", "Process")

try {
    $env:PATH = "$tempFull$([IO.Path]::PathSeparator)$oldPath"
    $pythonParts = @($shimDir, $aospPath)
    if (-not [string]::IsNullOrEmpty($oldPythonPath)) {
        $pythonParts += $oldPythonPath
    }
    $env:PYTHONPATH = $pythonParts -join [IO.Path]::PathSeparator
    $env:ADB_SERVER_SOCKET = $ServerSocket
    $env:ANDROID_SERIAL = $Serial

    Invoke-PythonChecked @("-c", "import google.protobuf")

    $state = (& $gateAdb -s $Serial get-state | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $state -ne "device") {
        throw "selected device is not active: $Serial state=$state"
    }

    $forwardRules = (& $gateAdb forward --list | Out-String).Trim()
    $reverseRules = (& $gateAdb -s $Serial reverse --list | Out-String).Trim()
    if ($forwardRules.Length -ne 0 -or $reverseRules.Length -ne 0) {
        throw "forward/reverse rules must be empty before the gate"
    }

    $safeTests = @(
        "test_device.ForwardReverseTest",
        "test_device.ShellTest.test_cat",
        "test_device.ShellTest.test_throws_on_failure",
        "test_device.ShellTest.test_output_not_stripped",
        "test_device.ShellTest.test_shell_command_length",
        "test_device.ShellTest.test_shell_nocheck_failure",
        "test_device.ShellTest.test_shell_nocheck_output_not_stripped",
        "test_device.ShellTest.test_can_distinguish_tricky_results",
        "test_device.ShellTest.test_line_endings",
        "test_device.ShellTest.test_shell_protocol",
        "test_device.ShellTest.test_non_interactive_stdin",
        "test_device.ArgumentEscapingTest.test_shell_escaping"
    )
    $features = & $gateAdb -s $Serial features
    if ($features -contains "abb") {
        $safeTests = @("test_device.AbbTest.test_smoke") + $safeTests
    } else {
        Write-Warning "skip AbbTest: device does not advertise feature abb"
    }
    Invoke-PythonChecked (@("-m", "unittest", "-v") + $safeTests)

    $deviceLines = & $gateAdb devices
    $trackerSerial = $deviceLines |
        ForEach-Object {
            if ($_ -match "^(\S+)\s+device(?:\s|$)") {
                $Matches[1]
            }
        } |
        Select-Object -First 1
    if ([string]::IsNullOrEmpty($trackerSerial)) {
        throw "no active device available for DevicesListing"
    }
    $env:ANDROID_SERIAL = $trackerSerial
    Invoke-PythonChecked @(
        (Join-Path $shimDir "run_devices_listing.py"),
        $testDevice,
        "test_track_devices_proto_text",
        "test_track_devices_proto_binary"
    )
    $env:ANDROID_SERIAL = $Serial

    $jdwpPids = @(Read-JdwpSnapshot $gateAdb $Serial "jdwp" $tempFull)
    if ($jdwpPids.Count -eq 0) {
        Write-Warning "skip track-jdwp snapshot: device has no active JDWP process"
    } else {
        $invalidPids = @($jdwpPids | Where-Object { $_ -notmatch "^\d+$" })
        if ($invalidPids.Count -ne 0) {
            throw "jdwp returned non-numeric process ids: $($invalidPids -join ', ')"
        }
        $trackedPids = @(Read-JdwpSnapshot $gateAdb $Serial "track-jdwp" $tempFull)
        foreach ($jdwpPid in $jdwpPids) {
            if ($trackedPids -notcontains $jdwpPid) {
                throw "track-jdwp did not report active process $jdwpPid"
            }
        }
        Write-Output "JDWP snapshot passed: $($jdwpPids -join ',')"
    }

    if ($IncludeServerStatus) {
        Invoke-PythonChecked @("-m", "unittest", "-v", "test_device.ServerStatus")
    }

    if ($Extended) {
        Invoke-PythonChecked @(
            "-m",
            "unittest",
            "-v",
            "test_device.SocketTest.test_socket_flush",
            "test_device.FramebufferTest.test_framebuffer"
        )
    }

    if ($FileOperations) {
        $fileTests = @()
        $fileClasses = @("FileOperationsTestUncompressed")
        foreach ($compression in @(
            @{ Feature = "sendrecv_v2_brotli"; Class = "FileOperationsTestBrotli" },
            @{ Feature = "sendrecv_v2_lz4"; Class = "FileOperationsTestLZ4" },
            @{ Feature = "sendrecv_v2_zstd"; Class = "FileOperationsTestZstd" }
        )) {
            if ($features -contains $compression.Feature) {
                $fileClasses += $compression.Class
            } else {
                Write-Warning "skip $($compression.Class): device does not advertise $($compression.Feature)"
            }
        }
        foreach ($class in $fileClasses) {
            foreach ($method in @(
                "test_push",
                "test_push_dir",
                "test_pull",
                "test_pull_dir",
                "test_pull_empty",
                "test_unicode_paths"
            )) {
                $fileTests += "test_device.$class.$method"
            }
        }
        Invoke-PythonChecked (@("-m", "unittest", "-v") + $fileTests)
    }

    Write-Output "AOSP device gate passed: serial=$Serial tracker_serial=$trackerSerial"
} finally {
    & $gateAdb -s $Serial forward --remove-all 2>$null | Out-Null
    & $gateAdb -s $Serial reverse --remove-all 2>$null | Out-Null
    if ($FileOperations) {
        & $gateAdb -s $Serial shell rm -rf "/data/local/tmp/adb_test_file" "/data/local/tmp/adb_test_dir" "/data/local/tmp/adb-test-*" 2>$null | Out-Null
    }
    & $gateAdb kill-server 2>$null | Out-Null
    Restore-EnvironmentValue "PATH" $oldPath
    Restore-EnvironmentValue "PYTHONPATH" $oldPythonPath
    Restore-EnvironmentValue "ADB_SERVER_SOCKET" $oldServerSocket
    Restore-EnvironmentValue "ANDROID_SERIAL" $oldSerial
    if (Test-Path -LiteralPath $tempFull) {
        Remove-Item -LiteralPath $tempFull -Recurse -Force
    }
}
