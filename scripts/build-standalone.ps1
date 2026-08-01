[CmdletBinding()]
param(
    [ValidateSet("x86_64-pc-windows-msvc")]
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$TargetDir = "target\standalone"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$buildArtifact = Join-Path $repo "$TargetDir\$Target\release\adb.exe"
$distributionDir = Join-Path $repo "target\dist\$Target"
$artifact = Join-Path $distributionDir "adb.exe"

Push-Location $repo
$oldPkgConfigLibDir = [Environment]::GetEnvironmentVariable("PKG_CONFIG_LIBDIR", "Process")
$oldPkgConfigPath = [Environment]::GetEnvironmentVariable("PKG_CONFIG_PATH", "Process")
try {
    # 发布构建必须使用 vendored C 库，不接受机器上的系统 pkg-config 结果。
    $env:PKG_CONFIG_LIBDIR = "/__adb_rust_no_pkg_config__"
    $env:PKG_CONFIG_PATH = "/__adb_rust_no_pkg_config__"
    cargo build --release --target $Target --target-dir $TargetDir
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build returned $LASTEXITCODE"
    }

    New-Item -ItemType Directory -Path $distributionDir -Force | Out-Null
    Copy-Item -LiteralPath $buildArtifact -Destination $artifact -Force
    $distributionEntries = @(Get-ChildItem -LiteralPath $distributionDir -Force)
    if ($distributionEntries.Count -ne 1 -or
        $distributionEntries[0].PSIsContainer -or
        $distributionEntries[0].Name -cne "adb.exe") {
        throw "standalone distribution must contain only adb.exe: $distributionDir"
    }

    & (Join-Path $PSScriptRoot "check-standalone.ps1") -Artifact $artifact -Format windows
    if ($LASTEXITCODE -ne 0) {
        throw "standalone checker returned $LASTEXITCODE"
    }
    Write-Output "standalone artifact: $artifact"
} finally {
    if ($null -eq $oldPkgConfigLibDir) {
        Remove-Item Env:PKG_CONFIG_LIBDIR -ErrorAction SilentlyContinue
    } else {
        $env:PKG_CONFIG_LIBDIR = $oldPkgConfigLibDir
    }
    if ($null -eq $oldPkgConfigPath) {
        Remove-Item Env:PKG_CONFIG_PATH -ErrorAction SilentlyContinue
    } else {
        $env:PKG_CONFIG_PATH = $oldPkgConfigPath
    }
    Pop-Location
}
