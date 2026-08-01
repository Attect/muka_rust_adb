[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact,

    [ValidateSet("auto", "windows")]
    [string]$Format = "auto"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "standalone check failed: $Message"
}

$resolved = Resolve-Path -LiteralPath $Artifact -ErrorAction Stop
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    Fail "artifact is not a file: $Artifact"
}

if ($Format -eq "auto") {
    if ([IO.Path]::GetExtension($resolved.Path) -ieq ".exe") {
        $Format = "windows"
    } else {
        Fail "cannot infer format on PowerShell; pass -Format windows for a PE artifact"
    }
}

if ($Format -ne "windows") {
    Fail "PowerShell checker only handles PE; use scripts/check-standalone.sh for ELF or Mach-O"
}

$objdump = Get-Command llvm-objdump -ErrorAction SilentlyContinue
if ($null -eq $objdump) {
    $objdump = Get-Command dumpbin -ErrorAction SilentlyContinue
}
if ($null -eq $objdump) {
    Fail "llvm-objdump or dumpbin is required"
}

$output = & $objdump.Source -p $resolved.Path 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "unable to inspect PE imports with $($objdump.Source)"
}

$imports = @(
    $output |
        Select-String -CaseSensitive -Pattern "DLL Name:\s*(.+)$" |
        ForEach-Object { $_.Matches[0].Groups[1].Value.Trim().ToLowerInvariant() }
)

$forbidden = @(
    $imports | Where-Object {
        $_ -match "^(adbwinapi|libusb-1\.0|vcruntime|msvcp|ucrtbase)\.dll$" -or
        $_ -match "(^|[-_.])adb[-_]?rust([-_.]|$)"
    }
)
if ($forbidden.Count -gt 0) {
    Fail "private or redistributable DLL imports found: $($forbidden -join ', ')"
}

$systemImport = {
    param([string]$Name)
    $Name -match "^(api-ms-win-|ext-ms-win-)" -or
        $Name -in @(
            "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cfgmgr32.dll",
            "combase.dll", "crypt32.dll", "gdi32.dll", "iphlpapi.dll", "kernel32.dll",
            "kernelbase.dll", "ntdll.dll", "ole32.dll", "powrprof.dll", "rpcrt4.dll",
            "secur32.dll", "setupapi.dll", "shell32.dll", "user32.dll", "version.dll",
            "winmm.dll", "ws2_32.dll"
        )
}
$nonSystem = @($imports | Where-Object { -not (& $systemImport $_) })
if ($nonSystem.Count -gt 0) {
    Fail "non-system DLL imports found: $($nonSystem -join ', ')"
}

Write-Output "standalone check passed: $($resolved.Path)"
Write-Output "PE imports: $($imports -join ', ')"
