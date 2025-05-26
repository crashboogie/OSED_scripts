# Define debugger and dependency paths
$debuggerPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
    "C:\Program Files\Windows Kits\10\Debuggers\x86"
)
$msdia90Paths = @(
    "C:\Program Files\Common Files\Microsoft Shared\VC\msdia90.dll",
    "C:\Program Files (x86)\Common Files\Microsoft Shared\VC\msdia90.dll"
)

$share_path = '\\tsclient\mona-share\\'
$install_dir = "C:\Users\Administrator\Desktop\install-mona"

# Find debugger base path
$debuggerBase = $null
foreach ($path in $debuggerPaths) {
    if (Test-Path $path) {
        $debuggerBase = $path
        break
    }
}
if (-not $debuggerBase) {
    Write-Host "[-] ERROR: Could not find debugger path. Exiting."
    return
}
Write-Host "[+] Debugger path found: $debuggerBase"

# Create install directory
Write-Host "[+] Creating install directory at: $install_dir"
New-Item -Path "$install_dir" -ItemType Directory -Force | Out-Null

# Ensure TrustedInstaller is running
Write-Host "[+] Starting TrustedInstaller..."
try {
    Set-Service -Name TrustedInstaller -StartupType Manual -ErrorAction Stop
    Start-Service -Name TrustedInstaller -ErrorAction Stop
    Write-Host "[+] TrustedInstaller started."
} catch {
    Write-Host "[-] Failed to start TrustedInstaller: $_"
}

# Copy Windbg theme
Write-Host "[+] Copying windbg theme..."
if (!(Test-Path "$share_path\dark.wew")) {
    Write-Host "[-] ERROR: dark.wew not found in $share_path"
} else {
    Copy-Item "$share_path\dark.wew" "$install_dir"
}

Start-Sleep -Seconds 3

# Install C++ Redistributable
Write-Host "[+] Installing C++ Redistributable..."
if (!(Test-Path "$share_path\vcredist_x86.exe")) {
    Write-Host "[-] ERROR: vcredist_x86.exe not found in $share_path"
} else {
    Copy-Item "$share_path\vcredist_x86.exe" "$install_dir"
    & "$install_dir\vcredist_x86.exe"
    Write-Host "[+] vcredist_x86.exe launched, sleeping to allow install..."
    Start-Sleep -Seconds 30
}

# Backup existing pykd if present
$pykdPath = Join-Path $debuggerBase "winext\pykd.pyd"
$pykdDLL = Join-Path $debuggerBase "winext\pykd.dll"

Write-Host "[+] Backing up existing pykd files..."
if (Test-Path $pykdPath) {
    Move-Item $pykdPath "$pykdPath.bak"
    Write-Host "[+] Backed up pykd.pyd"
}
if (Test-Path $pykdDLL) {
    Move-Item $pykdDLL "$pykdDLL.bak"
    Write-Host "[+] Backed up pykd.dll"
}

# Install Python 2.7
Write-Host "[+] Installing Python 2.7..."
if (!(Test-Path "$share_path\python-2.7.17.msi")) {
    Write-Host "[-] ERROR: python-2.7.17.msi not found in $share_path"
} else {
    Copy-Item "$share_path\python-2.7.17.msi" "$install_dir"
    msiexec.exe /i "$install_dir\python-2.7.17.msi" /qn
    Write-Host "[+] Python 2.7 install command sent"
    Start-Sleep -Seconds 10
}

# Add Python to PATH
Write-Host "[+] Adding Python to PATH..."
$p = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::User)
if ($p -notlike "*C:\Python27*") {
    [System.Environment]::SetEnvironmentVariable('Path', "C:\Python27\;C:\Python27\Scripts;" + $p, [System.EnvironmentVariableTarget]::User)
    Write-Host "[+] Python paths added to user PATH"
} else {
    Write-Host "[*] Python paths already exist in user PATH"
}

# Copy Mona and PYKD files
Write-Host "[+] Copying mona.py, windbglib.py, and pykd.pyd..."
$copyTargets = @("windbglib.py", "mona.py", "pykd.pyd")

foreach ($file in $copyTargets) {
    $src = Join-Path $share_path $file

    if ($file -eq "pykd.pyd") {
        $dst = Join-Path $debuggerBase "winext"
    } else {
        $dst = $debuggerBase
    }

    if (!(Test-Path $src)) {
        Write-Host "[-] ERROR: $file not found at $src"
    } else {
        Copy-Item $src $dst -Force
        Write-Host "[+] Copied $file to $dst"
    }
}

# Register msdia90.dll
Write-Host "[+] Attempting to register msdia90.dll..."
$msdiaDir = $null
foreach ($msdia in $msdia90Paths) {
    if (Test-Path $msdia) {
        $msdiaDir = Split-Path $msdia -Parent
        break
    }
}
if ($msdiaDir) {
    Write-Host "[+] Found msdia90.dll in: $msdiaDir"
    Push-Location $msdiaDir
    regsvr32 /s "msdia90.dll"
    Pop-Location
    Write-Host "[+] Successfully registered msdia90.dll"
} else {
    Write-Host "[-] msdia90.dll not found. Skipping registration."
}

Write-Host "[=] All done! If symbols or pykd fail, double-check dependencies and try:"
Write-Host "    regsvr32 'C:\Program Files\Common Files\Microsoft Shared\VC\msdia90.dll'"
Write-Host "    .load pykd from WinDbg"
