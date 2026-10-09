# VibeGuard uninstaller script (bilingual strings; comments in English)
#
# What it removes by default:
# - Try to stop background proxy
# - Remove autostart (Scheduled Task / HKCU Run)
# - Remove vibeguard.exe in install dir
# - Remove the helper injected into PowerShell profile by install.ps1 (# VibeGuard SHELL)
#
# Optional:
# - -Purge: remove ~/.vibeguard (config/certs/logs/WAL)
# - -RemovePath: remove install dir from user PATH

param(
  [string]$InstallDir = (Join-Path $HOME ".local\\bin"),
  [ValidateSet("auto", "zh", "en")]
  [string]$Language = "auto",
  [switch]$Purge,
  [switch]$KeepConfig,
  [int]$CallerPID = 0,
  [switch]$Yes,
  [switch]$RemovePath,
  [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptLang = $null
$LangFromFile = $false

function NormalizeLang([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    "zh" { return "zh" }
    "zh-cn" { return "zh" }
    "zh_cn" { return "zh" }
    "cn" { return "zh" }
    "chinese" { return "zh" }
    "中文" { return "zh" }
    "en" { return "en" }
    "en-us" { return "en" }
    "en_us" { return "en" }
    "english" { return "en" }
    default {
      if ($v -match '^zh') { return "zh" }
      if ($v -match '^en') { return "en" }
      return $null
    }
  }
}

function DetectDefaultLang() {
  try {
    $name = [System.Globalization.CultureInfo]::CurrentUICulture.Name
    if ($name -match '^zh') { return "zh" }
  } catch {
    # ignore
  }
  return "en"
}

if ($Language -ne "auto") {
  $ScriptLang = NormalizeLang $Language
}
if (-not $ScriptLang) {
  $ScriptLang = NormalizeLang $env:VIBEGUARD_LANG
}
if (-not $ScriptLang) {
  $langFile = Join-Path $HOME ".vibeguard\\lang"
  if (Test-Path -LiteralPath "$langFile") {
    try {
      $fileLang = (Get-Content -LiteralPath "$langFile" -Raw -ErrorAction Stop).Trim()
      $ScriptLang = NormalizeLang $fileLang
      if ($ScriptLang) { $LangFromFile = $true }
    } catch {
      # ignore
    }
  }
}
if (-not $ScriptLang) {
  $ScriptLang = DetectDefaultLang
}

$canPrompt = (-not $NonInteractive) -and ($Language -eq "auto") -and (-not $LangFromFile) -and (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected)
if ($canPrompt) {
  Write-Host ""
  Write-Host "请选择语言 / Choose language:"
  Write-Host "  1) 中文"
  Write-Host "  2) English"
  $defaultChoice = if ($ScriptLang -eq "zh") { "1" } else { "2" }
  $prompt = if ($ScriptLang -eq "zh") { "选择 [$defaultChoice]" } else { "Choose [$defaultChoice]" }
  $choice = Read-Host $prompt
  if ([string]::IsNullOrWhiteSpace($choice)) { $choice = $defaultChoice }
  switch ($choice) {
    "1" { $ScriptLang = "zh" }
    "2" { $ScriptLang = "en" }
    default { }
  }
}

function T([string]$Zh, [string]$En) {
  if ($ScriptLang -eq "zh") { return $Zh }
  return $En
}

function Say([string]$Zh, [string]$En) {
  Write-Host ""
  Write-Host "==> $(T $Zh $En)"
}

function Warn([string]$Zh, [string]$En) {
  Write-Warning (T $Zh $En)
}

function BackupFile([string]$Path) {
  if (-not (Test-Path -LiteralPath "$Path")) { return $null }
  $ts = (Get-Date).ToString("yyyyMMddHHmmss")
  $bak = "$Path.vibeguard.bak.$ts"
  try { Copy-Item -Force -LiteralPath "$Path" -Destination "$bak" | Out-Null } catch { }
  return $bak
}

function GetProfilePath() {
  try {
    if ($null -ne $PROFILE -and $null -ne $PROFILE.CurrentUserAllHosts -and -not [string]::IsNullOrWhiteSpace($PROFILE.CurrentUserAllHosts)) {
      return $PROFILE.CurrentUserAllHosts
    }
  } catch { }
  return $PROFILE
}

function RemoveProfileHelper([string]$ProfilePath) {
  if ([string]::IsNullOrWhiteSpace($ProfilePath)) { return $false }
  if (-not (Test-Path -LiteralPath "$ProfilePath")) { return $false }

  $text = $null
  $text = Get-Content -LiteralPath "$ProfilePath" -Raw -ErrorAction Stop
  if ($null -eq $text -or $text -notmatch '# VibeGuard SHELL') { return $false }

  # Remove the block from marker to the end of the function (matches what install.ps1 injects).
  # Note: the function body may contain indented "  }" lines (e.g. end of if blocks); do not mis-match them.
  # We require the ending line to start with "}" (no indentation), matching the injected function's final brace.
  $pattern = '(?ms)^[ \t]*# VibeGuard SHELL.*?^\}\s*\r?\n?'
  $newText = [System.Text.RegularExpressions.Regex]::Replace($text, $pattern, "")
  if ($newText -eq $text) { return $false }

  $bak = BackupFile "$ProfilePath"
  Set-Content -LiteralPath "$ProfilePath" -Value $newText -Encoding UTF8
  if ($null -ne $bak) {
    Say ("已清理 PowerShell Profile：$ProfilePath（备份：$bak）") ("Updated PowerShell profile: $ProfilePath (backup: $bak)")
  } else {
    Say ("已清理 PowerShell Profile：$ProfilePath") ("Updated PowerShell profile: $ProfilePath")
  }
  return $true
}

function StopVibeGuardProcess([int]$ProcessID, [string]$VgPath) {
  if ($ProcessID -le 1 -or $ProcessID -eq $CallerPID) { return }
  $proc = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue
  if ($null -eq $proc) { return }
  if ([string]::IsNullOrWhiteSpace($proc.Path)) { throw "Cannot identify process $ProcessID; leaving it untouched" }
  if (-not $proc.Path.Equals($VgPath, [StringComparison]::OrdinalIgnoreCase)) { return }
  Stop-Process -Id $ProcessID -Force -ErrorAction Stop
  if (-not $proc.HasExited) { $proc.WaitForExit(5000) | Out-Null }
  if (-not $proc.HasExited) { throw "Could not stop VibeGuard process $ProcessID" }
}

function TryStopProxy([string]$VgPath, [string]$ConfigDir) {
  $pidFile = Join-Path "$ConfigDir" "vibeguard.pid"
  if (Test-Path -LiteralPath $pidFile) {
    $processID = 0
    $pidText = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    if ([int]::TryParse($pidText, [ref]$processID)) { StopVibeGuardProcess $processID $VgPath }
    Remove-Item -Force -LiteralPath $pidFile
  }
  # Covers foreground proxies and the registry Run fallback, without killing other installs.
  Get-Process -Name vibeguard -ErrorAction SilentlyContinue | ForEach-Object {
    StopVibeGuardProcess $_.Id $VgPath
  }
}

function RemoveAutostart() {
  # Query/delete errors must propagate; a missing task is the only benign case.
  $task = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'VibeGuard' -and $_.TaskPath -eq '\' })
  foreach ($item in $task) {
    if ($item.State -eq 'Running') { Stop-ScheduledTask -InputObject $item -ErrorAction Stop }
    Unregister-ScheduledTask -InputObject $item -Confirm:$false -ErrorAction Stop
  }
  $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $runKey) {
    $entry = Get-ItemProperty -Path $runKey -ErrorAction Stop
    if ($entry.PSObject.Properties['VibeGuard']) {
      Remove-ItemProperty -Path $runKey -Name VibeGuard -ErrorAction Stop
    }
  }
}

function GetListenFromConfig([string]$Path) {
  if (-not (Test-Path -LiteralPath "$Path")) { return $null }
  try { $lines = Get-Content -LiteralPath "$Path" -ErrorAction Stop } catch { return $null }

  $inProxy = $false
  foreach ($line in $lines) {
    if ($line -match '^\s*proxy:\s*(#.*)?$') { $inProxy = $true; continue }
    if ($inProxy -and $line -match '^[A-Za-z_][A-Za-z0-9_]*:\s*(#.*)?$') { $inProxy = $false }
    if ($inProxy -and $line -match '^\s*listen:\s*(.+)$') {
      $v = $Matches[1]
      $v = ($v -replace '\s+#.*$', '').Trim()
      $v = $v.Trim('"').Trim("'")
      if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
      return $null
    }
  }
  return $null
}

function ProxyHostPortFromListen([string]$Listen) {
  if ([string]::IsNullOrWhiteSpace($Listen)) { return "127.0.0.1:28657" }
  $l = $Listen.Trim()
  if ($l.StartsWith("0.0.0.0:")) { return "127.0.0.1:" + $l.Substring("0.0.0.0:".Length) }
  if ($l.StartsWith(":")) { return "127.0.0.1" + $l }
  return $l
}

function RemoveProxyEnvIfMatches([string]$ProxyUrl, [string]$NoProxy) {
  $names = @("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
  foreach ($n in $names) {
    $cur = [Environment]::GetEnvironmentVariable($n, "User")
    if ([string]::IsNullOrWhiteSpace($cur)) { continue }
    $shouldRemove = $false
    if ($n -eq "NO_PROXY") { $shouldRemove = $cur.Equals($NoProxy, [System.StringComparison]::OrdinalIgnoreCase) }
    else { $shouldRemove = $cur.Equals($ProxyUrl, [System.StringComparison]::OrdinalIgnoreCase) }

    if ($shouldRemove) {
      [Environment]::SetEnvironmentVariable($n, $null, "User") | Out-Null
      try {
        if ((Get-Item -Path ("Env:" + $n) -ErrorAction SilentlyContinue).Value -eq $cur) {
          Remove-Item -Path ("Env:" + $n) -ErrorAction SilentlyContinue | Out-Null
        }
      } catch { }
    }
  }

  # Also clean lowercase env vars in the current session (do not touch User-level ones).
  foreach ($n in @("https_proxy", "http_proxy", "no_proxy")) {
    try { Remove-Item -Path ("Env:" + $n) -ErrorAction SilentlyContinue | Out-Null } catch { }
  }
}

function RemoveUserPathEntry([string]$Dir) {
  if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ([string]::IsNullOrWhiteSpace($userPath)) { return $false }
  $parts = $userPath -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  $parts = @($parts)
  $newParts = @($parts | Where-Object { -not $_.Equals($Dir, [System.StringComparison]::OrdinalIgnoreCase) })
  if ($newParts.Count -eq $parts.Count) { return $false }
  $newUserPath = ($newParts -join ';')
  [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")

  # Sync current session.
  $curParts = $env:Path -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  $env:Path = (($curParts | Where-Object { -not $_.Equals($Dir, [System.StringComparison]::OrdinalIgnoreCase) }) -join ';')
  return $true
}

function PurgeConfigDir([string]$ConfigDir) {
  if (-not (Test-Path -LiteralPath "$ConfigDir")) { return }
  if ($NonInteractive -and (-not $Yes)) {
    throw (T "非交互模式下执行 -Purge 需要同时带上 -Yes" "In non-interactive mode, -Purge requires -Yes")
  }
  if (-not $Yes -and (-not $NonInteractive)) {
    Write-Host ""
    Write-Host (T ("⚠️ 将删除目录（包含 CA 私钥、日志、WAL 等）：$ConfigDir") ("⚠️ This will delete (includes CA private key, logs, WAL): $ConfigDir"))
    $ans = Read-Host (T "确认删除？(y/N)" "Confirm delete? (y/N)")
    if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "N" }
    if ($ans -notmatch '^(?i:y|yes)$') {
      Warn "已跳过 -Purge（保留 ~/.vibeguard）" "Skipped -Purge (kept ~/.vibeguard)"
      return
    }
  }
  Remove-Item -Recurse -Force -LiteralPath "$ConfigDir" -ErrorAction Stop | Out-Null
  Say ("已删除配置目录：$ConfigDir") ("Removed config dir: $ConfigDir")
}

function GetCAThumbprintFromFile([string]$CertPath) {
  if (-not (Test-Path -LiteralPath $CertPath)) { return $null }
  # Native X509 avoids locale-dependent certutil output parsing.
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
  try { return $cert.Thumbprint } finally { $cert.Dispose() }
}

function RemoveCertByThumbprint([string]$StorePath, [string]$Thumbprint) {
  $items = @(Get-ChildItem -Path $StorePath -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $Thumbprint })
  foreach ($cert in $items) {
    Remove-Item -LiteralPath (Join-Path $StorePath $cert.Thumbprint) -Force -ErrorAction Stop
  }
}

function IsThumbprintInStore([string]$StorePath, [string]$Thumbprint) {
  $items = @(Get-ChildItem -Path $StorePath -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $Thumbprint })
  return $items.Count -gt 0
}

function TryUntrustCA([string]$ConfigDir) {
  foreach ($name in @('ca.crt', 'vibeguard-docker-ca.crt')) {
    $caPath = Join-Path $ConfigDir $name
    if (-not (Test-Path -LiteralPath $caPath)) { continue }
    $thumb = GetCAThumbprintFromFile $caPath
    if ([string]::IsNullOrWhiteSpace($thumb)) { return $false }
    foreach ($store in @('Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root')) {
      if (IsThumbprintInStore $store $thumb) { RemoveCertByThumbprint $store $thumb }
      if (IsThumbprintInStore $store $thumb) { return $false }
    }
  }
  return $true
}

function NewBinaryRemovalScript([string]$BinaryPath, [int]$ParentID, [string]$ResultPath) {
  $binLiteral = $BinaryPath.Replace("'", "''")
  $resultLiteral = $ResultPath.Replace("'", "''")
  return @"
`$ErrorActionPreference = 'Stop'
try {
  Set-Content -LiteralPath '$resultLiteral' -Value 'waiting for CLI exit'
  `$parent = if ($ParentID -gt 0) { Get-Process -Id $ParentID -ErrorAction SilentlyContinue } else { `$null }
  if (`$null -ne `$parent -and -not `$parent.WaitForExit(30000)) { throw 'CLI did not exit within 30 seconds' }
  for (`$i = 0; `$i -lt 30; `$i++) {
    if (-not (Test-Path -LiteralPath '$binLiteral')) { break }
    try { Remove-Item -LiteralPath '$binLiteral' -Force -ErrorAction Stop } catch { Start-Sleep -Milliseconds 100 }
  }
  if (Test-Path -LiteralPath '$binLiteral') { throw 'Could not delete executable' }
  Set-Content -LiteralPath '$resultLiteral' -Value 'complete'
} catch {
  Set-Content -LiteralPath '$resultLiteral' -Value ('failed: ' + `$_.Exception.Message)
  exit 1
}
"@
}

function RemoveInstalledBinary([string]$BinaryPath) {
  if (-not (Test-Path -LiteralPath $BinaryPath)) { return $null }
  $caller = if ($CallerPID -gt 0) { Get-Process -Id $CallerPID -ErrorAction Stop } else { $null }
  if ($null -eq $caller -or -not $caller.Path.Equals($BinaryPath, [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -Force -LiteralPath $BinaryPath -ErrorAction Stop
    return $null
  }
  # Windows locks the running executable. A detached worker deletes it after CLI exit.
  $result = Join-Path ([IO.Path]::GetTempPath()) ('vibeguard-uninstall-' + [Guid]::NewGuid().ToString('N') + '.txt')
  $code = NewBinaryRemovalScript $BinaryPath $CallerPID $result
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
  $worker = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -WindowStyle Hidden -PassThru
  for ($i = 0; $i -lt 100 -and -not (Test-Path -LiteralPath $result); $i++) {
    if ($worker.HasExited) { throw 'Binary removal worker exited before starting' }
    Start-Sleep -Milliseconds 100
  }
  if (-not (Test-Path -LiteralPath $result)) { throw 'Binary removal worker did not start' }
  return $result
}

$configDir = Join-Path $HOME ".vibeguard"
$configFile = if ($env:VIBEGUARD_CONFIG) { $env:VIBEGUARD_CONFIG } else { Join-Path "$configDir" "config.yaml" }

# Check deletion decisions before stopping services or touching files.
if ($Purge -and $KeepConfig) { throw "-Purge and -KeepConfig cannot be used together" }
if ($Purge -and -not $Yes) {
  if ($NonInteractive -or [Console]::IsInputRedirected) { throw "Deleting configuration requires -Purge -Yes" }
  $answer = Read-Host (T "删除配置、证书私钥、日志和 WAL？[y/N]" "Delete configuration, CA private key, logs and WAL? [y/N]")
  if ($answer -notmatch '^(?i:y|yes)$') { throw "Uninstall cancelled" }
  $Yes = $true
}

Say "开始卸载" "Starting uninstall"
Say ("安装目录：$InstallDir") ("Install dir: $InstallDir")

Say "停止后台代理" "Stopping proxy"
RemoveAutostart
TryStopProxy (Join-Path $InstallDir "vibeguard.exe") "$configDir"

Say "移除信任证书" "Removing trusted CA"
if (-not (TryUntrustCA "$configDir")) { throw "CA trust remains; binary and configuration preserved for retry" }

Say "清理 PowerShell Profile" "Cleaning PowerShell profile"
$profilePath = GetProfilePath
$documents = [Environment]::GetFolderPath('MyDocuments')
$profiles = @($profilePath)
if (-not [string]::IsNullOrWhiteSpace($documents)) {
  $profiles += Join-Path $documents 'WindowsPowerShell\profile.ps1'
  $profiles += Join-Path $documents 'PowerShell\profile.ps1'
}
$profiles | Select-Object -Unique | ForEach-Object { RemoveProfileHelper $_ | Out-Null }


Say "清理代理环境变量（仅在值匹配 VibeGuard 时）" "Cleaning proxy env vars (only if values match VibeGuard)"
$listen = GetListenFromConfig "$configFile"
$proxyHostPort = ProxyHostPortFromListen "$listen"
$proxyUrl = "http://$proxyHostPort"
$noProxy = "127.0.0.1,localhost"
RemoveProxyEnvIfMatches "$proxyUrl" "$noProxy"

if ($RemovePath) {
  Say "清理用户 PATH（可选）" "Cleaning user PATH (optional)"
  if (RemoveUserPathEntry "$InstallDir") {
    Say ("已从用户 PATH 移除：$InstallDir") ("Removed from user PATH: $InstallDir")
  } else {
    Say "用户 PATH 未包含该目录（或无需移除）" "User PATH does not contain that dir (or no change needed)"
  }
} else {
  Say "保留用户 PATH（如需移除请加 -RemovePath）" "Keeping user PATH (use -RemovePath to remove)"
}

if ($Purge) {
  Say "清理配置目录" "Purging config dir"
  PurgeConfigDir "$configDir"
} else {
  Say ("保留配置目录：$configDir（可用 -Purge 删除）") ("Keeping config dir: $configDir (use -Purge to remove)")
}

Say "删除二进制" "Removing binary"
$resultPath = RemoveInstalledBinary (Join-Path $InstallDir 'vibeguard.exe')
if ($resultPath) {
  Say ("清理完成，程序将在命令退出后删除；最终结果：$resultPath") ("Cleanup finished; executable deletion pending CLI exit. Final result: $resultPath")
} else {
  Say "卸载完成" "Uninstall complete"
}
