# VibeGuard 卸载脚本（中英双语） / VibeGuard uninstaller (ZH/EN)
#
# 默认会做什么 / What it removes by default:
# - 尝试停止后台代理 / Try to stop background proxy
# - 移除开机自启（计划任务 / HKCU Run） / Remove autostart (Scheduled Task / HKCU Run)
# - 删除安装目录中的 vibeguard.exe / Remove vibeguard.exe in install dir
# - 清理 PowerShell Profile 中由 install.ps1 写入的 helper（# VibeGuard SHELL） / Remove injected profile helper
#
# 可选 / Optional:
# - -Purge 删除 ~/.vibeguard（配置/证书/日志/WAL） / Remove ~/.vibeguard
# - -RemovePath 从用户 PATH 移除安装目录（谨慎） / Remove install dir from user PATH (careful)

param(
  [string]$InstallDir = (Join-Path $HOME ".local\\bin"),
  [ValidateSet("auto", "zh", "en")]
  [string]$Language = "auto",
  [switch]$Purge,
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
  try { $text = Get-Content -LiteralPath "$ProfilePath" -Raw -ErrorAction Stop } catch { return $false }
  if ($null -eq $text -or $text -notmatch '# VibeGuard SHELL') { return $false }

  # 删除从 marker 到 function 结束的区块（和 install.ps1 注入内容保持一致）
  # 注意：function 内部会有缩进的 "  }"（例如 if 块结束），不能误匹配；
  # 这里要求结束行必须以 "}" 开头（无缩进），对应 install.ps1 注入的 function 结束行。
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

function FindVibeGuardExe([string]$Dir) {
  $candidate = Join-Path "$Dir" "vibeguard.exe"
  if (Test-Path -LiteralPath "$candidate") { return $candidate }
  $cmd = Get-Command "vibeguard" -ErrorAction SilentlyContinue
  if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Path)) { return $cmd.Path }
  return $null
}

function TryStopProxy([string]$VgPath, [string]$ConfigDir) {
  # 尽量先用 CLI stop（里面已包含 schtasks/launchctl/systemctl/pid 的多种策略）
  if (-not [string]::IsNullOrWhiteSpace($VgPath) -and (Test-Path -LiteralPath "$VgPath")) {
    try { & "$VgPath" "stop" | Out-Null } catch { }
  }

  # 退化：尝试结束计划任务
  if ($null -ne (Get-Command "schtasks" -ErrorAction SilentlyContinue)) {
    try { & schtasks /End /TN "VibeGuard" 2>$null | Out-Null } catch { }
  }

  # 退化：按 PID 文件杀进程
  $pidFile = Join-Path "$ConfigDir" "vibeguard.pid"
  if (Test-Path -LiteralPath "$pidFile") {
    try {
      $pidText = (Get-Content -LiteralPath "$pidFile" -ErrorAction Stop | Select-Object -First 1).Trim()
      $pid = 0
      if ([int]::TryParse($pidText, [ref]$pid) -and $pid -gt 0) {
        try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch { }
      }
    } catch { }
    try { Remove-Item -Force -LiteralPath "$pidFile" -ErrorAction SilentlyContinue | Out-Null } catch { }
  }
}

function RemoveAutostart() {
  # 计划任务（install.ps1 默认任务名固定 VibeGuard）
  if ($null -ne (Get-Command "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) {
    try {
      Unregister-ScheduledTask -TaskName "VibeGuard" -Confirm:$false -ErrorAction Stop | Out-Null
      Say "已删除计划任务：VibeGuard" "Removed scheduled task: VibeGuard"
    } catch { }
  } elseif ($null -ne (Get-Command "schtasks" -ErrorAction SilentlyContinue)) {
    try { & schtasks /Delete /F /TN "VibeGuard" 2>$null | Out-Null; Say "已删除计划任务：VibeGuard" "Removed scheduled task: VibeGuard" } catch { }
  }

  # HKCU Run fallback（install.ps1 可能会退化到这里）
  $runKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  try {
    if (Get-ItemProperty -Path "$runKey" -Name "VibeGuard" -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path "$runKey" -Name "VibeGuard" -ErrorAction SilentlyContinue | Out-Null
      Say "已移除开机启动项（HKCU Run）：VibeGuard" "Removed autorun (HKCU Run): VibeGuard"
    }
  } catch { }
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

  # 当前会话的小写环境变量也尽量清理（不动 User 级）
  foreach ($n in @("https_proxy", "http_proxy", "no_proxy")) {
    try { Remove-Item -Path ("Env:" + $n) -ErrorAction SilentlyContinue | Out-Null } catch { }
  }
}

function RemoveUserPathEntry([string]$Dir) {
  if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ([string]::IsNullOrWhiteSpace($userPath)) { return $false }
  $parts = $userPath -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  $newParts = $parts | Where-Object { -not $_.Equals($Dir, [System.StringComparison]::OrdinalIgnoreCase) }
  if ($newParts.Count -eq $parts.Count) { return $false }
  $newUserPath = ($newParts -join ';')
  [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")

  # 当前会话同步
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
  Remove-Item -Recurse -Force -LiteralPath "$ConfigDir" -ErrorAction SilentlyContinue | Out-Null
  Say ("已删除配置目录：$ConfigDir") ("Removed config dir: $ConfigDir")
}

function GetCAThumbprintFromFile([string]$CertPath) {
  if ([string]::IsNullOrWhiteSpace($CertPath)) { return $null }
  if (-not (Test-Path -LiteralPath "$CertPath")) { return $null }
  $certutil = Get-Command "certutil" -ErrorAction SilentlyContinue
  if ($null -eq $certutil) { return $null }
  try {
    $lines = & certutil -dump "$CertPath" 2>$null
    $text = $lines | Out-String
    if ($text -match '(?im)^\s*Cert Hash\(sha1\):\s*([0-9a-f ]+)\s*$') {
      return (($Matches[1] -replace '\s+', '').ToUpperInvariant())
    }
  } catch { }
  return $null
}

function RemoveCertByThumbprint([string]$StorePath, [string]$Thumbprint) {
  if ([string]::IsNullOrWhiteSpace($StorePath) -or [string]::IsNullOrWhiteSpace($Thumbprint)) { return $false }
  try {
    $items = Get-ChildItem -Path "$StorePath" -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if ($null -eq $items) { return $false }
    foreach ($c in @($items)) {
      try { Remove-Item -Path (Join-Path "$StorePath" $c.Thumbprint) -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    return $true
  } catch { }
  return $false
}

function IsThumbprintInStore([string]$StorePath, [string]$Thumbprint) {
  if ([string]::IsNullOrWhiteSpace($StorePath) -or [string]::IsNullOrWhiteSpace($Thumbprint)) { return $false }
  try {
    $items = Get-ChildItem -Path "$StorePath" -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $Thumbprint }
    return ($null -ne $items -and @($items).Count -gt 0)
  } catch { }
  return $false
}

function TryUntrustCA([string]$ConfigDir) {
  $caPath = Join-Path "$ConfigDir" "ca.crt"
  $thumb = GetCAThumbprintFromFile "$caPath"
  if ([string]::IsNullOrWhiteSpace($thumb)) {
    return $false
  }
  $thumb = $thumb.ToUpperInvariant()

  $hasUser = IsThumbprintInStore "Cert:\\CurrentUser\\Root" "$thumb"
  $hasSystem = IsThumbprintInStore "Cert:\\LocalMachine\\Root" "$thumb"
  if (-not $hasUser -and -not $hasSystem) {
    return $true
  }

  if ($hasUser) {
    if (RemoveCertByThumbprint "Cert:\\CurrentUser\\Root" "$thumb") {
      Say "已从当前用户信任库移除 VibeGuard CA" "Removed VibeGuard CA from CurrentUser trust store"
    }
  }

  if ($hasSystem) {
    if (RemoveCertByThumbprint "Cert:\\LocalMachine\\Root" "$thumb") {
      Say "已从系统信任库移除 VibeGuard CA" "Removed VibeGuard CA from system trust store"
    }
  }

  $stillUser = IsThumbprintInStore "Cert:\\CurrentUser\\Root" "$thumb"
  $stillSystem = IsThumbprintInStore "Cert:\\LocalMachine\\Root" "$thumb"
  if (-not $stillUser -and -not $stillSystem) { return $true }
  return $false
}

$configDir = Join-Path $HOME ".vibeguard"
$configFile = Join-Path "$configDir" "config.yaml"

Say "开始卸载" "Starting uninstall"
Say ("安装目录：$InstallDir") ("Install dir: $InstallDir")

$vg = FindVibeGuardExe "$InstallDir"
Say "停止后台代理" "Stopping proxy"
TryStopProxy "$vg" "$configDir"

Say "移除开机自启" "Removing autostart"
RemoveAutostart

$untrustOk = $true
Say "移除信任证书" "Removing trusted CA"
try { $untrustOk = TryUntrustCA "$configDir" } catch { $untrustOk = $false }

Say "清理 PowerShell Profile" "Cleaning PowerShell profile"
$profilePath = GetProfilePath
try { RemoveProfileHelper "$profilePath" | Out-Null } catch { }

Say "删除二进制" "Removing binary"
$bin = Join-Path "$InstallDir" "vibeguard.exe"
if (Test-Path -LiteralPath "$bin") {
  try { Remove-Item -Force -LiteralPath "$bin" -ErrorAction Stop | Out-Null; Say ("已删除：$bin") ("Removed: $bin") } catch { Warn ("删除失败：$($_.Exception.Message)") ("Failed to remove: $($_.Exception.Message)") }
} else {
  Say ("未在安装目录找到：$bin") ("Not found in install dir: $bin")
}

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

Say "卸载完成" "Uninstall complete"
if (-not $untrustOk) {
  Write-Host ""
  Write-Host (T "提示：如果你曾运行 vibeguard trust 安装系统证书，请在证书管理器中手动移除 “VibeGuard CA”。" "Note: If you installed the CA via vibeguard trust, remove \"VibeGuard CA\" from the trust store manually if needed.")
}
