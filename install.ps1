# VibeGuard 安装脚本（中英双语） / VibeGuard installer (ZH/EN)
#
# 功能 / Features:
# - 安装 vibeguard.exe（二选一：从源码构建 / go install） / Install vibeguard.exe (build from source or go install)
# - 导出（“下载”）CA 证书到文件 / Export ("download") the CA certificate to a file
# - 可选：安装 CA 到系统/用户信任库（system/user/auto/skip） / Optional: install CA into trust store
#
# 用法 / Usage:
#   powershell -ExecutionPolicy Bypass -File .\\install.ps1

param(
  [string]$InstallDir = (Join-Path $HOME ".local\\bin"),
  [ValidateSet("system", "user", "auto", "skip")]
  [string]$Trust = "system",
  [ValidateSet("auto", "user", "skip")]
  [string]$PathMode = "auto",
  [ValidateSet("auto", "add", "skip")]
  [string]$AutostartMode = "auto",
  [ValidateSet("auto", "zh", "en")]
  [string]$Language = "auto",
  [switch]$Export,
  [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptLang = $null

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
  $ScriptLang = DetectDefaultLang
}

$canPrompt = (-not $NonInteractive) -and ($Language -eq "auto") -and (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected)
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

# 传递给 vibeguard 子进程（如未来 init/trust 支持多语言提示）
$env:VIBEGUARD_LANG = $ScriptLang

# 记住所选语言（供管理页/卸载脚本默认使用）
try {
  $cfgDir0 = Join-Path $HOME ".vibeguard"
  New-Item -ItemType Directory -Force -Path "$cfgDir0" | Out-Null
  $langFile = Join-Path "$cfgDir0" "lang"
  [System.IO.File]::WriteAllText("$langFile", ($ScriptLang + "`n"), [System.Text.UTF8Encoding]::new($false))
} catch {
  # ignore
}

function Say([string]$Zh, [string]$En) {
  Write-Host ""
  Write-Host "==> $(T $Zh $En)"
}

function Die([string]$Zh, [string]$En) {
  Write-Host ""
  Write-Error (T ("错误：" + $Zh) ("Error: " + $En))
  exit 1
}

function Have([string]$Name) {
  return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Need([string]$Name) {
  if (-not (Have $Name)) {
    Die "缺少依赖：$Name" "Missing dependency: $Name"
  }
}

function InRepo() {
  return (Test-Path -LiteralPath "go.mod") -and (Test-Path -LiteralPath "cmd/vibeguard/main.go")
}

function Run([string]$File, [string[]]$Args) {
  & $File @Args
  if ($LASTEXITCODE -ne 0) {
    Die "命令执行失败：$File $($Args -join ' ')" "Command failed: $File $($Args -join ' ')"
  }
}

function IsAdmin() {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function PathContains([string]$PathValue, [string]$Dir) {
  if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
  if ([string]::IsNullOrWhiteSpace($PathValue)) { return $false }
  $parts = $PathValue -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  foreach ($p in $parts) {
    if ($p.Equals($Dir, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function EnsureUserPath([string]$Dir) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not (PathContains $userPath $Dir)) {
    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { "$Dir" } else { "$Dir;$userPath" }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    return $true
  }
  return $false
}

function GetListenFromConfig([string]$Path) {
  if (-not (Test-Path -LiteralPath "$Path")) { return $null }
  try {
    $lines = Get-Content -LiteralPath "$Path" -ErrorAction Stop
  } catch {
    return $null
  }

  $inProxy = $false
  foreach ($line in $lines) {
    if ($line -match '^\s*proxy:\s*(#.*)?$') {
      $inProxy = $true
      continue
    }
    if ($inProxy -and $line -match '^[A-Za-z_][A-Za-z0-9_]*:\s*(#.*)?$') {
      $inProxy = $false
    }
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

function EnableAutostartTask([string]$VgPath, [string]$ConfigFile) {
  $taskName = "VibeGuard"
  $args = "--config `"$ConfigFile`" start --foreground"
  $action = New-ScheduledTaskAction -Execute "$VgPath" -Argument "$args"
  $trigger = New-ScheduledTaskTrigger -AtLogOn

  $userId = $null
  if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
    $userId = "$($env:USERDOMAIN)\\$($env:USERNAME)"
  } elseif (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
    $userId = "$($env:USERNAME)"
  } else {
    $userId = "$([Environment]::UserName)"
  }

  $principal = New-ScheduledTaskPrincipal -UserId "$userId" -LogonType Interactive -RunLevel LeastPrivilege
  try {
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  } catch {
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  }

  Register-ScheduledTask -TaskName "$taskName" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "VibeGuard proxy autostart" -Force | Out-Null
  try { Start-ScheduledTask -TaskName "$taskName" | Out-Null } catch { }
  return $taskName
}

function EnableAutostartRunKey([string]$VgPath, [string]$ConfigFile) {
  $runKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  $vgEsc = $VgPath -replace "'", "''"
  $cfgEsc = $ConfigFile -replace "'", "''"
  $cmd = "& '$vgEsc' --config '$cfgEsc' start --foreground"
  $value = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"$cmd`""
  New-Item -Path "$runKey" -Force | Out-Null
  New-ItemProperty -Path "$runKey" -Name "VibeGuard" -Value "$value" -PropertyType String -Force | Out-Null
  return $runKey
}

New-Item -ItemType Directory -Force -Path "$InstallDir" | Out-Null
Need "go"

Say "安装目录：$InstallDir" "Install dir: $InstallDir"

if (InRepo) {
  Say "检测到仓库源码：从源码构建并安装" "Repo detected: build from source"
  $tmp = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path "$tmp" | Out-Null
  try {
    $outExe = Join-Path "$tmp" "vibeguard.exe"
    Run "go" @("build", "-o", "$outExe", "./cmd/vibeguard")
    Copy-Item -Force -LiteralPath "$outExe" -Destination (Join-Path "$InstallDir" "vibeguard.exe")
  } finally {
    Remove-Item -Recurse -Force -LiteralPath "$tmp" -ErrorAction SilentlyContinue | Out-Null
  }
} else {
  Say "未检测到源码：通过 go install 安装" "Repo not found: installing via go install"
  $env:GOBIN = "$InstallDir"
  Run "go" @("install", "github.com/inkdust2021/vibeguard/cmd/vibeguard@latest")
}

$vg = Join-Path "$InstallDir" "vibeguard.exe"
if (-not (Test-Path -LiteralPath "$vg")) {
  $cmd = Get-Command "vibeguard" -ErrorAction SilentlyContinue
  if ($null -ne $cmd) {
    $vg = $cmd.Path
  }
}
if (-not (Test-Path -LiteralPath "$vg")) {
  Die "未找到 vibeguard：$vg" "vibeguard not found: $vg"
}

Say "vibeguard 路径：$vg" "vibeguard path: $vg"

$configDir = Join-Path $HOME ".vibeguard"
$caCert = Join-Path "$configDir" "ca.crt"
$configFile = Join-Path "$configDir" "config.yaml"

# 可选：让 vibeguard 在全局可调用（写入用户 PATH）
if ($PathMode -ne "skip") {
  $cmd = Get-Command "vibeguard" -ErrorAction SilentlyContinue
  $resolved = if ($null -ne $cmd) { $cmd.Path } else { $null }
  $needPath = $false
  if ($null -eq $resolved) { $needPath = $true }
  elseif (-not $resolved.Equals($vg, [System.StringComparison]::OrdinalIgnoreCase)) { $needPath = $true }

  if ($needPath) {
    $doIt = $false
    if ($PathMode -eq "user") {
      $doIt = $true
    } elseif (-not $NonInteractive) {
      $answer = Read-Host (T "检测到 vibeguard 可能无法全局调用，是否将安装目录写入用户 PATH？(Y/n)" "vibeguard may not be on PATH. Add install dir to user PATH? (Y/n)")
      if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "Y" }
      if ($answer -match '^(?i:y|yes)$') { $doIt = $true }
    } else {
      Write-Warning (T "非交互模式：未写入 PATH（可手动将 $InstallDir 加入用户 PATH）" "Non-interactive: PATH not modified (add $InstallDir to user PATH manually)")
    }

    if ($doIt) {
      $changed = EnsureUserPath "$InstallDir"
      if ($changed) {
        Say "已写入用户 PATH（需重开终端生效）" "Updated user PATH (restart terminal to apply)"
      } else {
        Say "用户 PATH 已包含该目录" "User PATH already contains this dir"
      }
      if (-not (PathContains $env:Path "$InstallDir")) {
        $env:Path = "$InstallDir;$($env:Path)"
      }
    }
  }
}

Say "检查 CA 证书" "Checking CA certificate"
if (-not (Test-Path -LiteralPath "$caCert")) {
  if (Test-Path -LiteralPath "$configFile") {
    Say "已存在配置但未找到 CA：请运行 vibeguard init 生成 CA" "Config exists but CA missing: run vibeguard init to generate CA"
  } else {
    Say "未找到 CA：将运行 vibeguard init 生成 CA" "CA not found: running vibeguard init to generate CA"
    if ($NonInteractive) {
      $tmp = Join-Path $env:TEMP ("vibeguard-init-" + [Guid]::NewGuid().ToString("N") + ".txt")
      try {
        $initInput = "`n`n`n`n3`n"
        [System.IO.File]::WriteAllText("$tmp", $initInput, [System.Text.UTF8Encoding]::new($false))
        $p = Start-Process -FilePath "$vg" -ArgumentList @("init") -RedirectStandardInput "$tmp" -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) {
          Write-Warning (T "init 返回非 0：$($p.ExitCode)" "init exited with non-zero: $($p.ExitCode)")
        }
      } finally {
        Remove-Item -Force -LiteralPath "$tmp" -ErrorAction SilentlyContinue | Out-Null
      }
    } else {
      & "$vg" "init"
    }
  }
}

if (Test-Path -LiteralPath "$caCert") {
  Say "CA 证书已就绪：$caCert" "CA certificate ready: $caCert"
} else {
  Say "仍未找到 CA 证书：跳过证书步骤" "CA certificate still missing: skipping cert steps"
  $Trust = "skip"
  $Export = $false
}

$exportWasProvided = $PSBoundParameters.ContainsKey('Export')
if (-not $NonInteractive -and (-not $exportWasProvided) -and (Test-Path -LiteralPath "$caCert")) {
  $ans = Read-Host (T "是否导出（下载）CA 证书到文件（便于排查/手动安装）？(y/N)" "Export CA certificate to a file (for debugging/manual install)? (y/N)")
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "N" }
  if ($ans -match '^(?i:y|yes)$') { $Export = $true }
}

$trustWasProvided = $PSBoundParameters.ContainsKey('Trust')
if (-not $NonInteractive -and (-not $trustWasProvided) -and (Test-Path -LiteralPath "$caCert")) {
  $ans = Read-Host (T "是否安装信任证书（HTTPS MITM 必需，推荐）？(Y/n)" "Install trusted CA (required for HTTPS MITM, recommended)? (Y/n)")
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "Y" }
  if ($ans -match '^(?i:n|no)$') { $Trust = "skip" } else { $Trust = "auto" }
}

if ($Export -and (Test-Path -LiteralPath "$caCert")) {
  $exportPath = $null
  $downloads = Join-Path $HOME "Downloads"
  if (Test-Path -LiteralPath "$downloads") {
    $exportPath = Join-Path "$downloads" "vibeguard-ca.crt"
  } else {
    $exportPath = (Join-Path (Get-Location) "vibeguard-ca.crt")
  }
  Copy-Item -Force -LiteralPath "$caCert" -Destination "$exportPath"
  Say "已导出（下载）CA 证书：$exportPath" "Exported CA certificate: $exportPath"
}

switch ($Trust) {
  "skip" {
    Say "跳过信任库安装" "Skipping trust store install"
  }
  "system" {
    Say "将安装到系统信任库（需要管理员权限）" "Installing to SYSTEM trust store (Administrator required)"
    if (-not (IsAdmin)) {
      Say "检测到当前不是管理员：将弹出 UAC 提示" "Not elevated: prompting UAC"
      $p = Start-Process -FilePath "$vg" -ArgumentList @("trust", "--mode", "system") -Verb RunAs -Wait -PassThru
      if ($p.ExitCode -ne 0) {
        Die "安装系统信任证书失败（exit=$($p.ExitCode)）" "Failed to install system trust certificate (exit=$($p.ExitCode))"
      }
    } else {
      Run "$vg" @("trust", "--mode", "system")
    }
  }
  "user" {
    Say "将安装到用户信任库" "Installing to USER trust store"
    Run "$vg" @("trust", "--mode", "user")
  }
  "auto" {
    Say "将自动选择信任库（先 user 再 system）" "Installing with AUTO mode (user then system)"
    Run "$vg" @("trust", "--mode", "auto")
  }
  default {
    Die "无效的 -Trust：$Trust" "Invalid -Trust: $Trust"
  }
}

$listen = GetListenFromConfig "$configFile"
$proxyHostPort = ProxyHostPortFromListen "$listen"
$proxyUrl = "http://$proxyHostPort"
$adminUrl = "http://$proxyHostPort/manager/"

# 可选：开机自启（Windows 计划任务；若不可用则退化为 HKCU Run）
$autostartEnabled = $false
$autostartHint = $null
if ($AutostartMode -ne "skip") {
  $doIt = $false
  if ($AutostartMode -eq "add") {
    $doIt = $true
  } elseif (-not $NonInteractive) {
    $answer = Read-Host (T "是否启用开机自启并后台运行（推荐）？(Y/n)" "Enable autostart + background run (recommended)? (Y/n)")
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "Y" }
    if ($answer -match '^(?i:y|yes)$') { $doIt = $true }
  } else {
    Write-Warning (T "非交互模式：未启用开机自启" "Non-interactive: autostart not configured")
  }

  if ($doIt) {
    $taskCmdOk = ($null -ne (Get-Command "Register-ScheduledTask" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskAction" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskTrigger" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskPrincipal" -ErrorAction SilentlyContinue))

    if ($taskCmdOk) {
      try {
        $name = EnableAutostartTask "$vg" "$configFile"
        $autostartEnabled = $true
        $autostartHint = (T "计划任务：$name（可用“任务计划程序”禁用/删除）" "Task Scheduler: $name (disable/delete via Task Scheduler)")
        Say "已启用开机自启（计划任务）" "Autostart enabled (Task Scheduler)"
      } catch {
        Write-Warning (T ("计划任务创建失败，将退化为 HKCU Run：$($_.Exception.Message)") ("Failed to create scheduled task; falling back to HKCU Run: $($_.Exception.Message)"))
      }
    }

    if (-not $autostartEnabled) {
      try {
        $where = EnableAutostartRunKey "$vg" "$configFile"
        $autostartEnabled = $true
        $autostartHint = (T "HKCU Run：登录后自动启动（可在注册表或启动项中移除）" "HKCU Run: starts on logon (remove via registry/startup apps)")
        Say "已启用开机自启（HKCU Run）" "Autostart enabled (HKCU Run)"
      } catch {
        Write-Warning (T ("启用开机自启失败：$($_.Exception.Message)") ("Failed to enable autostart: $($_.Exception.Message)"))
      }
    }
  }
}

Say "启动后台代理" "Starting proxy in background"
try {
  & "$vg" "start" | Out-Null
} catch { }

Say "安装完成" "Done"
Write-Host ""
Write-Host (T "下一步：" "Next steps:")
if ($autostartEnabled) {
  Write-Host (T "  1) 代理已设置为开机自启（登录后自动运行）" "  1) Proxy runs automatically on logon")
  if ($null -ne $autostartHint) { Write-Host ("     " + $autostartHint) }
} else {
  Write-Host (T "  1) 启动代理（后台）：$vg start" "  1) Start proxy (background): $vg start")
  Write-Host (T "     前台调试：$vg start --foreground" "     Foreground debug: $vg start --foreground")
}

Write-Host (T "  2) 打开管理页：$adminUrl" "  2) Open admin: $adminUrl")
Write-Host (T "  3) CLI 编程助手推荐用 VibeGuard 启动（仅该进程生效）：" "  3) For CLI assistants, launch via VibeGuard (process-only):")
Write-Host "     vibeguard codex [args...]"
Write-Host "     vibeguard claude [args...]"
Write-Host "     vibeguard gemini [args...]"
Write-Host "     vibeguard opencode [args...]"
Write-Host "     vibeguard qwen [args...]"
Write-Host "     vibeguard run <command> [args...]"
Write-Host (T "  4) IDE/GUI（如 Cursor）在软件设置里把代理地址填为：$proxyUrl" "  4) For IDE/GUI apps (Cursor, etc), set the proxy URL to: $proxyUrl")
