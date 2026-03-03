<# 
清理仓库内的本地产物/临时目录（默认仅预览）。
用法：
  powershell -ExecutionPolicy Bypass -File .\scripts\clean.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\clean.ps1 -Force
#>

param(
  [switch]$Force
)

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$Targets = @(
  (Join-Path $RootDir "temp"),
  (Join-Path $RootDir "~"),
  (Join-Path $RootDir "{cmd"),
  (Join-Path $RootDir "bin"),
  (Join-Path $RootDir "cmd/vibeguard/vibeguard"),
  (Join-Path $RootDir "cmd/vibeguard/vibeguard.exe"),
  (Join-Path $RootDir "vibeguard")
)

Write-Host "将清理以下本地产物（默认仅预览）："
$Existing = @()
foreach ($p in $Targets) {
  if (Test-Path -LiteralPath $p) {
    Write-Host " - $p"
    $Existing += $p
  }
}
if ($Existing.Count -eq 0) {
  Write-Host "（未发现可清理项）"
}

if (-not $Force) {
  Write-Host ""
  Write-Host "预览模式：不会删除任何文件。"
  Write-Host "如需执行清理：powershell -ExecutionPolicy Bypass -File .\scripts\clean.ps1 -Force"
  exit 0
}

Write-Host ""
Write-Host "正在清理..."
foreach ($p in $Existing) {
  Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "完成。"

