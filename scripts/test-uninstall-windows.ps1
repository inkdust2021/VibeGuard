# Run only on a disposable Windows test runner: exercises the real CLI/self-deletion.
param([Parameter(Mandatory=$true)][string]$BinaryPath)
$ErrorActionPreference = 'Stop'
$base = Join-Path ([IO.Path]::GetTempPath()) ('vg-uninstall-cli-test-' + [Guid]::NewGuid().ToString('N'))
$originalProfile = $env:USERPROFILE
$originalConfig = $env:VIBEGUARD_CONFIG
$originalLanguage = $env:VIBEGUARD_LANG
New-Item -ItemType Directory $base | Out-Null
try {
  foreach ($keep in @($true, $false)) {
    $homePath = Join-Path $base ([Guid]::NewGuid().ToString('N'))
    $dir = Join-Path $homePath 'custom bin'
    $config = Join-Path $homePath '.vibeguard'
    New-Item -ItemType Directory $dir, $config -Force | Out-Null
    $exe = Join-Path $dir 'vibeguard.exe'
    Copy-Item -LiteralPath $BinaryPath -Destination $exe
    Set-Content (Join-Path $config 'config.yaml') 'proxy: {listen: "127.0.0.1:28657"}'
    Set-Content (Join-Path $config 'vibeguard.log') 'synthetic log'
    $env:USERPROFILE = $homePath
    $env:VIBEGUARD_CONFIG = Join-Path $config 'config.yaml'
    $env:VIBEGUARD_LANG = 'en'
    $flags = if ($keep) { @('--keep-config', '--non-interactive') } else { @('--purge', '--yes', '--non-interactive') }
    $output = & $exe uninstall @flags 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw $output }
    if ($output -notmatch 'Final result: ([^\r\n]+)') { throw "Missing worker receipt: $output" }
    $receipt = $Matches[1].Trim()
    try {
      for ($i = 0; $i -lt 100; $i++) {
        $status = (Get-Content -LiteralPath $receipt -Raw).Trim()
        if ($status -eq 'complete') { break }
        if ($status.StartsWith('failed:')) { throw $status }
        Start-Sleep -Milliseconds 100
      }
      if ($status -ne 'complete') { throw 'Self-delete did not complete within 10 seconds' }
      if (Test-Path -LiteralPath $exe) { throw 'Executable remains after uninstall' }
      if ((Test-Path -LiteralPath $config) -ne $keep) { throw 'Configuration choice was not honored' }
    } finally { Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue }
  }
  Write-Host 'Windows CLI uninstall and executable self-deletion passed'
} finally {
  $env:USERPROFILE = $originalProfile
  $env:VIBEGUARD_CONFIG = $originalConfig
  $env:VIBEGUARD_LANG = $originalLanguage
  Remove-Item -LiteralPath $base -Recurse -Force
}
