package vibeguard

import _ "embed"

// UninstallShell is the same script distributed to Unix users, bundled for offline use.
//
//go:embed uninstall.sh
var UninstallShell []byte

// UninstallPowerShell is the Windows uninstaller, bundled for offline use.
//
//go:embed uninstall.ps1
var UninstallPowerShell []byte
