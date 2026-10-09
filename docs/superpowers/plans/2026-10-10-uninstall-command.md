# Uninstall Command Implementation Plan

> **For agentic workers:** Execute the authorized work in this session; request an independent code review before creating the PR.

**Goal:** Add an offline `vibeguard uninstall` command that asks users whether to retain configuration and does not claim completion when cleanup fails.

**Architecture:** Embed the existing Unix/Windows uninstall scripts in the binary, using one source of truth. Select keep/purge before making changes. Harden script cleanup and preserve CA material on trust-removal failures. Windows removes the running executable with a worker after the CLI exits and exposes its result.

**Tech Stack:** Go/Cobra, Bash, PowerShell, Python standard-library integration tests.

## Constraints

- Minimal changes; retain unrelated shell configuration and shared install directories.
- Never uninstall the developer's actual installation during testing.
- Noninteractive callers must explicitly select `--keep-config` or `--purge`; deleting data also requires `--yes`.
- Project overrides and files outside `~/.vibeguard` remain user-owned.

## Tasks

- [x] Add isolated integration tests (`scripts/test-uninstall.py`) for CLI help, explicit decisions before mutation, keep/purge, services, trust failures, binary deletion, shell preservation, unrelated PID protection and repeated cleanup. Run against the baseline binary to observe failures.
- [x] Add `uninstall_scripts.go` embed assets and `cmd/vibeguard/uninstall.go`; register the Cobra command in `main.go`. Forward the selected directory/config without shell interpolation.
- [x] Harden `uninstall.sh` and `uninstall.ps1`: validate destructive flags before cleanup, report failures, avoid unrelated processes, remove only installed blocks, and preserve cert/config when untrust fails. Test each failure with temporary files and command fixtures.
- [x] Document interactive choices, flags, platform cleanup and Windows deferred binary removal in both READMEs. Verify `go test ./...`, changed-package vet, full vet (report pre-existing issues), shell syntax, integration tests and Windows cross compilation.
- [x] Request independent review, resolve findings, commit and push `codex/uninstall-command`, create and attach a separate PR against `main`.

## Verification evidence

- `go test ./...`: passed.
- `go vet . ./cmd/vibeguard`, shell syntax, formatting and diff checks: passed.
- Unix isolated integration suite: 20 cases, including actual temporary proxy processes, stale/missing PID files, user config choices, service caches/symlinks, unavailable user manager, failed signals/trust queries/removal and repeated cleanup.
- PowerShell function fixtures, PEM thumbprint parsing and actual worker execution against a temporary synthetic binary: passed on temporary PowerShell 7.6.6 runtime.
- Darwin native build, Linux amd64 and Windows amd64/arm64 cross builds: passed. Windows locked executable removal will also be exercised by the added CI workflow.
- Independent reviewer approved after regression-backed fixes for failed signals and missing/cached service entries.
- Full `go vet ./...` still reports the existing `internal/wsproxy/transform_conn.go:117` ReadFrom signature warning; this PR does not change that package.

## Upstream references

Windows worker uses the documented detached Start-Process and process-handle waiting behavior; no external implementation is incorporated:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/wait-process?view=powershell-5.1

Temporary test runtime: official PowerShell v7.6.6 macOS arm64 binary distribution (MIT), outside the repository.
