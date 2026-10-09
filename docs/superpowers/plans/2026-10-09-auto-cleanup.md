# Automatic cleanup implementation plan

> Execute inline in the current session; the user has authorized implementation.

**Goal:** Bound runtime log storage and discard obsolete encrypted session WAL records, with independent user switches and intervals in YAML and the manager settings page.

**Architecture:** Add `cleanup.log` and `cleanup.session_wal` policies. Use a serialized file writer for size/time rotation with numbered backups. Rewrite the WAL from live in-memory mappings through a synced temporary file and rename, serializing registration, clear, and compaction. Keep existing session TTL semantics.

**Tech stack:** Go standard library, existing yaml.v3, existing embedded manager HTML/JavaScript.

## Constraints

- Defaults: log enabled, 24h, 10 MiB, 3 backups; WAL enabled, 1h.
- Accept positive durations of at least one minute, including day suffix (`7d`).
- Missing settings inherit defaults; explicit false works in global/project config.
- Disabled cleanup keeps append behavior. Do not delete valid session mappings.
- Runtime changes use existing config hot reload. Close the log cleanup worker on shutdown.
- Use synthetic data in deterministic tests; retain encryption and private WAL permissions.

## Task 1: Configuration and API

Files: `internal/config/cleanup.go`, `cleanup_test.go`, `config.go`; `internal/admin/api_settings.go`, `api_settings_test.go`.

- [x] Write tests for defaults, explicit disable, partial project overrides, invalid intervals, and API partial updates.
- [x] Run `go test ./internal/config ./internal/admin` and verify new behavior fails before implementation.
- [x] Implement nested policies, normalization/validation, field-wise overrides, and authenticated settings writes.
- [x] Run the tests again; confirm malformed updates leave stored config unchanged.

API shape:

```json
{"cleanup":{"log":{"enabled":true,"interval":"24h","max_size_mb":10,"max_backups":3},"session_wal":{"enabled":true,"interval":"1h"}}}
```

## Task 2: Storage lifecycle

Files: `internal/log/cleanup.go`, `cleanup_test.go`, `log.go`; `internal/session/wal.go`, `manager.go`, `cleanup_test.go`; `cmd/vibeguard/main.go`; `internal/proxy/proxy.go`; `internal/admin/api_logs.go`.

- [x] Write tests showing size/time rotation, disabled append, backup pruning, live policy changes, and continuing writes after rotation.
- [x] Write tests showing WAL compaction drops expired/evicted entries, preserves creation time and encrypted contents, permits further append/restore, and fails without damaging the previous WAL.
- [x] Verify the new tests fail, implement minimal serialized storage operations, then rerun.
- [x] Connect lifecycle and hot reload, and make the manager log stream recognize file replacement even when its size increases.
- [x] Run `go test -race ./internal/log ./internal/session ./internal/admin ./internal/config`.

## Task 3: Settings UI and documentation

Files: `internal/admin/static/index.html`, `docs/AUTO_CLEANUP.md`, `docs/README.md`.

- [x] Add bilingual enabled switches, interval inputs, log size/backup inputs, and Save to the existing settings page.
- [x] Describe defaults, disabled behavior, project override precedence, periodic scheduling, WAL TTL, and runtime changes.
- [x] Verify JavaScript syntax, exercise the settings page, and capture a screenshot.
- [x] Format changed Go files; run `go test ./...`, `go vet ./...`, and review the final diff.

## Research and reuse decision

Inspected [lumberjack v2](https://github.com/natefinch/lumberjack), [v2.2.1 MIT license](https://raw.githubusercontent.com/natefinch/lumberjack/v2.2.1/LICENSE), and its documented size rotation / backup retention API. MIT permits reuse. Its public configuration and persistent asynchronous backup worker would require additional lifecycle handling to support live changes safely. Use a small synchronous numbered-backup implementation instead, keeping file writes and live policy changes under one mutex and providing a stoppable timer. No external code or new dependency is incorporated. Validate against the existing append-only baseline through regression tests; there is no model/dataset/benchmark involved.

## Verification notes

Independent review found and regression tests now cover: preservation after failed/partial WAL restore, chronological snapshots when the next restart reduces mapping capacity, and settings responses after navigation. The preview server uses isolated temporary authentication/configuration, and its temporary fixture is removed after browser testing. Screenshot: `image/auto-cleanup-settings.jpg`.

`go vet ./...` reports a pre-existing `ReadFrom` signature issue in unchanged `internal/wsproxy/transform_conn.go:117`; do not change unrelated code.
