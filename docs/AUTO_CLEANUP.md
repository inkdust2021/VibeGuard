# 自动清理 / Automatic cleanup

在管理页面 `/manager/#/settings` 的“自动清理”中，可以分别设置运行日志和会话持久化文件的开关与清理周期。保存后通过配置热加载生效，无需重启。也可以编辑全局 `~/.vibeguard/config.yaml`（或 `VIBEGUARD_CONFIG` 指定的文件）：

```yaml
cleanup:
  log:
    enabled: true
    interval: 24h
    max_size_mb: 10
    max_backups: 3
  session_wal:
    enabled: true
    interval: 1h
```

旧配置省略这些字段时使用以上默认值。项目 `.vibeguard.yaml` 中同名字段覆盖全局配置；支持仅覆盖部分字段和显式 `enabled: false`。管理页面保存到全局配置，若项目有对应覆盖，应在项目配置中修改。

周期支持 Go duration（如 `30m`、`1h`、`24h`）和整数天（如 `7d`），最短 `1m`。周期按进程运行时间计算，每分钟检查一次，到期执行可能有不足一分钟的延迟。修改开关或周期会重新计时；重启也会重新计时。这里的周期不是每日固定时刻。

## 运行日志

达到清理周期或下一条日志会使文件超过 `max_size_mb` 时，当前文件轮转成 `.1`，旧备份依次移动为 `.2`、`.3` 等；超出 `max_backups` 的备份自动删除。当前日志路径不变，管理页继续读取新文件。仅删除该日志对应的数字备份，不删除其他文件。

`max_size_mb` 单位是 MiB（1024 × 1024 字节），范围 1–1024；备份数量范围 1–100。默认正常写入下，当前文件加备份最多约 40 MiB。升级前已存在的超大文件会作为一个备份保存，其体积不会被重新切分，之后随备份轮换删除。超过文件上限的单条日志不会写入日志文件。

`enabled: false` 同时关闭周期轮转、大小轮转和备份删除，恢复持续追加。降低日志级别不能代替清理。

## 会话 WAL

当 `session.wal_enabled` 开启时，WAL 默认每小时压缩；服务启动恢复会话后也压缩一次（仅在自动清理开启时）。压缩只保留内存中尚未过期的有效映射，因此同时移除已过期和因 `session.max_mappings` 被淘汰的记录。`session.ttl` 决定映射有效期，清理周期只决定多久整理一次磁盘文件，不延长或缩短 TTL。

压缩写入同目录的临时文件，使用原有 AES-GCM 加密格式及 `0600` 权限，完成同步后替换旧文件；失败时保留旧 WAL。写入、手动清空和压缩串行执行，避免并发清理丢失新映射。压缩期间映射操作会短暂等待磁盘写入完成。

如果启动时 WAL 无法读取、部分损坏或无法解密，会恢复其中可读取的有效记录并保留原文件；为避免覆盖尚未恢复的历史，本进程暂停 WAL 持久化和自动压缩，日志会提示。修复文件或密钥后重启服务。

`enabled: false` 关闭自动磁盘压缩，内存映射仍正常过期，WAL 会持续追加。手动清空会话仍会删除 WAL。开启压缩限制的是历史积累，不是固定字节上限；两个清理周期之间文件仍可增长。

SQLite 审计数据库沿用现有 `audit_db.enabled` 与 `audit_db.retention`，本次不改变其策略。

## English

Open `/manager/#/settings` to independently enable/disable runtime log rotation and session WAL compaction, set intervals, and choose the log size and backup count. The YAML above shows defaults, also applied to existing configurations. Changes use the existing config hot reload. Explicit project overrides take precedence over the global configuration edited by the UI.

Intervals accept Go durations and whole days, with a minimum of one minute. They count process running time and are checked every minute, rather than running at a fixed clock time. Changing a switch/interval or restarting resets its timer.

Log rotation runs on either size or time and retains numbered backups. With defaults, new logs occupy approximately 40 MiB including the active file; pre-existing oversized files are retained as a backup until aged out by subsequent rotations. A single entry larger than the configured limit is rejected from the file. Disabling log cleanup disables both rotation triggers and backup deletion.

WAL compaction retains only live, unexpired in-memory mappings and preserves their creation times, encryption, and private permissions. It runs periodically and once after startup restore when enabled. Writes, clear, and compaction are serialized; a synced temporary snapshot replaces the original, which is preserved on failure. The interval does not alter `session.ttl`. Disabling disk compaction leaves in-memory expiration active. WAL size can still grow between compactions; this is history retention, not a hard byte cap.

UI regression checks: `node scripts/test-cleanup-ui.cjs`. Startup preserves unreadable or partially restored WAL files and suspends persistence until the file/key is repaired and the service restarted. Valid records can still be recovered into memory.
