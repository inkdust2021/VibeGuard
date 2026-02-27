# VibeGuard CLI 命令参考

> 提示：`vibeguard`（无参数）默认显示帮助。  
> `vibeguard start` 默认后台启动；前台调试请加 `--foreground`。  
> 全局参数：`-c, --config` 指定配置文件（默认 `~/.vibeguard/config.yaml`）。

## 1) 启动代理（默认后台）

```bash
vibeguard start [--foreground] [-c PATH]
```

- 默认：后台启动（优先使用已安装的自启服务；否则自动拉起后台进程）。
- `--foreground`：以前台方式运行（适合调试/作为系统服务的 ExecStart）。

## 2) 停止代理（后台服务/进程）

```bash
vibeguard stop [-c PATH]
```

## 3) 仅对某个程序启用代理（不影响当前终端）

Claude Code：

```bash
vibeguard claude [args...]
```

Codex：

```bash
vibeguard codex [args...]
```

Gemini：

```bash
vibeguard gemini [args...]
```

OpenCode：

```bash
vibeguard opencode [args...]
```

Qwen：

```bash
vibeguard qwen [args...]
```

任意命令：

```bash
vibeguard run <command> [args...]
```

## 4) 初始化向导

```bash
vibeguard init [-c PATH]
```

- 交互式生成 `~/.vibeguard/config.yaml` 与 CA（可选），并可引导安装信任证书。

## 5) 安装信任证书（MITM 必需）

```bash
vibeguard trust --mode system|user|auto [-c PATH]
```

- `system`：系统信任库（macOS/Linux 可能需要 `sudo`；Windows 需要管理员）。
- `user`：用户信任库（部分 CLI/应用可能仍不信任）。
- `auto`：自动选择（平台相关）。

## 6) 测试脱敏规则

```bash
vibeguard test [pattern] [text] [-c PATH]
```

- `pattern` 仅按“关键词包含”处理（精确子串匹配）。

示例：

```bash
vibeguard test "张刘耀" "我是清华大学的张刘耀"
```

## 7) 查看版本信息

```bash
vibeguard version
```

## 8) 生成 Shell 自动补全

```bash
vibeguard completion bash|zsh|fish|powershell [--no-descriptions]
```

说明：

```bash
vibeguard completion bash --help
vibeguard completion zsh --help
vibeguard completion fish --help
vibeguard completion powershell --help
```

## 9) 查看帮助

```bash
vibeguard --help
vibeguard help [command]
vibeguard [command] --help
```
