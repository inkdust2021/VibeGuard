# VibeGuard MCP Server 使用指南

VibeGuard 内置 MCP（Model Context Protocol）Server，让 Claude Code 等 AI 客户端能够直接查询代理状态、检测敏感信息、预览脱敏效果以及管理规则。

> 本文档面向使用者；想了解开发细节请阅读 `internal/mcp/` 源码与 `cmd/vibeguard/e2e_test.go`。

---

## 1. 协议与端点

- **协议**：JSON-RPC 2.0（[Streamable HTTP](https://modelcontextprotocol.io/) 风格）
- **路径**：`POST /mcp`（与代理监听同一端口，默认 `127.0.0.1:28657`）
- **完整 URL**：`http://127.0.0.1:28657/mcp`
- **方法限制**：仅支持 `POST`，其他方法返回 `405 Method Not Allowed`

---

## 2. 认证

- 强制 **Bearer Token** 认证。
- VibeGuard 启动时自动生成随机 token，写入 `~/.vibeguard/mcp_token`（权限 `0600`）。
- 请求需要带头：

  ```http
  Authorization: Bearer <token>
  ```

- 缺失或错误的 token 一律返回 `401 Unauthorized`。
- token 持久化在用户目录中，重启 VibeGuard 不会变化；如需轮换可手动删除该文件后重启。

---

## 3. 一键生成客户端配置

VibeGuard 提供 CLI 子命令快速输出 Claude Code 可用的配置：

```bash
# 输出 JSON（默认）
vibeguard mcp setup

# 输出环境变量格式（适合 export 注入）
vibeguard mcp setup --format env
```

### 3.1 JSON 输出示例

```json
{
  "mcpServers": {
    "vibeguard": {
      "url": "http://127.0.0.1:28657/mcp",
      "headers": {
        "Authorization": "Bearer <自动生成的 token>"
      }
    }
  }
}
```

将该 JSON 片段合并到 Claude Code 的 MCP 配置文件即可（位置以官方文档为准）。

### 3.2 env 输出示例

```bash
VG_MCP_URL=http://127.0.0.1:28657/mcp
VG_MCP_TOKEN=<自动生成的 token>
```

> 前提：`vibeguard start` 已经成功运行至少一次（用以生成 token）。

---

## 4. 工具清单（Phase 1）

当前共注册 **5 个工具**，全部为只读，不会修改运行时状态。

| 工具名 | 用途 |
|--------|------|
| `get_proxy_status` | 查询代理运行状态、版本、统计计数、监听地址等 |
| `detect_sensitive` | 只读检测：返回命中规则列表，**不会** 生成占位符或注册到 session/WAL |
| `preview_redacted` | 预览脱敏效果，返回 `__VG_<CATEGORY>_PREVIEW__` 临时占位符（不持久化） |
| `list_keywords` | 查询当前加载的关键词规则（来源：用户配置 / 内置 / engine） |
| `list_rule_lists` | 查询启用的规则列表（rule lists）及其元数据 |

### 4.1 `get_proxy_status`

**参数**：无。

**返回字段**（JSON 文本）：

| 字段 | 含义 |
|------|------|
| `version` | VibeGuard 版本号 |
| `started_at` | 启动时间（RFC3339） |
| `uptime` | 运行时长 |
| `total_requests` | 处理总请求数 |
| `redacted_count` | 已脱敏请求数 |
| `restored_count` | 已还原响应数 |
| `errors` | 错误计数 |
| `intercept_mode` | 拦截模式（`global` / `selective`） |
| `websocket_beta` | WebSocket 脱敏 Beta 是否启用 |
| `listen_address` | 代理监听地址 |

### 4.2 `detect_sensitive`

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `text` | string | 是 | 待检测文本 |
| `include_originals` | bool | 否 | 是否在结果中暴露原始命中值（默认 `false`） |

**返回**：

```json
{
  "has_sensitive": true,
  "match_count": 1,
  "matches": [
    {
      "category": "TEST",
      "start": 14,
      "end": 26
      // include_originals=true 时才出现 "original": "topsecret123"
    }
  ]
}
```

> ⚠️ `detect_sensitive` 与 `preview_redacted` 仅在代理走 **raw Engine 模式** 时可用。如果启用了 NER 或 pipeline 模式，会返回 `-32001 Detection unavailable` 错误。

### 4.3 `preview_redacted`

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `text` | string | 是 | 待预览脱敏的文本 |

**返回**：

```json
{
  "redacted_text": "leak: __VG_TEST_PREVIEW__ here",
  "match_count": 1
}
```

占位符只用于本次预览，**不会** 写入 session 或 WAL。

### 4.4 `list_keywords`

返回所有已加载关键词，附带来源（`user` / `builtin` / `engine`）：

```json
{
  "count": 2,
  "keywords": [
    {"keyword": "topsecret", "category": "TEST", "source": "user"},
    {"keyword": "email",     "category": "EMAIL","source": "engine"}
  ]
}
```

### 4.5 `list_rule_lists`

```json
{
  "count": 1,
  "rule_lists": [
    {"id": "vibeguard-default", "name": "VibeGuard Default", "enabled": true, "source": "subscribed"}
  ]
}
```

`source` 取值：

- `subscribed`：远程订阅
- `local`：本地文件

---

## 5. 错误码

遵循 JSON-RPC 2.0 规范，业务错误使用 `-32000` 起的私有区段：

| 错误码 | 含义 |
|--------|------|
| `-32700` | Parse error（请求体不是合法 JSON） |
| `-32600` | Invalid Request |
| `-32601` | Method not found / Tool not found |
| `-32602` | Invalid params（如缺少必填字段、tool name 为空） |
| `-32603` | Internal error |
| `-32001` | Detection unavailable（代理处于 NER/pipeline 模式，无法 Detect） |

错误响应示例：

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "text is required"
  },
  "id": 1
}
```

---

## 6. 端到端调用示例

### 6.1 初始化握手

```bash
TOKEN=$(cat ~/.vibeguard/mcp_token)

curl -sS -X POST http://127.0.0.1:28657/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1}' | jq
```

返回：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "vibeguard", "version": "..."}
  }
}
```

### 6.2 列出工具

```bash
curl -sS -X POST http://127.0.0.1:28657/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}' | jq
```

### 6.3 调用工具

```bash
curl -sS -X POST http://127.0.0.1:28657/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"detect_sensitive",
      "arguments":{"text":"this contains topsecret123 keyword"}
    },
    "id":3
  }' | jq
```

工具响应统一通过 `result.content[0].text` 返回 JSON 字符串，需要再 `JSON.parse` 一次。

---

## 7. Claude Code 集成步骤

1. 启动 VibeGuard：`vibeguard start --foreground`（或后台启动）。
2. 生成配置：`vibeguard mcp setup > vibeguard.mcp.json`。
3. 把 `mcpServers.vibeguard` 段合并到 Claude Code 的 MCP 配置文件。
4. 重启 Claude Code，输入 `/mcp` 应能看到 `vibeguard` 服务器及其 5 个工具。
5. 直接在对话中要求 Claude 调用工具，例如：

   > "用 vibeguard 检测下这段日志里有没有敏感信息：…"

---

## 8. 注意事项

- **detect / preview 需要 raw Engine**：若你启用了 `patterns.ner.enabled: true` 或大量 rule_lists 走 pipeline 模式，这两个工具会拒绝服务。可暂时关闭 NER 或减少 rule lists。
- **token 安全**：`~/.vibeguard/mcp_token` 是明文，请勿提交到 git；CI / 容器场景建议挂载只读 secret。
- **端口冲突**：MCP 复用代理监听端口；修改 `proxy.listen` 后记得重新生成 `vibeguard mcp setup` 输出。
- **跨主机访问**：默认绑定 `127.0.0.1`。如需跨机访问，请自行处理 TLS / 反向代理 / 防火墙，**不要** 把 token 直接暴露到公网。
- **Phase 2 工具**：管理/控制类工具（如重载配置、新增关键词、注销 session）尚未实现，Roadmap 中规划。

---

## 9. 相关代码位置

| 模块 | 路径 |
|------|------|
| MCP Server 核心 | `internal/mcp/server.go` |
| 工具实现 | `internal/mcp/tools.go` |
| Bearer 认证 | `internal/mcp/auth.go` |
| CLI `mcp setup` | `cmd/vibeguard/main.go`（搜索 `runMcpSetup`） |
| 单元测试 | `internal/mcp/server_test.go` |
| E2E 测试 | `cmd/vibeguard/e2e_test.go` |

---

## 10. 故障排查

| 现象 | 可能原因 | 解决方案 |
|------|----------|----------|
| `401 Unauthorized` | token 缺失或不正确 | 检查 `Authorization: Bearer ...` 头；重新读取 `~/.vibeguard/mcp_token` |
| `405 Method Not Allowed` | 用了 GET | 必须 `POST /mcp` |
| `-32700 Parse error` | 请求体非 JSON | 检查 Content-Type 与 body |
| `-32601 Tool not found` | 工具名拼错 | 通过 `tools/list` 校对 |
| `-32001 Detection unavailable` | 代理走 NER/pipeline 模式 | 关闭 NER / 减少 rule_lists，或仅使用 `get_proxy_status` 等不依赖 Engine 的工具 |
| `vibeguard mcp setup` 报无法读取 token | VibeGuard 还没启动过 | 先 `vibeguard start` 一次让 token 生成 |
