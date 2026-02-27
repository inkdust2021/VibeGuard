#!/usr/bin/env sh
set -eu

cfg_dir="${HOME:-/root}/.vibeguard"
cfg_path="${cfg_dir}/config.yaml"

mkdir -p "${cfg_dir}"

if [ ! -f "${cfg_path}" ]; then
  cat >"${cfg_path}" <<'YAML'
# VibeGuard Docker 默认配置
# - 注意：容器内必须监听 0.0.0.0，宿主机再用端口映射限制暴露范围（建议只映射到 127.0.0.1）
proxy:
  listen: 0.0.0.0:28657
  placeholder_prefix: "__VG_"
  intercept_mode: global

session:
  ttl: 1h
  max_mappings: 100000

log:
  file: "~/.vibeguard/vibeguard.log"
  level: info
  redact_log: true

targets:
  - host: api.anthropic.com
    enabled: true
  - host: api.openai.com
    enabled: true
  - host: api2.cursor.sh
    enabled: true
  - host: generativelanguage.googleapis.com
    enabled: true

patterns:
  keywords: []
  regex: []
  builtin: ["china_id", "china_phone", "email", "uuid"]
  exclude: []
YAML
fi

exec /usr/local/bin/vibeguard "$@"

