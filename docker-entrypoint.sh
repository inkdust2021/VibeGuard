#!/usr/bin/env sh
set -eu

cfg_dir="${HOME:-/root}/.vibeguard"
cfg_path="${cfg_dir}/config.yaml"

mkdir -p "${cfg_dir}"

if [ ! -f "${cfg_path}" ]; then
  cat >"${cfg_path}" <<'YAML'
# VibeGuard Docker default configuration
# - Note: the container must listen on 0.0.0.0; restrict exposure on the host via port mapping (recommended: bind to 127.0.0.1 only)
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

cleanup:
  log:
    enabled: true
    interval: 24h
    max_size_mb: 10
    max_backups: 3
  session_wal:
    enabled: true
    interval: 1h

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
  builtin: []
  exclude: []
YAML
fi

exec /usr/local/bin/vibeguard "$@"
