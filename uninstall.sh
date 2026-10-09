#!/usr/bin/env bash
set -euo pipefail

# VibeGuard uninstaller script (bilingual strings; comments in English)
#
# What it removes by default:
# - Try to stop background proxy
# - Remove autostart (macOS LaunchAgent / Linux systemd --user)
# - Remove vibeguard binary in install dir
# - Remove blocks injected into shell rc by install.sh (PATH/PROXY/SHELL)
#
# Optional:
# - --purge: remove ~/.vibeguard (config/certs/logs/WAL)

SCRIPT_LANG=""     # zh|en
SCRIPT_LANG_SET="0"
LANG_FROM_FILE="0"

INSTALL_DIR="${HOME:-}/.local/bin"
PURGE="0"
KEEP_CONFIG="0"
YES="0"
NON_INTERACTIVE="0"
CONFIG_FILE="${VIBEGUARD_CONFIG:-${HOME:-}/.vibeguard/config.yaml}"
DOCKER_CLEANUP="0"
DOCKER_VOLUME_CLEANUP="0"

to_lower() { echo "${1:-}" | tr '[:upper:]' '[:lower:]'; }

normalize_lang() {
  local v
  v="$(to_lower "${1:-}")"
  case "${v}" in
    zh|zh-cn|zh_cn|cn|chinese|中文) echo "zh" ;;
    en|en-us|en_us|english) echo "en" ;;
    *) echo "" ;;
  esac
}

t() {
  # Usage: t "Chinese" "English"
  if [[ "${SCRIPT_LANG}" == "zh" ]]; then
    printf "%s" "$1"
  else
    printf "%s" "$2"
  fi
}

say() {
  echo ""
  echo "==> $(t "$1" "$2")"
}

warn() {
  echo ""
  echo "$(t "警告：$1" "Warning: $2")" >&2
}

die() {
  echo ""
  echo "$(t "错误：$1" "Error: $2")" >&2
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

is_tty() { [[ -t 0 && -t 1 ]]; }

detect_listen_from_config() {
  local cfg="${1:-}"
  [[ -f "${cfg}" ]] || return 1
  awk '
    /^[[:space:]]*proxy:[[:space:]]*$/ { inproxy=1; next }
    inproxy && /^[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*$/ { inproxy=0 }
    inproxy && /^[[:space:]]*listen:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*listen:[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*/, "", line)
      gsub(/^["'\'']/, "", line)
      gsub(/["'\'']$/, "", line)
      print line
      exit
    }
  ' "${cfg}"
}

proxy_hostport_from_listen() {
  local listen="${1:-}"
  listen="$(echo "${listen}" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [[ -z "${listen}" ]]; then
    echo "127.0.0.1:28657"
    return 0
  fi

  # Common: 0.0.0.0:28657 -> 127.0.0.1:28657 (more reasonable for clients)
  if [[ "${listen}" == 0.0.0.0:* ]]; then
    echo "127.0.0.1:${listen#0.0.0.0:}"
    return 0
  fi
  # Port-only form: :28657
  if [[ "${listen}" == :* ]]; then
    echo "127.0.0.1${listen}"
    return 0
  fi
  echo "${listen}"
}

proxy_hostport_for_client() {
  local listen
  listen="$(detect_listen_from_config "${CONFIG_FILE}" || true)"
  proxy_hostport_from_listen "${listen}"
}

untrust_darwin() {
  local ca_cert="${1}"
  [[ -f "${ca_cert}" ]] || return 0
  have security && have openssl || return 1

  local sha256
  sha256="$(openssl x509 -in "${ca_cert}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')" || return 1
  [[ -n "${sha256}" ]] || return 1

  local user_args=()
  if [[ -f "${HOME}/Library/Keychains/login.keychain-db" ]]; then
    user_args=("${HOME}/Library/Keychains/login.keychain-db")
  elif [[ -f "${HOME}/Library/Keychains/login.keychain" ]]; then
    user_args=("${HOME}/Library/Keychains/login.keychain")
  fi
  local system_kc="/Library/Keychains/System.keychain"
  local user_certs system_certs
  user_certs="$(security find-certificate -a -Z ${user_args[@]+"${user_args[@]}"} 2>/dev/null)" || return 1
  system_certs="$(security find-certificate -a -Z "${system_kc}" 2>/dev/null)" || return 1

  if [[ "${user_certs}" == *"SHA-256 hash: ${sha256}"* ]]; then
    security remove-trusted-cert "${ca_cert}" >/dev/null 2>&1 || return 1
    security delete-certificate -Z "${sha256}" -t ${user_args[@]+"${user_args[@]}"} >/dev/null 2>&1 || return 1
  fi
  if [[ "${system_certs}" == *"SHA-256 hash: ${sha256}"* ]]; then
    # Noninteractive runs may use existing sudo authorization, but never prompt.
    local sudo_args=()
    if [[ "${NON_INTERACTIVE}" == "1" ]] || ! is_tty; then sudo_args=(-n); fi
    sudo ${sudo_args[@]+"${sudo_args[@]}"} security remove-trusted-cert -d "${ca_cert}" >/dev/null 2>&1 || return 1
    sudo ${sudo_args[@]+"${sudo_args[@]}"} security delete-certificate -Z "${sha256}" "${system_kc}" >/dev/null 2>&1 || return 1
  fi
  user_certs="$(security find-certificate -a -Z ${user_args[@]+"${user_args[@]}"} 2>/dev/null)" || return 1
  system_certs="$(security find-certificate -a -Z "${system_kc}" 2>/dev/null)" || return 1
  [[ "${user_certs}" != *"SHA-256 hash: ${sha256}"* && "${system_certs}" != *"SHA-256 hash: ${sha256}"* ]]
}

untrust_linux() {
  # Linux trust store locations vary; best-effort cleanup based on common vibeguard trust paths.
  local found="0"
  local paths=(
    "/usr/local/share/ca-certificates/vibeguard-ca.crt"
    "/etc/ssl/certs/vibeguard-ca.crt"
    "/etc/ssl/certs/vibeguard-ca.pem"
    "/etc/pki/ca-trust/source/anchors/vibeguard-ca.crt"
  )

  local p
  for p in "${paths[@]}"; do
    if [[ -f "${p}" ]]; then
      found="1"
      rm -f "${p}" >/dev/null 2>&1 || sudo -n rm -f "${p}" >/dev/null 2>&1 || return 1
    fi
  done

  if [[ "${found}" != "1" && ! -f "${HOME}/.vibeguard/ca.crt" && ! -f "${HOME}/.vibeguard/vibeguard-docker-ca.crt" ]]; then
    return 0
  fi

  if have update-ca-certificates; then
    update-ca-certificates >/dev/null 2>&1 || sudo -n update-ca-certificates >/dev/null 2>&1 || return 1
  elif have update-ca-trust; then
    update-ca-trust extract >/dev/null 2>&1 || sudo -n update-ca-trust extract >/dev/null 2>&1 || return 1
  else
    return 1
  fi
  for p in "${paths[@]}"; do
    if [[ -f "${p}" ]]; then
      return 1
    fi
  done
  return 0
}

untrust_ca() {
  local os_name
  os_name="$(uname -s || true)"
  case "${os_name}" in
    Darwin)
      untrust_darwin "${HOME}/.vibeguard/ca.crt" && untrust_darwin "${HOME}/.vibeguard/vibeguard-docker-ca.crt"
      ;;
    Linux)
      untrust_linux
      ;;
    *)
      return 1
      ;;
  esac
}

expand_user_path() {
  local p="${1:-}"
  if [[ -z "${HOME:-}" ]]; then
    echo "${p}"
    return
  fi
  case "${p}" in
    "~") echo "${HOME}" ;;
    "~/"*) echo "${HOME}/${p#~/}" ;;
    *) echo "${p}" ;;
  esac
}

backup_file() {
  local f="${1:-}"
  [[ -f "${f}" ]] || return 0
  local ts
  ts="$(date +%Y%m%d%H%M%S)"
  cp -p "${f}" "${f}.vibeguard.bak.${ts}" >/dev/null 2>&1 || true
}

remove_vibeguard_blocks_in_rc() {
  local f="${1:-}"
  [[ -f "${f}" ]] || return 0

  # Only modify the file if markers exist.
  if ! grep -Fqs "# VibeGuard " "${f}"; then
    return 0
  fi

  local tmp
  tmp="$(mktemp "${f}.vibeguard-clean.XXXXXX")"

  awk '
    BEGIN { skip=0; mode="" }

    $0=="# VibeGuard PATH"  { skip=1; mode="path"; next }
    $0=="# VibeGuard PROXY" { skip=1; mode="proxy"; next }
    $0=="# VibeGuard SHELL" { skip=1; mode="shell"; next }

    skip==1 && mode=="path" { skip=0; mode=""; next } # PATH block always has exactly one export line

    skip==1 && mode=="proxy" {
      if ($0 ~ /^#/ ) { next }
      if ($0 ~ /^export (HTTPS_PROXY|HTTP_PROXY|https_proxy|http_proxy|NO_PROXY|no_proxy)=/ ) { next }
      skip=0; mode=""
    }

    skip==1 && mode=="shell" {
      if ($0 ~ /^}[[:space:]]*$/ ) { skip=0; mode=""; next }
      next
    }

    { print }
  ' "${f}" >"${tmp}"

  if ! cmp -s "${f}" "${tmp}"; then
    backup_file "${f}"
    cat "${tmp}" >"${f}"
    rm -f "${tmp}"
    echo "$(t "已清理 rc：${f}" "Updated rc: ${f}")"
  else
    rm -f "${tmp}"
  fi
}

stop_vibeguard_pid() {
  local pid="${1:-}" comm
  [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || return 0
  [[ "${pid}" != "${VIBEGUARD_UNINSTALL_PID:-}" ]] || return 0
  comm="$(ps -p "${pid}" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' || true)"
  # A stale PID must never stop an unrelated process.
  [[ "${comm##*/}" == "vibeguard" ]] || return 0
  if ! kill -TERM "${pid}" 2>/dev/null; then
    if ps -p "${pid}" -o comm= >/dev/null 2>&1; then
      die "无法停止 VibeGuard 进程：${pid}；请检查权限" "Could not stop VibeGuard process: ${pid}; check permissions"
    fi
    return 0
  fi
  local i
  for i in {1..20}; do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || true
  for i in {1..20}; do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.1
  done
  die "无法停止 VibeGuard 进程：${pid}" "Could not stop VibeGuard process: ${pid}"
}

stop_proxy_best_effort() {
  local pid_file="${HOME}/.vibeguard/vibeguard.pid"
  if [[ -f "${pid_file}" ]]; then
    stop_vibeguard_pid "$(tr -d '[:space:]' <"${pid_file}")"
    rm -f "${pid_file}"
  fi
  # Also find this installation's proxies when a PID file was lost and lsof is absent.
  local pid comm exe_dir installed_dir
  installed_dir="$(cd "${INSTALL_DIR}" 2>/dev/null && pwd -P)" || installed_dir=""
  while read -r pid comm; do
    [[ "${pid}" != "${VIBEGUARD_UNINSTALL_PID:-}" && "${comm##*/}" == "vibeguard" ]] || continue
    if [[ -e "/proc/${pid}/exe" ]]; then
      comm="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
    fi
    [[ "${comm}" == /* ]] || continue
    exe_dir="$(cd "$(dirname "${comm}")" 2>/dev/null && pwd -P)" || continue
    [[ "${exe_dir}" == "${installed_dir}" ]] || continue
    stop_vibeguard_pid "${pid}"
  done < <(ps -ax -o pid= -o comm=)
  # Foreground proxies have no PID file; only stop VibeGuard listeners.
  have lsof || return 0
  local hostport
  hostport="$(proxy_hostport_for_client)"
  for pid in $(lsof -nP -iTCP:"${hostport##*:}" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 && $1=="vibeguard" {print $2}' | sort -u || true); do
    stop_vibeguard_pid "${pid}"
  done
}

remove_autostart_macos() {
  local label="com.vibeguard.proxy"
  local plist_path="${HOME}/Library/LaunchAgents/${label}.plist"
  if [[ ! -f "${plist_path}" ]]; then
    have launchctl || return 0
    local service="gui/$(id -u)/${label}"
    launchctl print "${service}" >/dev/null 2>&1 || return 0
    launchctl bootout "${service}" >/dev/null 2>&1 || die "无法移除 LaunchAgent" "Could not unload LaunchAgent"
    if launchctl print "${service}" >/dev/null 2>&1; then
      die "LaunchAgent 仍在运行" "LaunchAgent is still registered"
    fi
    return 0
  fi

  have launchctl || die "未找到 launchctl" "launchctl not found"
  if have launchctl; then
    local uid domain
    uid="$(id -u)"
    domain="gui/${uid}"
    if ! launchctl bootout "${domain}" "${plist_path}" >/dev/null 2>&1; then
      if launchctl print "${domain}/${label}" >/dev/null 2>&1; then
        die "无法移除 LaunchAgent" "Could not unload LaunchAgent"
      fi
    fi
    if launchctl print "${domain}/${label}" >/dev/null 2>&1; then
      die "LaunchAgent 仍在运行" "LaunchAgent is still registered"
    fi
  fi

  rm -f "${plist_path}"
  echo "$(t "已移除 LaunchAgent：${plist_path}" "Removed LaunchAgent: ${plist_path}")"
}

remove_autostart_linux() {
  local unit_path="${HOME}/.config/systemd/user/vibeguard.service"
  if [[ ! -f "${unit_path}" ]]; then
    local load_state="not-found" changed="0" link
    if have systemctl; then
      if ! load_state="$(systemctl --user show -p LoadState --value vibeguard.service 2>/dev/null)"; then
        local user_processes
        user_processes="$(ps -u "$(id -u)" -o args=)" || die "无法检查用户服务进程" "Could not check user service processes"
        if grep -Eq '(^|/)systemd --user([[:space:]]|$)' <<< "${user_processes}"; then
          die "无法检查 systemd 服务" "Could not check systemd service"
        fi
        # Detached/container installs may have systemctl but no user manager.
        load_state="not-found"
      fi
      if [[ "${load_state}" != "not-found" ]]; then
        systemctl --user stop vibeguard.service >/dev/null 2>&1 || die "无法停止 systemd 服务" "Could not stop systemd service"
        changed="1"
      fi
    fi
    # A removed unit file can leave a broken enablement symlink behind.
    for link in "${HOME}/.config/systemd/user/"*.wants/vibeguard.service; do
      if [[ -L "${link}" ]]; then
        rm -f "${link}"
        changed="1"
      fi
    done
    if [[ "${changed}" == "1" ]]; then
      systemctl --user daemon-reload >/dev/null 2>&1 || die "无法重载 systemd" "Could not reload systemd"
    fi
    return 0
  fi

  have systemctl || die "未找到 systemctl" "systemctl not found"
  if have systemctl; then
    systemctl --user disable --now vibeguard.service >/dev/null 2>&1 || die "无法停止 systemd 服务" "Could not disable systemd service"
  fi

  rm -f "${unit_path}"
  systemctl --user daemon-reload >/dev/null 2>&1 || die "无法重载 systemd" "Could not reload systemd"
  echo "$(t "已移除 systemd 用户服务：${unit_path}" "Removed systemd user service: ${unit_path}")"
}

remove_installed_binary() {
  local bin_path="${INSTALL_DIR}/vibeguard"
  if [[ -f "${bin_path}" || -L "${bin_path}" ]]; then
    rm -f "${bin_path}"
    echo "$(t "已删除二进制：${bin_path}" "Removed binary: ${bin_path}")"
  else
    echo "$(t "未在安装目录找到二进制：${bin_path}" "Binary not found in install dir: ${bin_path}")"
  fi
}

cleanup_docker() {
  local container_name="vibeguard"
  local volume_name="vibeguard-data"
  [[ "${DOCKER_CLEANUP}" == "1" ]] || return 0

  have docker || die "未找到 docker，无法清理 Docker 部署" "docker not found; cannot clean Docker deployment"
  docker info >/dev/null 2>&1 || die "Docker 不可用，保留配置供重试" "Docker unavailable; configuration preserved for retry"

  # Query both resources before changing either; query failures are not absence.
  local containers volumes=""
  containers="$(docker ps -a --format '{{.Names}}')" || die "无法查询 Docker 容器" "Could not query Docker containers"
  if [[ "${DOCKER_VOLUME_CLEANUP}" == "1" ]]; then
    volumes="$(docker volume ls --format '{{.Name}}')" || die "无法查询 Docker 数据卷" "Could not query Docker volumes"
  fi

  if grep -Fxq "${container_name}" <<< "${containers}"; then
    local remove_container="1" ans
    if [[ "${YES}" != "1" && "${NON_INTERACTIVE}" == "0" ]] && is_tty; then
      read -r -p "$(t "删除 Docker 容器（保留数据卷）？[y/N]: " "Remove Docker container (keep volume)? [y/N]: ")" ans
      [[ "${ans}" == "y" || "${ans}" == "Y" ]] || remove_container="0"
    fi
    if [[ "${remove_container}" == "1" ]]; then
      docker rm -f "${container_name}" >/dev/null || die "无法删除 Docker 容器；保留配置供重试" "Could not remove Docker container; configuration preserved for retry"
      echo "$(t "已删除 Docker 容器：${container_name}" "Removed Docker container: ${container_name}")"
    fi
  fi

  if [[ "${DOCKER_VOLUME_CLEANUP}" == "1" ]] && grep -Fxq "${volume_name}" <<< "${volumes}"; then
    if [[ "${YES}" != "1" && "${NON_INTERACTIVE}" == "0" ]] && is_tty; then
      read -r -p "$(t "删除数据卷及其中的密码、配置和 CA？[y/N]: " "Delete volume including password, configuration and CA? [y/N]: ")" ans
      [[ "${ans}" == "y" || "${ans}" == "Y" ]] || return 0
    fi
    docker volume rm "${volume_name}" >/dev/null || die "无法删除 Docker 数据卷；保留配置供重试" "Could not remove Docker volume; configuration preserved for retry"
    echo "$(t "已删除 Docker 数据卷：${volume_name}" "Removed Docker volume: ${volume_name}")"
  fi
}

purge_config_dir() {
  local cfg_dir="${HOME}/.vibeguard"
  [[ -d "${cfg_dir}" ]] || return 0

  if [[ "${YES}" != "1" && "${NON_INTERACTIVE}" == "1" ]]; then
    die "非交互模式下执行 --purge 需要同时带上 --yes" "In non-interactive mode, --purge requires --yes"
  fi

  if [[ "${YES}" != "1" && "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 ]]; then
    echo ""
    echo "⚠️ $(t "将删除目录：${cfg_dir}；其中包含 CA 私钥、日志、WAL 等" "This will delete: ${cfg_dir}; includes CA private key, logs, WAL, etc.")"
    read -r -p "$(t "确认删除？[y/N]: " "Confirm delete? [y/N]: ")" ans || true
    ans="${ans:-N}"
    if [[ "${ans}" != "Y" && "${ans}" != "y" ]]; then
      warn "已跳过 purge；保留 ~/.vibeguard" "Skipped purge; kept ~/.vibeguard"
      return 0
    fi
  fi

  rm -rf "${cfg_dir}"
  echo "$(t "已删除配置目录：${cfg_dir}" "Removed config dir: ${cfg_dir}")"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="${2:-}"; shift 2;;
    --docker)
      DOCKER_CLEANUP="1"; shift 1;;
    --docker-volume|--docker-volumes)
      DOCKER_CLEANUP="1"; DOCKER_VOLUME_CLEANUP="1"; shift 1;;
    --keep-config)
      KEEP_CONFIG="1"; shift 1;;
    --purge)
      PURGE="1"; shift 1;;
    --yes)
      YES="1"; shift 1;;
    --lang|--language)
      SCRIPT_LANG="${2:-}"; SCRIPT_LANG_SET="1"; shift 2;;
    --non-interactive)
      NON_INTERACTIVE="1"; shift 1;;
    -h|--help)
      cat <<'EOF'
VibeGuard 卸载脚本 / Uninstaller

参数 / Options:
  --dir DIR           安装目录 / Install dir (default: $HOME/.local/bin)
  --docker            清理 Docker 容器 vibeguard / Remove Docker container vibeguard
  --docker-volume     同时清理 Docker 数据卷 vibeguard-data（会丢失容器内配置与 CA） / Also remove vibeguard-data volume (loses config+CA)
  --keep-config       保留 ~/.vibeguard / Keep ~/.vibeguard
  --purge             删除 ~/.vibeguard：配置/证书/日志/WAL / Remove ~/.vibeguard
  --yes               跳过确认：配合 --purge/--docker-volume / Skip confirmations: for --purge/--docker-volume
  --lang LANG         zh|en (default: auto)
  --non-interactive   非交互模式 / Non-interactive

示例 / Examples:
  bash uninstall.sh
  bash uninstall.sh --docker
  bash uninstall.sh --docker --docker-volume
  bash uninstall.sh --purge
  bash uninstall.sh --purge --yes --non-interactive
EOF
      exit 0;;
    *)
      die "未知参数：$1" "Unknown option: $1";;
  esac
done

INSTALL_DIR="$(expand_user_path "${INSTALL_DIR}")"

if [[ "${SCRIPT_LANG_SET}" == "1" ]]; then
  SCRIPT_LANG="$(normalize_lang "${SCRIPT_LANG}")"
  [[ -n "${SCRIPT_LANG}" ]] || die "无效的 --lang：请用 zh 或 en" "Invalid --lang: use zh or en"
else
  SCRIPT_LANG="$(normalize_lang "${VIBEGUARD_LANG:-}")"
fi

if [[ -z "${SCRIPT_LANG}" && -n "${HOME:-}" && -f "${HOME}/.vibeguard/lang" ]]; then
  file_lang="$(tr -d '\r\n' <"${HOME}/.vibeguard/lang" 2>/dev/null || true)"
  SCRIPT_LANG="$(normalize_lang "${file_lang}")"
  if [[ -n "${SCRIPT_LANG}" ]]; then
    LANG_FROM_FILE="1"
  fi
fi

if [[ -z "${SCRIPT_LANG}" ]]; then
  loc="$(to_lower "${LC_ALL:-${LANG:-}}")"
  if [[ "${loc}" == zh* || "${loc}" == *zh* ]]; then
    SCRIPT_LANG="zh"
  else
    SCRIPT_LANG="en"
  fi
fi

if [[ "${SCRIPT_LANG_SET}" == "0" && -z "${VIBEGUARD_LANG:-}" && "${LANG_FROM_FILE}" != "1" && "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 ]]; then
  echo ""
  echo "请选择语言 / Choose language:"
  echo "  1) 中文"
  echo "  2) English"
  if [[ "${SCRIPT_LANG}" == "zh" ]]; then
    read -r -p "选择 [1]: " choice || true
    choice="${choice:-1}"
  else
    read -r -p "Choose [2]: " choice || true
    choice="${choice:-2}"
  fi
  case "${choice}" in
    1) SCRIPT_LANG="zh" ;;
    2) SCRIPT_LANG="en" ;;
    *) : ;;
  esac
fi

# Validate all destructive choices before removing anything.
[[ "${PURGE}" != "1" || "${KEEP_CONFIG}" != "1" ]] || die "--purge 与 --keep-config 不能同时使用" "--purge and --keep-config cannot be used together"
if [[ "${PURGE}" == "1" && "${YES}" != "1" ]]; then
  if [[ "${NON_INTERACTIVE}" == "1" ]] || ! is_tty; then
    die "删除配置需要 --purge --yes" "Deleting configuration requires --purge --yes"
  fi
  read -r -p "$(t "删除配置、证书私钥、日志和 WAL？[y/N]: " "Delete configuration, CA private key, logs and WAL? [y/N]: ")" ans
  [[ "${ans}" == "y" || "${ans}" == "Y" ]] || exit 1
  YES="1"
fi
if [[ "${DOCKER_CLEANUP}" == "1" && "${YES}" != "1" ]]; then
  if [[ "${NON_INTERACTIVE}" == "1" ]] || ! is_tty; then
    die "Docker 清理需要 --yes" "Docker cleanup requires --yes"
  fi
fi

say "开始卸载" "Starting uninstall"
say "安装目录：${INSTALL_DIR}" "Install dir: ${INSTALL_DIR}"

say "移除开机自启" "Removing autostart"
os_name="$(uname -s || true)"
case "${os_name}" in
  Darwin) remove_autostart_macos ;;
  Linux) remove_autostart_linux ;;
  *) : ;;
esac

say "停止后台代理" "Stopping proxy"
stop_proxy_best_effort

say "清理 Docker（可选）" "Cleaning Docker (optional)"
cleanup_docker

say "移除信任证书" "Removing trusted CA"
if ! untrust_ca; then
  die "无法确认 CA 信任已移除；保留程序和配置以便重试。请检查权限。" "Could not remove or verify CA trust; binary and configuration preserved for retry. Check permissions."
fi

say "清理 shell rc" "Cleaning shell rc"
rc_candidates=(
  "${HOME}/.zshrc"
  "${HOME}/.bash_profile"
  "${HOME}/.bashrc"
  "${HOME}/.profile"
)
for f in "${rc_candidates[@]}"; do
  remove_vibeguard_blocks_in_rc "${f}"
done

say "删除二进制" "Removing binary"
remove_installed_binary

if [[ "${PURGE}" == "1" ]]; then
  say "清理配置目录" "Purging config dir"
  purge_config_dir
else
  say "保留配置目录：${HOME}/.vibeguard（可用 --purge 删除）" "Keeping config dir: ${HOME}/.vibeguard (use --purge to remove)"
fi

say "卸载完成" "Uninstall complete"
