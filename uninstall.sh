#!/usr/bin/env bash
set -euo pipefail

# VibeGuard 卸载脚本（中英双语） / VibeGuard uninstaller (ZH/EN)
#
# 默认会做什么 / What it removes by default:
# - 尝试停止后台代理 / Try to stop background proxy
# - 移除开机自启（macOS LaunchAgent / Linux systemd --user） / Remove autostart
# - 删除安装目录中的 vibeguard 二进制 / Remove vibeguard binary in install dir
# - 清理 shell rc 中由 install.sh 写入的区块（PATH/PROXY/SHELL） / Remove rc blocks inserted by install.sh
#
# 可选 / Optional:
# - --purge 删除 ~/.vibeguard（配置/证书/日志/WAL） / Remove ~/.vibeguard (config/certs/logs/WAL)

SCRIPT_LANG=""     # zh|en
SCRIPT_LANG_SET="0"
LANG_FROM_FILE="0"

INSTALL_DIR="${HOME:-}/.local/bin"
PURGE="0"
YES="0"
NON_INTERACTIVE="0"
CONFIG_FILE="${VIBEGUARD_CONFIG:-${HOME:-}/.vibeguard/config.yaml}"

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
  # 用法：t "中文" "English"
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

  # 常见：0.0.0.0:28657 -> 127.0.0.1:28657（给客户端用更合理）
  if [[ "${listen}" == 0.0.0.0:* ]]; then
    echo "127.0.0.1:${listen#0.0.0.0:}"
    return 0
  fi
  # 仅端口：:28657
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
  if ! have security; then
    return 1
  fi

  local ca_cert="${HOME}/.vibeguard/ca.crt"
  if [[ ! -f "${ca_cert}" ]]; then
    return 1
  fi

  if ! have openssl; then
    return 1
  fi

  local sha256
  sha256="$(openssl x509 -in "${ca_cert}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]' || true)"
  if [[ -z "${sha256}" ]]; then
    return 1
  fi

  local login_kc=""
  if [[ -n "${HOME:-}" ]]; then
    if [[ -f "${HOME}/Library/Keychains/login.keychain-db" ]]; then
      login_kc="${HOME}/Library/Keychains/login.keychain-db"
    elif [[ -f "${HOME}/Library/Keychains/login.keychain" ]]; then
      login_kc="${HOME}/Library/Keychains/login.keychain"
    fi
  fi

  local has_user="0"
  local has_system="0"
  if [[ -n "${login_kc}" ]]; then
    if security find-certificate -a -Z "${login_kc}" 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
      has_user="1"
    fi
  else
    if security find-certificate -a -Z 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
      has_user="1"
    fi
  fi
  if security find-certificate -a -Z "/Library/Keychains/System.keychain" 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
    has_system="1"
  fi

  if [[ "${has_user}" != "1" && "${has_system}" != "1" ]]; then
    return 0
  fi

  # 用户钥匙串（Login Keychain）
  if [[ "${has_user}" == "1" ]]; then
    if [[ -n "${login_kc}" ]]; then
      security delete-certificate -Z "${sha256}" -t "${login_kc}" >/dev/null 2>&1 || true
    else
      security delete-certificate -Z "${sha256}" -t >/dev/null 2>&1 || true
    fi
  fi

  # 系统钥匙串（System.keychain / admin trust store）
  if [[ "${has_system}" == "1" ]]; then
    if [[ "${NON_INTERACTIVE}" == "1" ]] || ! is_tty; then
      # 无法交互输入 sudo 密码：留给用户手动处理
      :
    else
      sudo security remove-trusted-cert -d "${ca_cert}" >/dev/null 2>&1 || true
      sudo security delete-certificate -Z "${sha256}" "/Library/Keychains/System.keychain" >/dev/null 2>&1 || true
    fi
  fi

  # 再次检查：仍存在则认为自动移除失败
  local still="0"
  if [[ -n "${login_kc}" ]]; then
    if security find-certificate -a -Z "${login_kc}" 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
      still="1"
    fi
  else
    if security find-certificate -a -Z 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
      still="1"
    fi
  fi
  if security find-certificate -a -Z "/Library/Keychains/System.keychain" 2>/dev/null | grep -Fq "SHA-256 hash: ${sha256}"; then
    still="1"
  fi
  [[ "${still}" == "1" ]] && return 1
  return 0
}

untrust_linux() {
  # Linux 信任库位置不统一：按 vibeguard trust 的常见写入位置做 best-effort 清理。
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
      rm -f "${p}" >/dev/null 2>&1 || sudo rm -f "${p}" >/dev/null 2>&1 || true
    fi
  done

  if [[ "${found}" != "1" ]]; then
    return 0
  fi

  if have update-ca-certificates; then
    update-ca-certificates >/dev/null 2>&1 || sudo update-ca-certificates >/dev/null 2>&1 || true
  elif have update-ca-trust; then
    update-ca-trust extract >/dev/null 2>&1 || sudo update-ca-trust extract >/dev/null 2>&1 || true
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
      untrust_darwin
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

  # 仅在存在 marker 时才改动文件
  if ! grep -Fqs "# VibeGuard " "${f}"; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"

  awk '
    BEGIN { skip=0; mode="" }

    $0=="# VibeGuard PATH"  { skip=1; mode="path"; next }
    $0=="# VibeGuard PROXY" { skip=1; mode="proxy"; next }
    $0=="# VibeGuard SHELL" { skip=1; mode="shell"; next }

    skip==1 && mode=="path" { skip=0; mode=""; next } # PATH 区块固定只有 1 行 export

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
    mv "${tmp}" "${f}"
    echo "$(t "已清理 rc：${f}" "Updated rc: ${f}")"
  else
    rm -f "${tmp}"
  fi
}

find_vg_bin() {
  local p=""

  if [[ -n "${INSTALL_DIR:-}" && -x "${INSTALL_DIR}/vibeguard" ]]; then
    echo "${INSTALL_DIR}/vibeguard"
    return 0
  fi

  # type -P 会忽略 shell function，优先返回可执行文件路径
  p="$(type -P vibeguard 2>/dev/null || true)"
  if [[ -n "${p}" && -x "${p}" ]]; then
    echo "${p}"
    return 0
  fi

  return 1
}

kill_vibeguard_listeners_on_port() {
  local hostport="${1:-}"
  local port=""
  if [[ -z "${hostport}" ]]; then
    hostport="127.0.0.1:28657"
  fi
  port="${hostport##*:}"
  if [[ -z "${port}" ]]; then
    return 0
  fi

  if ! have lsof; then
    warn "未找到 lsof：无法按端口自动定位进程；可手动执行：lsof -nP -iTCP:${port} -sTCP:LISTEN" "lsof not found; cannot resolve PID by port; run: lsof -nP -iTCP:${port} -sTCP:LISTEN"
    return 0
  fi

  # 只提取 COMMAND 为 vibeguard 的 PID，避免误杀其他进程。
  local pids
  pids="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 && $1=="vibeguard" {print $2}' | sort -u || true)"
  if [[ -z "${pids}" ]]; then
    # 端口仍被占用但不是 vibeguard：提示即可，不自动结束。
    local other
    other="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | awk 'NR==1{next} {print $1" "$2; exit}' || true)"
    if [[ -n "${other}" ]]; then
      warn "端口 ${port} 被其他进程占用：${other}；未自动结束" "Port ${port} is used by another process: ${other}; not killed"
    fi
    return 0
  fi

  local pid comm
  for pid in ${pids}; do
    comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    sleep 0.3 || true
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill -KILL "${pid}" >/dev/null 2>&1 || true
    fi
    echo "$(t "已结束监听进程：PID=${pid} cmd=${comm:-unknown}" "Killed listener: PID=${pid} cmd=${comm:-unknown}")"
  done
}

stop_proxy_best_effort() {
  local vg=""
  vg="$(find_vg_bin 2>/dev/null || true)"
  if [[ -n "${vg}" ]]; then
    "${vg}" stop >/dev/null 2>&1 || true
  fi

  # 退化：按 PID 文件杀进程（仅限未安装系统服务、但 detached 后台运行的场景）
  local pid_file="${HOME}/.vibeguard/vibeguard.pid"
  if [[ -f "${pid_file}" ]]; then
    local pid
    pid="$(tr -d '[:space:]' <"${pid_file}" || true)"
    if [[ "${pid}" =~ ^[0-9]+$ ]]; then
      kill -TERM "${pid}" >/dev/null 2>&1 || true
      sleep 0.3 || true
      kill -KILL "${pid}" >/dev/null 2>&1 || true
    fi
    rm -f "${pid_file}" >/dev/null 2>&1 || true
  fi

  # 最后兜底：按端口找到实际监听进程并结束（只杀 vibeguard）。
  kill_vibeguard_listeners_on_port "$(proxy_hostport_for_client)"
}

remove_autostart_macos() {
  local label="com.vibeguard.proxy"
  local plist_path="${HOME}/Library/LaunchAgents/${label}.plist"
  [[ -f "${plist_path}" ]] || return 0

  if have launchctl; then
    local uid domain
    uid="$(id -u)"
    domain="gui/${uid}"
    launchctl bootout "${domain}" "${plist_path}" >/dev/null 2>&1 || true
  fi

  rm -f "${plist_path}" >/dev/null 2>&1 || true
  echo "$(t "已移除 LaunchAgent：${plist_path}" "Removed LaunchAgent: ${plist_path}")"
}

remove_autostart_linux() {
  local unit_path="${HOME}/.config/systemd/user/vibeguard.service"
  [[ -f "${unit_path}" ]] || return 0

  if have systemctl; then
    systemctl --user disable --now vibeguard.service >/dev/null 2>&1 || true
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi

  rm -f "${unit_path}" >/dev/null 2>&1 || true
  echo "$(t "已移除 systemd 用户服务：${unit_path}" "Removed systemd user service: ${unit_path}")"
}

remove_installed_binary() {
  local bin_path="${INSTALL_DIR}/vibeguard"
  if [[ -f "${bin_path}" || -L "${bin_path}" ]]; then
    rm -f "${bin_path}" >/dev/null 2>&1 || true
    echo "$(t "已删除二进制：${bin_path}" "Removed binary: ${bin_path}")"
  else
    echo "$(t "未在安装目录找到二进制：${bin_path}" "Binary not found in install dir: ${bin_path}")"
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
  --purge             删除 ~/.vibeguard：配置/证书/日志/WAL / Remove ~/.vibeguard
  --yes               跳过确认：配合 --purge / Skip confirmations: for --purge
  --lang LANG         zh|en (default: auto)
  --non-interactive   非交互模式 / Non-interactive

示例 / Examples:
  bash uninstall.sh
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

untrust_ok="1"
say "移除信任证书" "Removing trusted CA"
if ! untrust_ca; then
  untrust_ok="0"
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
if [[ "${untrust_ok}" != "1" ]]; then
  echo ""
  echo "$(t "提示：如果你曾运行 vibeguard trust 安装系统证书，请在系统钥匙串/信任库中手动移除 “VibeGuard CA”。" "Note: If you installed the CA via vibeguard trust, remove \"VibeGuard CA\" from your system trust store manually if needed.")"
fi
