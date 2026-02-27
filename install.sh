#!/usr/bin/env bash
set -euo pipefail

# VibeGuard 安装脚本（中英双语） / VibeGuard installer (ZH/EN)
#
# 功能 / Features:
# - 安装 vibeguard 二进制（优先从源码构建，其次 go install） / Install vibeguard (build from source or go install)
# - 导出（“下载”）系统信任所需的 CA 证书到文件 / Export ("download") the CA certificate to a file
# - 可选：安装 CA 到系统信任库（会触发 sudo） / Optional: install CA into system trust store (will invoke sudo)
#
# 用法 / Usage:
#   bash install.sh
#
# 提示 / Note:
#   默认不修改你的 shell 配置；如需“全局可调用”，可用 --path auto|add 自动写入 PATH。
#   如需“开机自启后台运行”，可用 --autostart auto|add 安装用户级自启服务（macOS LaunchAgent / Linux systemd --user）。

SCRIPT_LANG=""     # zh|en
SCRIPT_LANG_SET="0"
TRUST_MODE_SET="0"
DO_EXPORT_SET="0"

to_lower() {
  # macOS 默认 bash 3.2 不支持 ${var,,}
  echo "${1:-}" | tr '[:upper:]' '[:lower:]'
}

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

persist_lang_best_effort() {
  # 将安装脚本选择的语言持久化到 ~/.vibeguard/lang，供管理页与卸载脚本默认使用。
  # Best-effort: do not fail installation if writing fails.
  [[ -n "${HOME:-}" ]] || return 0
  local dir="${HOME}/.vibeguard"
  local f="${dir}/lang"
  mkdir -p "${dir}" >/dev/null 2>&1 || return 0
  ( umask 077; printf "%s\n" "${SCRIPT_LANG}" >"${f}" ) >/dev/null 2>&1 || true
}

die() {
  echo ""
  echo "$(t "错误：$1" "Error: $2")" >&2
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

need() {
  have "$1" || die "缺少依赖：$1" "Missing dependency: $1"
}

in_repo() {
  [[ -f "go.mod" && -f "cmd/vibeguard/main.go" ]]
}

is_tty() { [[ -t 0 && -t 1 ]]; }

default_install_dir() {
  if [[ -n "${HOME:-}" && -d "${HOME}/.local/bin" ]]; then
    echo "${HOME}/.local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
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

path_has_dir() {
  local dir="${1:-}"
  [[ -n "${dir}" ]] || return 1
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
    *) return 1 ;;
  esac
}

detect_shell_rc() {
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  case "${shell_name}" in
    zsh)
      echo "${HOME}/.zshrc"
      return 0
      ;;
    bash)
      if [[ -f "${HOME}/.bash_profile" ]]; then
        echo "${HOME}/.bash_profile"
      else
        echo "${HOME}/.bashrc"
      fi
      return 0
      ;;
    fish)
      return 1
      ;;
    *)
      echo "${HOME}/.profile"
      return 0
      ;;
  esac
}

ensure_path_in_rc() {
  local rc="${1:-}"
  local dir="${2:-}"
  local marker="# VibeGuard PATH"

  [[ -n "${rc}" && -n "${dir}" ]] || return 1

  if [[ -f "${rc}" ]]; then
    if grep -Fqs "${marker}" "${rc}"; then
      return 0
    fi
    if grep -Fqs "PATH=\"${dir}:" "${rc}" || grep -Fqs "PATH='${dir}:" "${rc}"; then
      return 0
    fi
  fi

  {
    echo ""
    echo "${marker}"
    echo "export PATH=\"${dir}:\$PATH\""
  } >>"${rc}"
}

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

proxy_url_from_listen() {
  echo "http://$(proxy_hostport_from_listen "${1:-}")"
}

install_launch_agent() {
  local label="com.vibeguard.proxy"
  local plist_dir="${HOME}/Library/LaunchAgents"
  local plist_path="${plist_dir}/${label}.plist"

  mkdir -p "${plist_dir}"

  cat >"${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>${VG}</string>
      <string>start</string>
      <string>--foreground</string>
      <string>--config</string>
      <string>${CONFIG_FILE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${CONFIG_DIR}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>${CONFIG_DIR}/launchd.err.log</string>
  </dict>
</plist>
EOF

  echo "${plist_path}"
}

enable_launch_agent() {
  local plist_path="${1:-}"
  local label="com.vibeguard.proxy"
  local uid
  uid="$(id -u)"
  local domain="gui/${uid}"
  local svc="${domain}/${label}"

  have launchctl || return 1

  # 先清理旧的（避免重复注册）
  launchctl bootout "${domain}" "${plist_path}" >/dev/null 2>&1 || true

  if ! launchctl bootstrap "${domain}" "${plist_path}" >/dev/null 2>&1; then
    return 1
  fi
  launchctl enable "${svc}" >/dev/null 2>&1 || true
  if ! launchctl kickstart -k "${svc}" >/dev/null 2>&1; then
    return 1
  fi
}

install_systemd_user_service() {
  local unit_dir="${HOME}/.config/systemd/user"
  local unit_path="${unit_dir}/vibeguard.service"

  mkdir -p "${unit_dir}"

  cat >"${unit_path}" <<EOF
[Unit]
Description=VibeGuard MITM HTTPS proxy
After=network-online.target

[Service]
Type=simple
ExecStart=${VG} start --foreground --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=2
Environment=VIBEGUARD_LANG=${SCRIPT_LANG}

[Install]
WantedBy=default.target
EOF

  echo "${unit_path}"
}

enable_systemd_user_service() {
  have systemctl || return 1
  if ! systemctl --user daemon-reload >/dev/null 2>&1; then
    return 1
  fi
  if ! systemctl --user enable --now vibeguard.service >/dev/null 2>&1; then
    return 1
  fi
}

INSTALL_DIR="$(default_install_dir)"
TRUST_MODE="system"   # system|user|auto|skip
DO_EXPORT="0"
PATH_MODE="auto"      # auto|add|skip
AUTOSTART_MODE="auto" # auto|add|skip
NON_INTERACTIVE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="${2:-}"; shift 2;;
    --trust)
      TRUST_MODE="${2:-}"; TRUST_MODE_SET="1"; shift 2;;
    --export)
      DO_EXPORT="1"; DO_EXPORT_SET="1"; shift 1;;
    --lang|--language)
      SCRIPT_LANG="${2:-}"; SCRIPT_LANG_SET="1"; shift 2;;
    --path)
      PATH_MODE="${2:-}"; shift 2;;
    --autostart)
      AUTOSTART_MODE="${2:-}"; shift 2;;
    --non-interactive)
      NON_INTERACTIVE="1"; shift 1;;
    -h|--help)
      cat <<'EOF'
VibeGuard 安装脚本 / Installer

参数 / Options:
  --dir DIR              安装目录 / Install dir (default: $HOME/.local/bin)
  --trust MODE           system|user|auto|skip (default: system)
  --export               导出 CA 证书到文件 / Export CA cert to a file
  --lang LANG            zh|en (default: auto)
  --path MODE            auto|add|skip (default: auto)
  --autostart MODE       auto|add|skip (default: auto)
  --non-interactive      非交互模式（尽量使用默认值） / Non-interactive (use defaults)

示例 / Examples:
  bash install.sh
EOF
      exit 0;;
    *)
      die "未知参数：$1" "Unknown option: $1";;
  esac
done

# 语言选择：优先 --lang，其次 VIBEGUARD_LANG，然后根据系统语言推断；若可交互则启动时询问一次。
if [[ "${SCRIPT_LANG_SET}" == "1" ]]; then
  SCRIPT_LANG="$(normalize_lang "${SCRIPT_LANG}")"
  [[ -n "${SCRIPT_LANG}" ]] || die "无效的 --lang（请用 zh 或 en）" "Invalid --lang (use zh or en)"
else
  SCRIPT_LANG="$(normalize_lang "${VIBEGUARD_LANG:-}")"
fi

if [[ -z "${SCRIPT_LANG}" ]]; then
  loc="$(to_lower "${LC_ALL:-${LANG:-}}")"
  if [[ "${loc}" == zh* || "${loc}" == *zh* ]]; then
    SCRIPT_LANG="zh"
  else
    SCRIPT_LANG="en"
  fi
fi

if [[ "${SCRIPT_LANG_SET}" == "0" && -z "${VIBEGUARD_LANG:-}" && "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 ]]; then
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

persist_lang_best_effort

case "$(to_lower "${PATH_MODE}")" in
  auto|add|skip) ;;
  *) die "无效的 --path（可选：auto|add|skip）" "Invalid --path (expected: auto|add|skip)" ;;
esac
PATH_MODE="$(to_lower "${PATH_MODE}")"

case "$(to_lower "${AUTOSTART_MODE}")" in
  auto|add|skip) ;;
  *) die "无效的 --autostart（可选：auto|add|skip）" "Invalid --autostart (expected: auto|add|skip)" ;;
esac
AUTOSTART_MODE="$(to_lower "${AUTOSTART_MODE}")"

INSTALL_DIR="$(expand_user_path "${INSTALL_DIR}")"
mkdir -p "${INSTALL_DIR}"

need go

say "安装目录：${INSTALL_DIR}" "Install dir: ${INSTALL_DIR}"

if in_repo; then
  say "检测到仓库源码：从源码构建并安装" "Repo detected: build from source"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  go build -o "${tmp}/vibeguard" ./cmd/vibeguard
  install -m 0755 "${tmp}/vibeguard" "${INSTALL_DIR}/vibeguard"
else
  say "未检测到源码：通过 go install 安装" "Repo not found: installing via go install"
  GOBIN="${INSTALL_DIR}" go install github.com/inkdust2021/vibeguard/cmd/vibeguard@latest
fi

VG="${INSTALL_DIR}/vibeguard"
if [[ ! -x "${VG}" ]] && have vibeguard; then
  VG="$(command -v vibeguard)"
fi

if [[ ! -x "${VG}" ]]; then
  die "vibeguard 未找到或不可执行：${VG}" "vibeguard not found or not executable: ${VG}"
fi

say "vibeguard 路径：${VG}" "vibeguard path: ${VG}"

CONFIG_DIR="${HOME}/.vibeguard"
CA_CERT="${CONFIG_DIR}/ca.crt"
CA_KEY="${CONFIG_DIR}/ca.key"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"

# 可选：将安装目录写入 PATH（永久生效）
resolved="$(command -v vibeguard 2>/dev/null || true)"
need_path="0"
reason=""
if [[ "${resolved}" == "${VG}" ]]; then
  need_path="0"
else
  need_path="1"
  if [[ -z "${resolved}" ]]; then
    reason="not_found"
  else
    reason="different"
  fi
fi

if [[ "${PATH_MODE}" != "skip" && "${need_path}" == "1" ]]; then
  rc_file="$(detect_shell_rc || true)"
  if [[ -z "${rc_file}" ]]; then
    say "未识别你的 Shell，无法自动写入 PATH（请手动添加）" "Shell not recognized; cannot auto-update PATH (please add it manually)"
  else
    prompt_zh=""
    prompt_en=""
    if [[ "${reason}" == "not_found" ]]; then
      prompt_zh="检测到 vibeguard 可能无法全局调用，是否将 ${INSTALL_DIR} 写入 PATH（${rc_file}）？[Y/n]: "
      prompt_en="vibeguard may not be on PATH. Add ${INSTALL_DIR} to PATH via ${rc_file}? [Y/n]: "
    else
      say "检测到 PATH 中已有 vibeguard：${resolved}（不是本次安装版本）" "Found existing vibeguard on PATH: ${resolved} (not the one just installed)"
      prompt_zh="是否让本次安装版本优先生效（将 ${INSTALL_DIR} 写入 PATH / ${rc_file}）？[Y/n]: "
      prompt_en="Prefer the newly installed one (prepend ${INSTALL_DIR} via ${rc_file})? [Y/n]: "
    fi

    if [[ "${PATH_MODE}" == "add" ]]; then
      ensure_path_in_rc "${rc_file}" "${INSTALL_DIR}"
      say "已写入 PATH：${rc_file}" "PATH updated: ${rc_file}"
      say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
    elif [[ "${PATH_MODE}" == "auto" ]]; then
      if [[ "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 ]]; then
        echo ""
        read -r -p "$(t "${prompt_zh}" "${prompt_en}")" ans || true
        ans="${ans:-Y}"
        if [[ "${ans}" == "Y" || "${ans}" == "y" ]]; then
          ensure_path_in_rc "${rc_file}" "${INSTALL_DIR}"
          say "已写入 PATH：${rc_file}" "PATH updated: ${rc_file}"
          say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
        else
          say "已跳过 PATH 写入" "Skipped PATH update"
        fi
      else
        say "非交互模式：未写入 PATH（你可以手动添加）" "Non-interactive: PATH not modified (you can add it manually)"
      fi
    fi
  fi
fi

say "检查 CA 证书" "Checking CA certificate"
if [[ ! -f "${CA_CERT}" ]]; then
  if [[ -f "${CONFIG_FILE}" ]]; then
    say "已存在配置但未找到 CA：请运行 vibeguard init 生成 CA" "Config exists but CA missing: run vibeguard init to generate CA"
  else
    say "未找到 CA：将运行 vibeguard init 生成 CA（不覆盖已有配置）" "CA not found: running vibeguard init to generate CA"
    if [[ "${NON_INTERACTIVE}" == "1" ]]; then
      # 选择默认配置 + 生成 CA + 跳过 init 内置的 trust（由脚本单独处理）
      printf '\n\n\n\n3\n' | VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" init || true
    else
      VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" init || true
    fi
  fi
fi

if [[ -f "${CA_CERT}" ]]; then
  say "CA 证书已就绪：${CA_CERT}" "CA certificate ready: ${CA_CERT}"
else
  say "仍未找到 CA 证书：跳过证书步骤" "CA certificate still missing: skipping cert steps"
  TRUST_MODE="skip"
  DO_EXPORT="0"
fi

if [[ "${DO_EXPORT_SET}" == "0" && "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 && -f "${CA_CERT}" ]]; then
  echo ""
  read -r -p "$(t "是否导出（下载）CA 证书到文件（便于排查/手动安装）？[y/N]: " "Export CA certificate to a file (for debugging/manual install)? [y/N]: ")" ans || true
  ans="$(to_lower "${ans:-n}")"
  if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
    DO_EXPORT="1"
  fi
fi

if [[ "${DO_EXPORT}" == "1" && -f "${CA_CERT}" ]]; then
  export_path=""
  if [[ -d "${HOME}/Downloads" ]]; then
    export_path="${HOME}/Downloads/vibeguard-ca.crt"
  else
    export_path="$(pwd)/vibeguard-ca.crt"
  fi
  cp -f "${CA_CERT}" "${export_path}"
  say "已导出（下载）CA 证书：${export_path}" "Exported CA certificate: ${export_path}"
fi

if [[ "${TRUST_MODE_SET}" == "0" && "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 && -f "${CA_CERT}" ]]; then
  echo ""
  read -r -p "$(t "是否安装信任证书（HTTPS MITM 必需，推荐）？[Y/n]: " "Install trusted CA (required for HTTPS MITM, recommended)? [Y/n]: ")" ans || true
  ans="$(to_lower "${ans:-y}")"
  if [[ "${ans}" == "n" || "${ans}" == "no" ]]; then
    TRUST_MODE="skip"
  else
    TRUST_MODE="auto"
  fi
fi

case "${TRUST_MODE}" in
  skip)
    say "跳过信任库安装" "Skipping trust store install";;
  system|user|auto)
    if [[ ! -f "${CA_CERT}" ]]; then
      die "未找到 CA 证书，无法安装信任" "CA certificate missing, cannot install trust"
    fi

    if [[ "${TRUST_MODE}" == "system" ]]; then
      say "将安装到系统信任库（可能需要 sudo）" "Installing to SYSTEM trust store (may require sudo)"
    else
      say "将安装到信任库：${TRUST_MODE}" "Installing to trust store: ${TRUST_MODE}"
    fi

    if [[ "${NON_INTERACTIVE}" == "0" && "${TRUST_MODE}" == "system" && is_tty ]]; then
      echo ""
      read -r -p "$(t "继续安装系统信任证书？[Y/n]: " "Continue? [Y/n]: ")" ans || true
      ans="${ans:-Y}"
      if [[ "${ans}" != "Y" && "${ans}" != "y" ]]; then
        say "已取消" "Cancelled"
        TRUST_MODE="skip"
      fi
    fi

    if [[ "${TRUST_MODE}" != "skip" ]]; then
      VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" trust --mode "${TRUST_MODE}"
    fi
    ;;
  *)
    die "无效的 --trust：${TRUST_MODE}" "Invalid --trust: ${TRUST_MODE}";;
esac

# 基于当前配置推断代理地址（用于写入环境变量与输出提示）
listen_addr="$(detect_listen_from_config "${CONFIG_FILE}" || true)"
proxy_hostport="$(proxy_hostport_from_listen "${listen_addr}")"
proxy_url="http://${proxy_hostport}"
admin_url="http://${proxy_hostport}/manager/"

# 可选：开机自启后台运行（用户级服务）
autostart_enabled="0"
if [[ "${AUTOSTART_MODE}" != "skip" ]]; then
  do_autostart="0"
  if [[ "${AUTOSTART_MODE}" == "add" ]]; then
    do_autostart="1"
  elif [[ "${AUTOSTART_MODE}" == "auto" ]]; then
    if [[ "${NON_INTERACTIVE}" == "0" && -t 0 && -t 1 ]]; then
      echo ""
      read -r -p "$(t "是否启用开机自启并后台运行（推荐）？[Y/n]: " "Enable autostart + background service (recommended)? [Y/n]: ")" ans || true
      ans="${ans:-Y}"
      if [[ "${ans}" == "Y" || "${ans}" == "y" ]]; then
        do_autostart="1"
      fi
    fi
  fi

  if [[ "${do_autostart}" == "1" ]]; then
    os_name="$(uname -s || true)"
    case "${os_name}" in
      Darwin)
        say "配置开机自启（macOS LaunchAgent）" "Setting up autostart (macOS LaunchAgent)"
        plist_path="$(install_launch_agent)"
        if enable_launch_agent "${plist_path}"; then
          autostart_enabled="1"
          say "已启用开机自启：${plist_path}" "Autostart enabled: ${plist_path}"
        else
          say "启用 LaunchAgent 失败（你可稍后手动启动）：${VG} start" "Failed to enable LaunchAgent (you can start manually): ${VG} start"
        fi
        ;;
      Linux)
        say "配置开机自启（Linux systemd --user）" "Setting up autostart (Linux systemd --user)"
        if have systemctl; then
          unit_path="$(install_systemd_user_service)"
          if enable_systemd_user_service; then
            autostart_enabled="1"
            say "已启用开机自启：${unit_path}" "Autostart enabled: ${unit_path}"
          else
            say "启用 systemd 用户服务失败（你可稍后手动启动）：${VG} start" "Failed to enable systemd user service (you can start manually): ${VG} start"
          fi
        else
          say "未检测到 systemctl：跳过开机自启（你的发行版可能不是 systemd）" "systemctl not found; skipping autostart (your distro may not use systemd)"
        fi
        ;;
      *)
        say "当前系统暂不支持自动配置开机自启（你可手动启动）：${VG} start" "Autostart not supported on this OS (start manually): ${VG} start"
        ;;
    esac
  fi
fi

# 如果没有启用自启服务，但写入了代理环境变量，建议立即启动后台代理，避免“已设置代理但端口未监听”导致网络请求失败。
say "启动后台代理" "Starting proxy in background"
if ! VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" start; then
  say "后台代理启动失败（你可稍后手动运行：vibeguard start --foreground）" "Failed to start proxy (you can run: vibeguard start --foreground)"
fi

say "安装完成" "Done"
echo ""
echo "$(t "下一步：" "Next steps:")"
if [[ "${autostart_enabled}" == "1" ]]; then
  echo "  1) $(t "代理已设置为后台自启（登录后自动运行）" "Proxy runs in background on login")"
else
  echo "  1) $(t "启动代理（后台）" "Start proxy (background)"): ${VG} start"
fi
echo "  2) $(t "打开管理页" "Open admin"): ${admin_url}"
echo "  3) $(t "CLI 助手推荐用 VibeGuard 启动（仅该进程生效）：" "For CLI assistants, launch via VibeGuard (process-only):")"
echo "     vibeguard codex [args...]"
echo "     vibeguard claude [args...]"
echo "     vibeguard gemini [args...]"
echo "     vibeguard opencode [args...]"
echo "     vibeguard qwen [args...]"
echo "     vibeguard run <command> [args...]"
echo "  4) $(t "IDE/GUI（如 Cursor）在软件设置里把代理地址填为" "For IDE/GUI apps (Cursor, etc), set the proxy URL to"): ${proxy_url}"
