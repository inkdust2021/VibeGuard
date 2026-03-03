#!/usr/bin/env bash
set -euo pipefail

# 清理仓库内的本地产物/临时目录（默认仅预览）。
# 用法：
#   scripts/clean.sh          # 预览将删除哪些内容
#   scripts/clean.sh --force  # 实际删除

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

force=0
case "${1:-}" in
  --force|-f) force=1 ;;
  "" ) ;;
  *)
    echo "未知参数：$1" >&2
    echo "用法：scripts/clean.sh [--force]" >&2
    exit 2
    ;;
esac

targets=(
  "${ROOT_DIR}/temp"
  "${ROOT_DIR}/~"
  "${ROOT_DIR}/{cmd"
  "${ROOT_DIR}/bin"
  "${ROOT_DIR}/cmd/vibeguard/vibeguard"
  "${ROOT_DIR}/cmd/vibeguard/vibeguard.exe"
  "${ROOT_DIR}/vibeguard"
)

echo "将清理以下本地产物（默认仅预览）："
has_any=0
for p in "${targets[@]}"; do
  if [[ -e "${p}" ]]; then
    echo " - ${p}"
    has_any=1
  fi
done
if [[ "${has_any}" -eq 0 ]]; then
  echo "（未发现可清理项）"
fi

if [[ "${force}" -ne 1 ]]; then
  echo
  echo "预览模式：不会删除任何文件。"
  echo "如需执行清理：scripts/clean.sh --force"
  exit 0
fi

echo
echo "正在清理..."
for p in "${targets[@]}"; do
  if [[ -e "${p}" ]]; then
    rm -rf -- "${p}"
  fi
done
echo "完成。"

