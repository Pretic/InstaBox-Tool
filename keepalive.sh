#!/usr/bin/env bash
# Author: Pre
# Heartbeat commands are independent of the optional SDK policy manager.
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
APP="$HOME/.local/share/insta-box"
SDK="$APP/management"
CFG="$HOME/.config/insta-box"
KEY="$CFG/api-key"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE="$HERE/platform.mjs"
[[ -f "$SOURCE" ]] || SOURCE="$APP/cli/platform.mjs"
CMD="${1:-status}"; NAME="${2:-}"
say() { printf '  %s\n' "$*"; }
die() { printf '  [失败] %s\n' "$*" >&2; exit 1; }
case "$CMD" in
  key-set|key-status|key-forget)
    command -v python3 >/dev/null 2>&1 || die 'API 授权管理需要 Python 3。'
    HELPER="$HERE/cloud.py"
    [[ -f "$HELPER" ]] || HELPER="$APP/cli/cloud.py"
    [[ -f "$HELPER" ]] || die '授权管理组件缺失，请运行 ibt update。'
    exec python3 "$HELPER" key "${CMD#key-}"
    ;;
  rotate-setup|rotate-now|rotate-off|token-status)
    command -v python3 >/dev/null 2>&1 || die 'SSH 凭据轮换需要 Python 3。'
    HELPER="$HERE/ssh_tokens.py"
    [[ -f "$HELPER" ]] || HELPER="$APP/cli/ssh_tokens.py"
    [[ -f "$HELPER" ]] || die '凭据轮换组件缺失，请运行 ibt update。'
    exec python3 "$HELPER" "$CMD" "${@:2}"
    ;;
  auto|auto-local|setup|setup-api|setup-ssh|add|add-api|renew|remove|run|status|start|stop|clear|logs)
    command -v python3 >/dev/null 2>&1 || die '周期保活需要 Python 3，请先安装系统 python3。'
    HELPER="$HERE/heartbeat.py"
    [[ -f "$HELPER" ]] || HELPER="$APP/cli/heartbeat.py"
    [[ -f "$HELPER" ]] || die '保活组件缺失，请运行 ibt update。'
    exec python3 "$HELPER" "$CMD" "${@:2}"
    ;;
esac
case "$CMD" in
  apply|check|status|resume|machines|auth|doctor) ;;
  *) NAME="$CMD"; CMD="${2:-apply}" ;;
esac
[[ ! -L "$CFG" && ! -L "$KEY" ]] || die '管理配置不能是符号链接。'
mkdir -p "$CFG" "$SDK"
chmod 700 "$CFG" "$SDK"
if [[ -e "$KEY" ]]; then
  [[ -f "$KEY" && -O "$KEY" ]] || die '密钥文件归属异常，已停止。'
  chmod 600 "$KEY"
fi
case "$CMD" in
  apply|check|status|resume|machines|auth|doctor) ;;
  *) die '未知操作。请运行 ibt help。' ;;
esac

major=0
if command -v node >/dev/null 2>&1; then major="$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"; fi
if ! [[ "$major" =~ ^[0-9]+$ ]] || (( major < 20 )); then
  if [[ "${IBT_NO_SUDO:-0}" == 1 || "${IB_NO_SUDO:-0}" == 1 || "${SB_NO_SUDO:-0}" == 1 ]] || ! command -v apt-get >/dev/null 2>&1 ||
     ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
    die '此功能需要 Node.js 20+，当前无法自动安装。节点服务不受影响。'
  fi
  say '准备安装平台管理依赖 Node.js / npm…'
  sudo -n apt-get update -qq && sudo -n apt-get install -y -qq nodejs npm || die '依赖安装失败。'
  major="$(node -p 'Number(process.versions.node.split(".")[0])')"
  (( major >= 20 )) || die '系统仓库 Node.js 版本不足，请安装 20+ 后重试。'
fi
[[ -s "$SOURCE" ]] || die '管理组件缺失，请运行 ibt update。'
if [[ ! -s "$SDK/node_modules/@insforge/instabox-sdk/package.json" ]]; then
  command -v npm >/dev/null 2>&1 || die '缺少 npm，无法准备官方管理组件。'
  say '准备官方管理组件…'
  (unset INSTABOX_API_KEY; npm install --prefix "$SDK" --ignore-scripts --no-audit --no-fund --no-save --silent '@insforge/instabox-sdk@0.2.0') || die '官方 SDK 下载失败。'
fi
install -m 700 "$SOURCE" "$SDK/platform.mjs"

NEW_KEY=''; SAVE=no; key_tmp=''
cleanup() { unset NEW_KEY INSTABOX_API_KEY; [[ -z "$key_tmp" ]] || rm -f -- "$key_tmp"; }
trap cleanup EXIT
if [[ ! -s "$KEY" && -z "${INSTABOX_API_KEY:-}" ]]; then
  read -r -s -p '  输入 InstaBox API Key：' NEW_KEY </dev/tty || die '已取消授权。'
  printf '\n'
  [[ "$NEW_KEY" == ibk_* && "$NEW_KEY" != *[[:space:]]* ]] || die '密钥格式无效，应以 ibk_ 开头。'
  export INSTABOX_API_KEY="$NEW_KEY"
  # Authenticate separately: a good key can be remembered even if the later action needs attention.
  (cd "$SDK" && node platform.mjs auth) || die '授权未通过；原有密钥未修改。'
  say '保存后无需重复输入；密钥仅存本机，云平台和快照仍可能读取。'
  read -r -p '  保存授权？[Y/n]：' answer </dev/tty || die '已取消。'
  [[ -n "$answer" && "${answer,,}" != y && "${answer,,}" != yes ]] || SAVE=yes
  if [[ "$SAVE" == yes ]]; then
    key_tmp="$(mktemp "$CFG/.api-key.XXXXXXXX")"
    printf '%s\n' "$NEW_KEY" > "$key_tmp"
    chmod 600 "$key_tmp"
    mv -f -- "$key_tmp" "$KEY"; key_tmp=''
    say '授权已保存。'
  fi
elif [[ -z "${INSTABOX_API_KEY:-}" ]]; then
  INSTABOX_API_KEY="$(cat -- "$KEY")"; export INSTABOX_API_KEY
fi
(cd "$SDK" && node platform.mjs "$CMD" "$NAME")
