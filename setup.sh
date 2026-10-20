#!/usr/bin/env bash
# Author: Pre
# InstaBox Tool: verified, commit-pinned installer with an owned-state migration.
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
REPO='Pretic/InstaBox-Tool'
APP="$HOME/.local/share/insta-box"
CLI="$APP/cli"
MODE="${1:-install}"
REF="${IBT_REF:-${IB_REF:-${ISB_REF:-}}}"
FILES=(setup.sh ibt.sh install.sh keepalive.sh platform.mjs cf_route.py cf_select.py heartbeat.py cloud.py ssh_tokens.py machine_opt.py node_probe.py system_info.py ui_time.py migrate.py)
die() { printf '  [失败] %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Linux ]] || die '请在 Linux SSH 终端运行。'
(( EUID != 0 )) || die '请使用普通用户，不要加 sudo。'
[[ "$MODE" == install || "$MODE" == --menu-only ]] || die '参数为 install 或 --menu-only。'
for x in curl bash python3 mktemp sha256sum awk sed; do command -v "$x" >/dev/null 2>&1 || die "缺少系统命令：$x"; done
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 90 "$1" -o "$2"; }
if [[ -z "$REF" ]]; then
  fetch "https://api.github.com/repos/$REPO/git/ref/heads/main" "$TMP/ref.json" || die '无法读取更新版本；节点服务未修改。'
  REF="$(sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' "$TMP/ref.json" | head -1)"
fi
[[ "$REF" =~ ^[a-f0-9]{40}$ ]] || die '版本信息无效，请稍后重试。'
BASE="https://raw.githubusercontent.com/$REPO/$REF"
printf '  正在准备管理工具…\n'
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die '下载校验清单失败。'
for f in "${FILES[@]}"; do
  digest="$(awk -v f="$f" '$2 == f {print $1}' "$TMP/SHA256SUMS")"
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || die "校验清单缺少 $f。"
  fetch "$BASE/$f" "$TMP/$f" || die "下载 $f 失败；原配置未改动。"
  printf '%s  %s\n' "$digest" "$TMP/$f" | sha256sum -c --status || die "$f 校验未通过。"
  if [[ "$f" == *.sh ]]; then bash -n "$TMP/$f" || die "$f 语法检查失败。"; fi
  if [[ "$f" == *.mjs ]] && command -v node >/dev/null 2>&1; then node --check "$TMP/$f" || die '平台组件检查失败。'; fi
  chmod 700 "$TMP/$f"
done
# Prepare image-created parent directories before persisting authorization or
# taking the installation lock. Only verified existing directories are touched.
python3 "$TMP/migrate.py" --bundle "$TMP" --ref "$REF" --prepare-only || die '安装目录检查未通过；请按上方提示处理后重新运行同一命令。'
# Check before migration: creating the new credential directory first would
# conflict with a real legacy configuration that still needs to be moved.
FRESH=1
for existing in "$APP" "$HOME/.local/share/insta-sing-box"; do
  for record in state.conf cli/ibt.sh cli/ib.sh cli/isb.sh; do
    if [[ -e "$existing/$record" || -L "$existing/$record" ]]; then FRESH=0; fi
  done
done
if [[ -e "$HOME/.config/insta-sing-box" || -L "$HOME/.config/insta-sing-box" ]]; then FRESH=0; fi
if (( FRESH )); then
  python3 "$TMP/cloud.py" key ensure || die '首次授权未完成，尚未安装节点；请修正 API Key 后重新运行。'
fi
python3 "$TMP/migrate.py" --bundle "$TMP" --ref "$REF" || die '安装尚未完成；请按上方提示处理后重新运行同一命令。'
if [[ "$MODE" == install ]]; then
  bash "$CLI/install.sh" install
fi
if [[ "$MODE" == install && -t 0 && -t 1 ]]; then
  "$HOME/.local/bin/ibt"
fi
printf '\n  InstaBox Tool 已就绪。\n'
case ":$PATH:" in
  *":$HOME/.local/bin:"*) printf '  管理入口： ibt\n';;
  *)
    printf '  当前窗口： 先执行 export PATH="$HOME/.local/bin:$PATH"，再输入 ibt。\n'
    printf '  直接打开： ~/.local/bin/ibt\n'
    ;;
esac
printf '  下次登录： 输入 ibt 打开管理菜单。\n'
