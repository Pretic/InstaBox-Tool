#!/usr/bin/env bash
# Author: Pre
# Managed-by: InstaBox Tool CLI
set -uo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
VERSION='0.0.1'
AUTHOR='Pre'
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CORE="$HERE/install.sh"
PLATFORM="$HERE/keepalive.sh"
CLOUD="$HERE/cloud.py"
OPTIMIZER="$HERE/machine_opt.py"
SYSTEM_INFO="$HERE/system_info.py"
TIME_SETTINGS="$HERE/ui_time.py"
CF_SELECTOR="$HERE/cf_select.py"
IBT_INITIAL_TZ_PRESENT="${TZ+x}"
IBT_INITIAL_TZ_VALUE="${TZ-}"
APP="$HOME/.local/share/insta-box"
CFG="$HOME/.config/insta-box"
SETUP='https://raw.githubusercontent.com/Pretic/InstaBox-Tool/main/setup.sh'
# The previous menu re-execs its old command after an update. A one-use
# migration bridge lets that process hand off, and is removed on first use.
for legacy_command in ib isb; do
  legacy_bridge="$HOME/.local/bin/$legacy_command"
  if [[ -f "$legacy_bridge" && ! -L "$legacy_bridge" && -O "$legacy_bridge" ]] &&
     grep -Fqx '# Managed-by: InstaBox Tool migration bridge' "$legacy_bridge"; then
    rm -f -- "$legacy_bridge"
  fi
done
unset legacy_bridge legacy_command
BOLD='' ACCENT='' GREEN='' YELLOW='' RED='' DIM='' RESET=''
if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
  BOLD=$'\e[1m'; ACCENT=$'\e[38;5;75m'; GREEN=$'\e[32m'
  YELLOW=$'\e[33m'; RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m'
fi
say() { printf '  %s\n' "$*"; }
error() { printf '  %s[失败]%s %s\n' "$RED" "$RESET" "$*" >&2; }
ask() {
  local answer
  read -r -p "  ${ACCENT}$1${RESET} " answer </dev/tty || return 1
  printf '%s' "$answer"
}
pause_once() { read -r -p "  ${DIM}按回车返回…${RESET}" _ </dev/tty || true; }
confirm() {
  local a; a="$(ask "$1 [y/N]：")" || return 1
  [[ ${a,,} == y || ${a,,} == yes ]]
}
screen() {
  if [[ -t 1 && ${TERM:-dumb} != dumb && ${IBT_NO_CLEAR:-${IB_NO_CLEAR:-0}} != 1 ]]; then printf '\033[H\033[2J'; fi
  printf '\n  %sInstaBox Tool%s  %sv%s · 作者 %s%s\n' "$BOLD$ACCENT" "$RESET" "$DIM" "$VERSION" "$AUTHOR" "$RESET"
  printf '  %s────────────────────────────────────────────%s\n' "$DIM" "$RESET"
  [[ -z ${1:-} ]] || printf '  %s%s%s\n\n' "$BOLD" "$1" "$RESET"
}
item() {
  local color="$ACCENT"
  [[ "$1" != 0 ]] || color="$DIM"
  printf '  %s%s.%s %s\n' "$color" "$1" "$RESET" "$2"
}
core() { [[ -f "$CORE" ]] || { error '组件缺失，请更新工具。'; return 1; }; bash "$CORE" "$@"; }
platform() { [[ -f "$PLATFORM" ]] || { error '组件缺失，请更新工具。'; return 1; }; bash "$PLATFORM" "$@"; }
cloud() {
  [[ -f "$CLOUD" ]] || { error '云端管理组件缺失，请更新工具。'; return 1; }
  command -v python3 >/dev/null 2>&1 || { error '云端管理需要 Python 3。'; return 1; }
  python3 "$CLOUD" "$@"
}
optimize() {
  [[ -f "$OPTIMIZER" ]] || { error '机器优化组件缺失，请更新工具。'; return 1; }
  command -v python3 >/dev/null 2>&1 || { error '机器优化需要 Python 3。'; return 1; }
  python3 "$OPTIMIZER" "$@"
}
local_info() {
  [[ -f "$SYSTEM_INFO" ]] || { error '本机信息组件缺失，请更新工具。'; return 1; }
  command -v python3 >/dev/null 2>&1 || { error '本机信息需要 Python 3。'; return 1; }
  python3 "$SYSTEM_INFO" "$@"
}
cf_runtime_ready() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -c '
import os, re, ssl, sys
try:
    context = ssl.create_default_context()
    # OpenSSL loads hashed CA directories lazily. Check a certificate without
    # making a request or treating an empty pre-handshake store as missing.
    if not context.cert_store_stats()["x509_ca"]:
        capath = ssl.get_default_verify_paths().capath
        for name in os.listdir(capath)[:512] if capath else ():
            if not re.fullmatch(r"[0-9a-fA-F]{8}\.[0-9]+", name):
                continue
            try:
                context.load_verify_locations(cafile=os.path.join(capath, name))
            except (OSError, ssl.SSLError):
                continue
            if context.cert_store_stats()["x509_ca"]:
                break
    sys.exit(0 if context.cert_store_stats()["x509_ca"] else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)
' >/dev/null 2>&1
}
cf_dependencies() {
  cf_runtime_ready && return 0
  if [[ "${IBT_NO_SUDO:-${IB_NO_SUDO:-${SB_NO_SUDO:-0}}}" == 1 ]]; then
    error 'CF 优选需要 Python 3 与 CA 证书；当前已禁止自动安装依赖。'
    return 1
  fi
  command -v apt-get >/dev/null 2>&1 || {
    error '请用系统包管理器安装 python3 和 ca-certificates 后重试。'; return 1;
  }
  local -a elevation=()
  if (( EUID != 0 )); then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
      error '自动安装需要免密 sudo；请先执行 sudo apt-get install -y python3 ca-certificates。'
      return 1
    fi
    elevation=(sudo -n)
  fi
  say '正在自动准备 CF 优选依赖：Python 3 与 CA 证书…'
  "${elevation[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 update -qq || {
    error '刷新依赖索引失败，请检查软件源后重试。'; return 1;
  }
  "${elevation[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends python3 ca-certificates || {
    error '依赖安装失败，本次未生成优选链接。'; return 1;
  }
  cf_runtime_ready || { error '依赖仍不完整，请检查 Python 3 的 SSL 模块与 CA 证书。'; return 1; }
}
cf_nodes() {
  [[ -f "$CF_SELECTOR" ]] || { error 'CF 优选组件缺失，请更新工具。'; return 1; }
  cf_dependencies || return
  python3 "$CF_SELECTOR" "$@"
}
cf_menu() {
  local n
  [[ -f "$CF_SELECTOR" ]] || { error 'CF 优选组件缺失，请更新工具。'; pause_once; return 1; }
  cf_dependencies || { pause_once; return 1; }
  while :; do
    screen 'CF 优选'
    say '参考 byJoey/cfy，支持 VLESS + WebSocket + TLS。'
    say '选择节点和优选方式，生成后复制链接导入客户端。'
    printf '\n'
    item 1 '生成优选链接'
    item 2 '查看上次结果'
    item 0 '返回节点管理'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) python3 "$CF_SELECTOR";;
      2) python3 "$CF_SELECTOR" --show-last;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
time_settings() {
  [[ -f "$TIME_SETTINGS" ]] || { error '显示时区组件缺失，请更新工具。'; return 1; }
  command -v python3 >/dev/null 2>&1 || { error '显示时区需要 Python 3。'; return 1; }
  # The TZ exported below is an effective setting, not an original override.
  # Recompute from the original shell environment after every set/reset.
  if [[ -n "$IBT_INITIAL_TZ_PRESENT" ]]; then
    TZ="$IBT_INITIAL_TZ_VALUE" python3 "$TIME_SETTINGS" "$@"
  else
    env -u TZ python3 "$TIME_SETTINGS" "$@"
  fi
}
refresh_display_timezone() {
  [[ -f "$TIME_SETTINGS" ]] && command -v python3 >/dev/null 2>&1 || return 0
  local selected rc=0
  selected="$(time_settings env)" || rc=$?
  if (( rc == 0 )) && [[ -n "$selected" ]]; then export TZ="$selected"
  else unset TZ; fi
}
restore_initial_timezone() {
  if [[ -n "$IBT_INITIAL_TZ_PRESENT" ]]; then export TZ="$IBT_INITIAL_TZ_VALUE"
  else unset TZ; fi
}
timezone_menu() {
  local n zone
  while :; do
    screen '设置显示时区'
    time_settings status
    say '只调整本工具的时间显示；保活间隔与到期时刻不变。'
    printf '\n'
    item 1 '使用系统时区'
    item 2 '使用北京时间'
    item 3 '设置其他时区'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) time_settings reset && refresh_display_timezone;;
      2) time_settings set Asia/Shanghai && refresh_display_timezone;;
      3)
        zone="$(ask '输入 IANA 时区（如 Asia/Tokyo，留空取消）：')" || return
        [[ -z "$zone" ]] || { time_settings set "$zone" && refresh_display_timezone; }
        ;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
info_menu() {
  local n
  while :; do
    screen '本机信息'
    local_info || say '部分信息无法读取，可刷新后重试。'
    printf '\n'
    item 1 '刷新本机信息'
    item 2 '设置显示时区'
    item 0 '返回工具主页'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) continue;;
      2) timezone_menu;;
      *) say '请输入菜单序号。'; pause_once;;
    esac
  done
}
service_label() {
  local unit="$1" value
  if ! command -v systemctl >/dev/null 2>&1; then printf '不可读取'; return; fi
  value="$(systemctl --user is-active "$unit" 2>/dev/null || true)"
  case "$value" in
    active) printf '%s运行中%s' "$GREEN" "$RESET";;
    activating) printf '%s连接中%s' "$YELLOW" "$RESET";;
    failed) printf '%s异常%s' "$RED" "$RESET";;
    *) printf '%s未运行%s' "$DIM" "$RESET";;
  esac
}
node_configured() {
  # Use the same persisted installation marker as install.sh, including when
  # a configured node is stopped or needs repair.
  [[ -f "$APP/state.conf" ]]
}
node_label() {
  if node_configured; then service_label insta-box-node.service
  else printf '%s未安装%s' "$DIM" "$RESET"; fi
}
cache_label() {
  command -v node >/dev/null 2>&1 || { printf '尚未检查'; return; }
  node - "$CFG" <<'JS'
const fs=require('fs'), path=require('path');
const read=f=>{try{return JSON.parse(fs.readFileSync(path.join(process.argv[2],f),'utf8'))}catch{return {}}};
const s=read('keepalive-state.json'), m=read('machine.json');
const current=s.sandboxId && (!m.sandboxId || s.sandboxId===m.sandboxId);
const labels={confirmed:'已配置',needs_action:'需要处理',unknown:'未确认',error:'读取失败',conflict:'数据不一致'};
let label=current&&s.schema===2 ? (labels[s.result]||'需要重新检查') : '需要重新检查';
if(!s.sandboxId) label='尚未检查';
if(current && s.schema===2 && s.checkedAt) {
 const d=new Date(s.checkedAt);
 if(Number.isFinite(d.getTime())) label+=' · '+d.toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});
}
const target=String(m.name||s.name||'').replace(/[\x00-\x1f\x7f-\x9f]/g,'').slice(0,24);
process.stdout.write((target ? target+' · ' : '')+label);
JS
}
node_services() {
  say "节点状态： $(node_label)"
  say "快捷隧道： $(service_label insta-box-quick.service)"
  say "固定隧道： $(service_label insta-box-tunnel.service)"
  if command -v loginctl >/dev/null 2>&1; then
    local linger; linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
    [[ "$linger" == yes ]] && say '后台自启： 已启用' || say '后台自启： 需要检查（ibt repair）'
  fi
}
services() {
  node_services
  say "保活状态： $(service_label insta-box-heartbeat.timer)"
  say "平台策略： $(cache_label)"
}
update_cli() {
  local tmp rc=0
  tmp="$(mktemp)" || return 1
  if curl -fsSL --retry 2 --connect-timeout 15 --max-time 90 "$SETUP" -o "$tmp" && bash -n "$tmp"; then
    bash "$tmp" --menu-only || rc=$?
  else rc=1; error '更新下载失败，原有节点未修改。'; fi
  rm -f -- "$tmp"
  return "$rc"
}
remove_all() {
  confirm '删除本工具的节点服务和管理菜单？' || { say '已取消。'; return 1; }
  if [[ -d /var/lib/insta-box-tool ]]; then
    if confirm '卸载前恢复本工具设置的 Swap 和 BBR？'; then
      optimize restore || { error '系统优化尚未恢复，保留工具以便重试。'; return 1; }
    else
      say '保留系统优化；以后重新安装工具即可进入机器优化管理。'
    fi
  fi
  local remove_key=no
  if [[ -s "$CFG/api-key" ]]; then
    confirm '同时清除本机保存的 InstaBox 授权？' && remove_key=yes
  fi
  CONFIRM=YES core uninstall || return 1
  local link="$HOME/.local/bin/ibt"
  if [[ -f "$link" ]] && grep -Fqx '# Managed-by: InstaBox Tool CLI' "$link"; then rm -f -- "$link"; fi
  if [[ "$remove_key" == yes && ! -L "$CFG" ]]; then
    rm -f -- "$CFG/api-key" "$CFG/machine.json" "$CFG/keepalive-state.json"
  fi
  say '本机卸载完成。Cloudflare 后台资源未修改。'
}
account_menu() {
  local n
  while :; do
    screen '管理账户授权'
    item 1 '查看账户限制'
    item 2 '查看授权状态'
    item 3 '更新访问密钥'
    item 4 '清除本机授权'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '管理账户授权'
    case "$n" in
      1) cloud account;;
      2) cloud key status;;
      3) cloud key set;;
      4) if confirm '清除本机授权？'; then cloud key forget; fi;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
cloud_protection_menu() {
  local n
  while :; do
    screen '管理机器保活'
    say '选择一台或多台机器，只调整它们在本机的 API 保活。'
    say '开启保活不会开机；关闭保活不会关机。'
    printf '\n'
    item 1 '开启机器保活'
    item 2 '关闭机器保活'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '管理机器保活'
    case "$n" in
      1) cloud protect on;;
      2) cloud protect off;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
cloud_menu() {
  local n rc
  while :; do
    screen '机器管理'
    if cloud overview; then :; else
      rc=$?
      [[ "$rc" != 130 ]] || return "$rc"
      say '列表暂时无法读取：可用 7 检查授权，或用 9 重试。'
    fi
    printf '\n'
    say '启动 = 开机；保活 = 由本机定时维护所选机器。'
    printf '\n'
    item 1 '查看机器详情'
    item 2 '启动所选机器'
    item 3 '暂停所选机器'
    item 4 '停止所选机器'
    item 5 '管理机器保活'
    item 6 '查看操作进度'
    item 7 '管理账户授权'
    item 8 '打开保活面板'
    item 9 '刷新机器列表'
    item 0 '返回工具主页'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    if [[ "$n" == 5 ]]; then cloud_protection_menu; continue; fi
    if [[ "$n" == 7 ]]; then account_menu; continue; fi
    [[ "$n" != 8 ]] || return 21
    [[ "$n" != 9 ]] || continue
    screen '机器管理'
    case "$n" in
      1) cloud info --choose;;
      2) cloud batch start;; 3) cloud batch pause;; 4) cloud batch stop;;
      6) cloud operations;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
keepalive_menu() {
  local n
  while :; do
    screen '机器保活'
    platform status --brief || true
    printf '\n'
    item 1 '一键保活机器'
    item 2 '管理保活目标'
    item 3 '管理自动任务'
    item 4 '管理命令凭据'
    item 5 '平台高级选项'
    item 6 '打开机器管理'
    item 7 '查看保活详情'
    item 0 '返回工具主页'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) screen '一键保活机器'; platform auto; pause_once;;
      2) keepalive_targets_menu;;
      3) keepalive_tasks_menu;;
      4) token_menu;;
      5) keepalive_advanced_menu;;
      6) return 20;;
      7) screen '保活详情'; platform status; pause_once;;
      *) say '请输入菜单序号。'; pause_once;;
    esac
  done
}
keepalive_targets_menu() {
  local n
  while :; do
    screen '管理保活目标'
    say '推荐用 API Key 选择云端机器；也可独立粘贴 SSH / Mosh 命令。'
    say '添加目标会启用自动任务，已配置的其他目标保留。'
    printf '\n'
    item 1 '选择云端机器'
    item 2 '添加命令机器'
    item 3 '移除保活目标'
    item 4 '清除保活配置'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '管理保活目标'
    case "$n" in
      1) cloud protect on;; 2) platform add;; 3) platform remove;;
      4) if confirm '停用本机保活并清除保活目标与临时凭据？'; then platform clear; fi;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
keepalive_tasks_menu() {
  local n
  while :; do
    screen '管理自动任务'
    say '启用后按间隔自动执行，无需反复点击「立即执行保活」。'
    say '具体执行时间在保活面板查看；停止任务会停止所有目标的自动保活。'
    printf '\n'
    item 1 '立即执行保活'
    item 2 '启用后台保活'
    item 3 '停止后台保活'
    item 4 '查看保活日志'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '管理自动任务'
    case "$n" in
      1) platform run;; 2) platform start;; 3) platform stop;; 4) platform logs;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
keepalive_advanced_menu() {
  local n
  while :; do
    screen '平台高级选项'
    say '日常保活不需要更改平台的空闲暂停规则。'
    printf '\n'
    item 1 '配置平台策略'
    item 2 '查看平台策略'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '平台高级选项'
    case "$n" in
      1) platform apply;; 2) platform check;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
machine_pages() {
  # These are peer pages. Return a route instead of nesting their menu loops.
  local page="$1" rc
  while :; do
    case "$page" in
      cloud) cloud_menu; rc=$?;;
      keepalive) keepalive_menu; rc=$?;;
      *) return 1;;
    esac
    case "$rc" in
      20) page=cloud;;
      21) page=keepalive;;
      *) return "$rc";;
    esac
  done
}
token_menu() {
  local n
  while :; do
    screen '管理命令凭据'
    say '仅用于已添加的 SSH / Mosh 目标；API 保活不需要 SSH token。'
    say '首次使用：先到「管理保活目标」中添加命令机器。'
    printf '\n'
    item 1 '配置自动换新'
    item 2 '查看换新状态'
    item 3 '立即换新凭据'
    item 4 '停用自动换新'
    item 5 '手动更新凭据'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '管理命令凭据'
    case "$n" in
      1) platform rotate-setup;; 2) platform token-status;;
      3) platform rotate-now;; 4) platform rotate-off;; 5) platform renew;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
tunnel_menu() {
  local n
  while :; do
    screen '管理域名隧道'
    item 1 '启动快捷节点'
    item 2 '刷新快捷地址'
    item 3 '绑定固定域名'
    item 4 '自动配置域名'
    item 5 '托管固定隧道'
    item 6 '关闭快捷隧道'
    item 7 '检查节点连接'
    item 8 '设置快捷传输'
    item 9 '管理开机自启'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    if [[ "$n" == 8 ]]; then quick_protocol_menu; continue; fi
    if [[ "$n" == 9 ]]; then quick_autostart_menu; continue; fi
    screen '管理域名隧道'
    case "$n" in
      1) core quick;;
      2) if confirm '刷新后旧快捷链接会失效，继续？'; then core refresh-quick; fi;;
      3) core bind;;
      4) say '需要受限 Cloudflare API Token，已有同名路由不会被覆盖。'; core bind-auto;;
      5) core tunnel;;
      6) if confirm '已确认固定节点可用，关闭快捷隧道？'; then core stop-quick; fi;;
      7) core diagnose;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
quick_autostart_menu() {
  local n
  while :; do
    screen '管理开机自启'
    core quick-autostart status
    printf '\n'
    item 1 '开启开机重建'
    item 2 '关闭开机重建'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) core quick-autostart enable;;
      2) core quick-autostart disable;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
quick_protocol_menu() {
  local n protocol
  while :; do
    screen '设置快捷传输'
    say '自动模式可从 QUIC 回退到 HTTP/2；TCP 模式适合排查 UDP 不通。'
    say '更改后会重建快捷隧道，旧地址失效，请重新导入新链接。'
    printf '\n'
    item 1 '使用自动回退'
    item 2 '使用备用传输'
    item 0 '返回上级菜单'
    say '备用传输使用 HTTP/2（TCP），仅影响临时隧道。'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) protocol=auto;;
      2) protocol=http2;;
      *) say '请输入菜单序号。'; pause_once; continue;;
    esac
    if confirm '更换临时隧道传输并生成新地址？'; then core quick-protocol "$protocol"; fi
    pause_once
  done
}
node_logs_menu() {
  local n
  while :; do
    screen '节点日志'
    item 1 '查看节点日志'
    item 2 '查看快捷日志'
    item 3 '查看固定日志'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '节点日志'
    case "$n" in
      1) core logs singbox;; 2) core logs quick;; 3) core logs named;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
repair_node_menu() {
  local rc=0 n protocol
  core repair || rc=$?
  (( rc != 130 && rc != 143 )) || return "$rc"
  if (( rc == 0 )); then
    say '已显示当前链接；如需主动换新临时隧道，可在下面重建。'
  else
    say '修复后的连接检查未通过，请按上面的失败层继续处理。'
  fi
  while :; do
    printf '\n'
    item 1 '重新检查连接'
    item 2 '重建快捷隧道'
    item 3 '使用备用传输'
    item 4 '查看节点日志'
    item 5 '管理开机自启'
    item 0 '返回节点管理'
    say '重建适用于临时隧道问题；本机配置或握手失败请先查看节点日志。'
    n="$(ask '请选择：')" || return "$rc"
    [[ -n "$n" && "$n" != 0 ]] || return "$rc"
    case "$n" in
      1) core diagnose && return 0;;
      2|3)
        protocol=auto
        [[ "$n" != 3 ]] || protocol=http2
        if confirm '重建临时隧道会使旧地址失效，继续并重新导入新链接？'; then
          core quick-protocol "$protocol" && return 0
        fi
        ;;
      4) core logs singbox;;
      5) quick_autostart_menu;;
      *) say '请输入菜单序号。';;
    esac
  done
}
node_menu() {
  local n installed
  while :; do
    screen '节点管理'
    installed=no
    if node_configured; then
      installed=yes
      say "节点状态： $(node_label)"
      say '修复会检查后台服务并验证连接；重建临时地址前会另行确认。'
      printf '\n'
      item 1 '修复现有节点'
      item 2 '查看节点链接'
      item 3 '管理域名隧道'
      item 4 '查看运行状态'
      item 5 '重启节点服务'
      item 6 '查看节点日志'
      item 7 '检查节点连接'
      item 8 '优选节点地址'
    else
      say '本机尚未安装节点，选择「一键安装节点」开始。'
      printf '\n'
      item 1 '一键安装节点'
    fi
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    if [[ "$installed" == yes ]]; then
      case "$n" in
        3) tunnel_menu; continue;;
        6) node_logs_menu; continue;;
        8) cf_menu; continue;;
      esac
    fi
    screen '节点管理'
    if [[ "$installed" == no ]]; then
      case "$n" in
        1) core install;;
        *) say '请选择 1 安装节点，或选择 0 返回。';;
      esac
    else
      case "$n" in
        1) repair_node_menu;; 2) core show;; 4) node_services;; 5) core restart;; 7) core diagnose;;
        *) say '请输入菜单序号。';;
      esac
    fi
    pause_once
  done
}
swap_menu() {
  local n size
  while :; do
    screen '管理交换空间'
    say '仅管理本工具创建的 Swap；已有其他交换空间会保留。'
    printf '\n'
    item 1 '开启推荐容量'
    item 2 '指定交换容量'
    item 3 '关闭工具交换'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) optimize swap-on;;
      2)
        size="$(ask '交换容量（MiB，1024 = 1 GiB；留空取消）：')" || return
        if [[ -n "$size" ]]; then
          if [[ "$size" =~ ^[1-9][0-9]{0,6}$ ]]; then optimize swap-on "$size"
          else error '请输入有效的整数容量。'; fi
        fi
        ;;
      3) optimize swap-off;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
network_opt_menu() {
  local n
  while :; do
    screen '管理网络参数'
    say 'BBR 面向 TCP；fq 默认值与网卡正在使用的队列分别显示。'
    say '性能取决于实际链路，设置不会改变 Cloudflare 的带宽限制。'
    printf '\n'
    item 1 '开启推荐参数'
    item 2 '恢复原有参数'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      1) optimize bbr-on;; 2) optimize bbr-off;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
optimize_menu() {
  local n
  while :; do
    screen '机器优化'
    optimize status || say '部分系统状态无法读取，可在建议页查看限制。'
    printf '\n'
    item 1 '查看优化建议'
    item 2 '应用推荐设置'
    item 3 '管理交换空间'
    item 4 '管理网络参数'
    item 5 '恢复原有设置'
    item 0 '返回工具主页'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    case "$n" in
      3) swap_menu; continue;;
      4) network_opt_menu; continue;;
    esac
    screen '机器优化'
    case "$n" in
      1) optimize recommend;; 2) optimize apply;; 5) optimize restore;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
tool_menu() {
  local n
  while :; do
    screen '更新卸载'
    item 1 '更新管理工具'
    item 2 '卸载管理工具'
    item 0 '返回上级菜单'
    n="$(ask '请选择：')" || return
    [[ -n "$n" && "$n" != 0 ]] || return
    screen '更新卸载'
    case "$n" in
      1) if update_cli; then restore_initial_timezone; exec "$HOME/.local/bin/ibt"; fi;;
      2) if remove_all; then exit 0; fi;;
      *) say '请输入菜单序号。';;
    esac
    pause_once
  done
}
main_menu() {
  [[ -r /dev/tty && -w /dev/tty ]] || { error '请通过 SSH 登录后打开菜单。'; return 1; }
  local n host
  host="$(hostname 2>/dev/null | tr -cd 'a-zA-Z0-9._-' || true)"
  while :; do
    screen
    say "本机名称： ${host:-Linux}"
    say "保活状态： $(service_label insta-box-heartbeat.timer)"
    say "节点状态： $(node_label)"
    printf '\n'
    item 1 '本机信息'
    item 2 '查看节点'
    item 3 '节点管理'
    item 4 '机器保活'
    item 5 '机器管理'
    item 6 '机器优化'
    item 7 '更新卸载'
    item 0 '退出菜单'
    printf '\n'
    n="$(ask '请选择：')" || break
    case "$n" in
      0|'') break;;
      1) info_menu; continue;;
      2)
        if node_configured; then
          screen '查看节点'; core show; pause_once
        else node_menu; fi
        ;;
      3) node_menu; continue;;
      4) machine_pages keepalive; continue;;
      5) machine_pages cloud; continue;;
      6) optimize_menu; continue;;
      7) tool_menu; continue;;
      *) say '请输入 0–7。'; pause_once;;
    esac
  done
}
help_msg() {
  printf '\n  InstaBox Tool v%s · 作者 %s\n' "$VERSION" "$AUTHOR"
  printf '  ────────────────────────────────────────────\n\n'
  local command description
  while IFS=$'\t' read -r command description; do
    if (( ${#command} > 30 )); then
      printf '  %s\n    %s\n' "$command" "$description" || return
    else
      printf '  %-30s %s\n' "$command" "$description" || return
    fi
  done <<'EOF'
ibt	打开管理菜单
ibt info [--json]	查看当前本机系统、资源、网络与服务
ibt timezone status	查看显示时区
ibt timezone set Asia/Shanghai	保存北京时间显示（不改系统时区）
ibt timezone reset	清除工具设置，跟随系统时区或显式 TZ
ibt install / show	安装节点 / 查看链接
ibt status / restart	运行状态 / 重启节点
ibt repair	修复后台服务并检查本机与隧道连接
ibt quick / refresh-quick	启动快捷隧道 / 刷新地址
ibt diagnose	分层检查本机与临时域名连接（隐藏凭据）
ibt quick-protocol auto|http2	设置快捷传输并重建临时地址
ibt quick-autostart status|enable|disable	管理开机自动新建临时隧道
ibt cf	生成 CF 优选 VLESS 链接，自动准备依赖
ibt cf --show-last	查看上次生成的优选链接
ibt bind / bind-auto	手动 / 自动绑定域名
ibt tunnel / stop-quick	托管固定隧道 / 关闭快捷隧道
ibt keepalive auto	一键保活当前授权可见的运行中机器
ibt keepalive auto-local	自动识别并保活当前机器
ibt keepalive setup	配置 API 保活或 SSH 保活（单台 / 多台）
ibt keepalive setup-api	选择机器，配置 API 保活（推荐）
ibt keepalive setup-ssh	粘贴 SSH / Mosh 临时连接命令
ibt keepalive add|add-api	添加 SSH / API 保活目标
ibt keepalive renew	更新某个目标的 SSH 临时凭据
ibt keepalive rotate-setup	配置 SSH token 自动换新（共用 API Key）
ibt keepalive rotate-now	立即签发并验证新 token
ibt keepalive rotate-off	停用 SSH token 自动换新
ibt keepalive token-status	查看自动换新与真实到期信息
ibt keepalive status|run	查看保活状态 / 立即执行一轮
ibt keepalive start|stop	启用 / 停止本机保活任务
ibt keepalive remove|clear	移除目标 / 停用并清空保活配置
ibt keepalive logs	查看后台保活日志
ibt keepalive apply|check	配置 / 读回平台暂停策略
ibt cloud	查看全部云端机器及本机保活状态
ibt cloud batch start	选择一台或多台机器启动
ibt cloud batch pause|stop	选择一台或多台机器暂停 / 停止
ibt cloud protect on|off	为所选机器开启 / 关闭本机 API 保活
ibt cloud info --choose	选择一台机器查看详情
ibt cloud operations	选择一台机器查询云端操作进度
ibt cloud info|list|select	详情 / 机器列表 / 命令行默认目标
ibt cloud start|resume	启动 / 恢复所选机器
ibt cloud pause|stop	暂停 / 停止机器（需确认）
ibt cloud wake	仅唤醒因空闲自动暂停的机器
ibt cloud account	查看账户配额和平台规则
ibt cloud operation	查询最近提交的云端操作
ibt doctor	精简平台策略诊断
ibt machines / resume	选择 / 恢复机器（cloud 命令别名）
ibt key set|status|forget	统一管理 API Key（云端 / 保活 / 凭据换新共用）
ibt logs [singbox|quick|named]	查看所选服务日志
ibt optimize status	查看内存、Swap、内核、BBR 与队列
ibt optimize recommend	按本机情况生成优化建议（只读）
ibt optimize apply	确认后应用推荐 Swap 与 BBR + fq
ibt optimize swap-on [MiB]	开启本工具 Swap（不填则采用建议容量）
ibt optimize swap-off	关闭本工具创建的 Swap
ibt optimize bbr-on|bbr-off	开启 BBR + fq / 恢复原值
ibt optimize restore	恢复本工具管理的系统设置
ibt update / uninstall	更新 / 卸载工具
EOF
}
case "${1:-menu}" in
  version|--version|help|-h|--help|timezone) ;;
  *) refresh_display_timezone;;
esac
case "${1:-menu}" in
  menu) main_menu;;
  info) shift; local_info "$@";;
  timezone) time_settings "${2:-status}" "${@:3}";;
  status) services;;
  keepalive) shift; platform "$@";;
  cloud) cloud "${2:-overview}" "${@:3}";;
  optimize) optimize "${2:-status}" "${@:3}";;
  cf) shift; cf_nodes "$@";;
  doctor) platform doctor "${2:-}";;
  machines) cloud select "${@:2}";;
  resume) cloud resume "${@:2}";;
  key) case "${2:-status}" in set|status|forget) cloud key "${2:-status}";; *) error '使用 ibt key set|status|forget'; exit 2;; esac;;
  update) update_cli;;
  uninstall) remove_all;;
  install|show|quick|refresh-quick|quick-protocol|quick-autostart|diagnose|bind|bind-auto|stop-quick|tunnel|logs|restart|repair) core "$@";;
  version|--version) printf '%s\n' "$VERSION";;
  help|-h|--help) help_msg;;
  *) error '未知操作，请运行 ibt help。'; exit 2;;
esac
