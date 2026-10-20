#!/usr/bin/env bash
# Author: Pre
# InstaBox Tool: a user-scoped VLESS/WebSocket node with a managed Cloudflare tunnel.
# Only generic defaults are here. Domain, UUID, path and Tunnel tokens stay on the VM.
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

SB_VERSION='1.14.2'
SB_ARCHIVE="sing-box-${SB_VERSION}-linux-amd64.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/${SB_ARCHIVE}"
SB_SHA256='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6'
CF_VERSION='2026.10.1'
CF_URL="https://github.com/cloudflare/cloudflared/releases/download/${CF_VERSION}/cloudflared-linux-amd64"
CF_SHA256='3bfc539f45d2620c71debb7a86be0efa737ed5ccbad9eb85c787116900e5c586'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CF_HELPER="$SCRIPT_DIR/cf_route.py"
NODE_PROBE="$SCRIPT_DIR/node_probe.py"

APP_DIR="${HOME}/.local/share/insta-box"
BIN_DIR="${APP_DIR}/bin"
SB_BIN="${BIN_DIR}/sing-box"
CF_BIN="${BIN_DIR}/cloudflared"
CONFIG="${APP_DIR}/config.json"
STATE="${APP_DIR}/state.conf"
QUICK_LOG="${APP_DIR}/quick.log"
QUICK_LAUNCHER="${BIN_DIR}/start-quick-tunnel"
QUICK_PROTOCOL="${APP_DIR}/quick-protocol"
UNIT_DIR="${HOME}/.config/systemd/user"
SB_SERVICE='insta-box-node.service'
CF_SERVICE='insta-box-tunnel.service'
QUICK_SERVICE='insta-box-quick.service'
SB_UNIT="${UNIT_DIR}/${SB_SERVICE}"
CF_UNIT="${UNIT_DIR}/${CF_SERVICE}"
QUICK_UNIT="${UNIT_DIR}/${QUICK_SERVICE}"
MARKER='# Managed-by: InstaBox Tool'
LEGACY_MARKER='# Managed-by: Insta Box'
owned_unit() { grep -Fqx "$MARKER" "$1" || grep -Fqx "$LEGACY_MARKER" "$1"; }

BOLD='' ACCENT='' YELLOW='' RED='' DIM='' RESET=''
if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
  BOLD=$'\e[1m'; ACCENT=$'\e[38;5;75m'; YELLOW=$'\e[33m'
  RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m'
fi
say() { printf '  %s\n' "$*"; }
field() { printf '  %s： %s\n' "$1" "$2"; }
section() {
  printf '\n  %s%s%s\n' "$BOLD$ACCENT" "$1" "$RESET"
  printf '  %s────────────────────────────────────────────%s\n' "$DIM" "$RESET"
}
info() { printf '  %s[信息]%s %s\n' "$ACCENT" "$RESET" "$*"; }
warn() { printf '  %s[提示]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() { printf '  %s[失败]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令 $1；请先安装该系统依赖。"; }
preflight() {
  [[ "$(uname -s)" == Linux ]] || die '本脚本只支持 Linux。'
  [[ "$(uname -m)" == x86_64 || "$(uname -m)" == amd64 ]] || die '目前只支持 Linux amd64。'
  (( EUID != 0 )) || die '请用普通用户执行，勿使用 sudo bash。'
  local tool
  for tool in curl sha256sum tar awk grep sed tr od find install mktemp stat python3 systemctl journalctl; do need "$tool"; done
  systemctl --user show-environment >/dev/null 2>&1 || die '用户级 systemd 当前不可用，请从 SSH 登录后检查 systemctl --user status。'
}
read_state() {
  [[ -s "$STATE" ]] || die '未找到部署记录，请先运行安装命令。'
  UUID="$(awk -F= '$1=="uuid" {print substr($0,6); exit}' "$STATE")"
  WS_PATH="$(awk -F= '$1=="path" {print substr($0,6); exit}' "$STATE")"
  PORT="$(awk -F= '$1=="port" {print substr($0,6); exit}' "$STATE")"
  DOMAIN="$(awk -F= '$1=="domain" {print substr($0,8); exit}' "$STATE")"
  MODE="$(awk -F= '$1=="mode" {print substr($0,6); exit}' "$STATE")"
  [[ -n "$MODE" ]] || MODE='fixed' # Backwards compatibility with the first release.
  [[ "$UUID" =~ ^[0-9a-f-]{36}$ && "$WS_PATH" =~ ^/ws-[0-9a-f]{36}$ && "$PORT" =~ ^[0-9]+$ ]] || die '本地部署记录无效。'
}
write_state() {
  install -d -m 700 "$APP_DIR"
  local tmp
  tmp="$(mktemp "${STATE}.tmp.XXXXXX")"
  printf 'mode=%s\ndomain=%s\nuuid=%s\npath=%s\nport=%s\n' "$MODE" "$DOMAIN" "$UUID" "$WS_PATH" "$PORT" > "$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$STATE"
}
check_domain() {
  local new_domain="${1:-}"
  [[ -n "$new_domain" ]] || die '请输入域名，例如 proxy.example.com（不含 https://）。'
  new_domain="${new_domain,,}"
  [[ "$new_domain" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die '域名格式错误。'
  [[ "$new_domain" != *.trycloudflare.com ]] || die 'Quick Tunnel 临时域名不能当作固定域名绑定。'
  DOMAIN="$new_domain"
}
validate_port() {
  PORT="${IBT_PORT:-${IB_PORT:-${SB_PORT:-20000}}}"
  [[ "$PORT" =~ ^[1-9][0-9]{3,4}$ ]] || die '端口必须是 1024～65535。'
  (( 10#$PORT >= 1024 && 10#$PORT <= 65535 )) || die '端口超出范围。'
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnH | awk -v p="$PORT" '$4 ~ (":"p"$") {found=1} END {exit !found}'; then
      die "本机端口 $PORT 已占用。可以指定 IBT_PORT=20001。"
    fi
  fi
}
make_link() {
  local host="$1" label="$2" url_path="${WS_PATH//\//%2F}"
  printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%s#%s\n' \
    "$UUID" "$host" "$host" "$host" "$url_path" "$label"
}
quick_host() {
  [[ -s "$QUICK_LOG" ]] || return 1
  local addr
  addr="$(grep -oE 'https://[A-Za-z0-9-]+\.trycloudflare\.com' "$QUICK_LOG" | tail -n 1 || true)"
  [[ -n "$addr" ]] || return 1
  printf '%s\n' "${addr#https://}"
}
show_main() {
  read_state
  SHOW_QUICK_STATUS=1
  section '节点链接'
  if [[ -n "$DOMAIN" ]]; then
    printf '\n'
    field '节点类型' '固定节点'
    field '访问域名' "$DOMAIN"
    printf '\n'
    make_link "$DOMAIN" 'InstaBox-Tool-Fixed'
    printf '\n'
    field '本机入口' "http://127.0.0.1:$PORT"
  fi
  local host
  if systemctl --user is-active --quiet "$QUICK_SERVICE" && host="$(quick_host)"; then
    printf '\n'
    field '节点名称' 'IBT-Quick'
    field '访问域名' "$host"
    printf '\n'
    make_link "$host" 'IBT-Quick'
    printf '\n'
    if [[ -f "$NODE_PROBE" ]] && python3 "$NODE_PROBE" check-quick --timeout 5 --quiet --expect-host "$host"; then
      SHOW_QUICK_STATUS=0
      field '链路检查' 'WebSocket 握手通过'
      field '使用提示' '请在客户端确认实际上网。'
    else
      field '链路检查' '尚未通过，请运行 ibt diagnose。'
    fi
    field '地址更新' '隧道重建后，用 ibt show 获取新链接并重新导入。'
  elif [[ -z "$DOMAIN" ]]; then
    warn '隧道尚未生成地址，请用 ibt logs quick 查看连接情况。'
  fi
  printf '\n'
  field '导入方式' '复制完整 vless:// 链接；链接含凭据，请勿公开。'
  printf '\n'
}

ensure_linger() {
  command -v loginctl >/dev/null 2>&1 || { warn '没有 loginctl，无法验证重启后是否自启。'; return; }
  local linger
  linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
  if [[ "$linger" == yes ]]; then return; fi
  if [[ "${IBT_NO_SUDO:-0}" == 1 || "${IB_NO_SUDO:-0}" == 1 || "${SB_NO_SUDO:-0}" == 1 ]]; then warn '已按设置跳过启用 Linger；开机自启可能受到限制。'; return; fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    if sudo -n loginctl enable-linger "$(id -un)"; then info '后台驻留已启用，退出终端后继续运行。'; return; fi
  fi
  warn '无法自动启用 Linger；如有权限，可执行 sudo loginctl enable-linger "$USER"。'
}
fetch_verified() {
  local url="$1" digest="$2" dest="$3" temp
  temp="$(mktemp "${APP_DIR}/download.XXXXXX")"
  if ! curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 "$url" -o "$temp"; then
    rm -f -- "$temp"; die '无法下载官方发行包。'
  fi
  if ! printf '%s  %s\n' "$digest" "$temp" | sha256sum -c --status; then
    rm -f -- "$temp"; die '官方发行包 SHA-256 验证失败，已停止。'
  fi
  mv -f -- "$temp" "$dest"
}
install_singbox() {
  install -d -m 700 "$APP_DIR" "$BIN_DIR"
  local temp unpacked
  temp="${APP_DIR}/${SB_ARCHIVE}"
  info "正在从 sing-box 官方仓库下载 v${SB_VERSION}..."
  fetch_verified "$SB_URL" "$SB_SHA256" "$temp"
  local unpack_dir
  unpack_dir="$(mktemp -d "${APP_DIR}/unpack.XXXXXX")"
  if ! tar -xzf "$temp" -C "$unpack_dir"; then
    rm -rf -- "$unpack_dir" "$temp"; die 'sing-box 官方发行包无法解压。'
  fi
  unpacked="$(find "$unpack_dir" -type f -name sing-box -print -quit)"
  [[ -n "$unpacked" ]] || die '发行包中找不到 sing-box 二进制。'
  install -m 700 "$unpacked" "${SB_BIN}.new"
  mv -f -- "${SB_BIN}.new" "$SB_BIN"
  rm -rf -- "$unpack_dir" "$temp"
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  WS_PATH="/ws-$(od -An -N 18 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$UUID" =~ ^[a-f0-9-]{36}$ && "$WS_PATH" =~ ^/ws-[a-f0-9]{36}$ ]] || die '生成 UUID 或 WebSocket Path 失败。'
  cat > "$CONFIG" <<EOF
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "vless", "tag": "vless-ws",
      "listen": "127.0.0.1", "listen_port": ${PORT},
      "users": [{"name": "private", "uuid": "${UUID}"}],
      "transport": {"type": "ws", "path": "${WS_PATH}"}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF
  chmod 600 "$CONFIG"
  "$SB_BIN" check -c "$CONFIG" || die 'sing-box 配置验证失败。'
}
install_singbox_unit() {
  install -d -m 700 "$UNIT_DIR"
  if [[ -e "$SB_UNIT" ]]; then
    owned_unit "$SB_UNIT" || die '服务名与其他项目冲突，未覆盖。'
  else
  cat > "$SB_UNIT" <<'EOF'
# Managed-by: InstaBox Tool
[Unit]
Description=InstaBox Tool (VLESS over WebSocket)
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=%h/.local/share/insta-box/bin/sing-box run -c %h/.local/share/insta-box/config.json
Restart=always
RestartSec=5
NoNewPrivileges=yes
[Install]
WantedBy=default.target
EOF
  fi
  systemctl --user daemon-reload
  if ! systemctl --user enable --now "$SB_SERVICE" || ! systemctl --user is-active --quiet "$SB_SERVICE"; then
    warn 'sing-box 服务启动失败，可用 logs 查看原因。'
    die '安装未完成，需排查 sing-box 服务。'
  fi
  info 'sing-box 后台服务已经启动。'
}
ensure_cloudflared() {
  [[ -x "$CF_BIN" ]] && return
  install -d -m 700 "$BIN_DIR"
  local reused="${HOME}/bin/cloudflared"
  if [[ -x "$reused" ]] && printf '%s  %s\n' "$CF_SHA256" "$reused" | sha256sum -c --status; then
    install -m 700 "$reused" "$CF_BIN"
    info '复用已有且 SHA-256 校验通过的 cloudflared。'
    return
  fi
  info "正在从 Cloudflare 官方仓库下载 cloudflared ${CF_VERSION}..."
  fetch_verified "$CF_URL" "$CF_SHA256" "$CF_BIN"
  chmod 700 "$CF_BIN"
}
install_named_tunnel_unit() {
  # Existing named Tunnel; never create/modify/replace its DNS or route.
  local token_path=''
  for f in '%h/.config/cloudflared/token' '%h/.config/cloudflared/tunnel.token'; do
    local relative="${f#%h}"
    if [[ -s "${HOME}${relative}" ]]; then token_path="$f"; break; fi
  done
  if [[ -z "$token_path" ]]; then
    return
  fi
  if [[ -e "$CF_UNIT" ]]; then
    if owned_unit "$CF_UNIT"; then
      systemctl --user enable --now "$CF_SERVICE" || warn '固定隧道启动失败，请查看日志。'
    else
      warn '固定隧道由其他工具管理，未修改。'
    fi
    return
  fi
  if systemctl --user is-active --quiet cloudflared.service; then
    info '已有其他 cloudflared 用户服务在线，跳过创建重复服务。'
    return
  fi
  install -d -m 700 "$UNIT_DIR"
  cat > "$CF_UNIT" <<EOF
# Managed-by: InstaBox Tool
[Unit]
Description=InstaBox Tool Cloudflare Named Tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=%h/.local/share/insta-box/bin/cloudflared tunnel run --token-file ${token_path}
Restart=always
RestartSec=5
NoNewPrivileges=yes
[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  if systemctl --user enable --now "$CF_SERVICE" && systemctl --user is-active --quiet "$CF_SERVICE"; then
    info '已将原有固定 Tunnel 配成后台服务（保留原有 DNS 和路由）。'
  else
    warn '固定 Tunnel 后台服务未正常启动；请检查 logs named。'
  fi
}
prepare_quick_directory() {
  local directory permissions
  for directory in "$HOME" "$HOME/.local" "$HOME/.local/share" "$APP_DIR" "$BIN_DIR"; do
    if [[ -e "$directory" || -L "$directory" ]]; then
      [[ -d "$directory" && ! -L "$directory" && -O "$directory" ]] || die '快捷隧道目录类型或归属异常，未修改。'
      permissions="$(stat -c %a -- "$directory")"
      (( (8#$permissions & 022) == 0 )) || die '快捷隧道目录可被其他用户写入，未修改。'
    fi
  done
  install -d -m 700 "$APP_DIR" "$BIN_DIR"
}
write_quick_launcher() {
  local tmp
  prepare_quick_directory
  if [[ -e "$QUICK_LAUNCHER" || -L "$QUICK_LAUNCHER" ]]; then
    [[ -f "$QUICK_LAUNCHER" && ! -L "$QUICK_LAUNCHER" && -O "$QUICK_LAUNCHER" ]] || die '快捷隧道启动器类型或归属异常，未修改。'
    [[ "$(stat -c %h -- "$QUICK_LAUNCHER")" == 1 ]] || die '快捷隧道启动器存在额外链接，未修改。'
  fi
  tmp="$(mktemp "${BIN_DIR}/start-quick.XXXXXX")"
  cat > "$tmp" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
base="${HOME}/.local/share/insta-box"
port="$(awk -F= '$1=="port" {print substr($0,6); exit}' "${base}/state.conf")"
[[ "$port" =~ ^[1-9][0-9]{3,4}$ ]] || exit 2
(( 10#$port >= 1024 && 10#$port <= 65535 )) || exit 2
for file in quick-protocol quick-config.yml quick.log; do
  if [[ -e "${base}/${file}" || -L "${base}/${file}" ]]; then
    [[ -f "${base}/${file}" && ! -L "${base}/${file}" && -O "${base}/${file}" ]] || exit 2
    [[ "$(stat -c %h -- "${base}/${file}")" == 1 ]] || exit 2
  fi
done
protocol=auto
if [[ -f "${base}/quick-protocol" ]]; then
  IFS= read -r protocol < "${base}/quick-protocol" || exit 2
else
  printf 'auto\n' > "${base}/quick-protocol"
  chmod 600 "${base}/quick-protocol"
fi
[[ "$protocol" == auto || "$protocol" == http2 ]] || exit 2
# An explicit empty config prevents unrelated named-tunnel ingress from winning
# over --url. It does not change the user's ~/.cloudflared configuration.
if [[ -f "${base}/quick-config.yml" && "$(< "${base}/quick-config.yml")" != '{}' ]]; then
  exit 2
fi
printf '{}\n' > "${base}/quick-config.yml"
chmod 600 "${base}/quick-config.yml"
: > "${base}/quick.log"
chmod 600 "${base}/quick.log"
invocation="${INVOCATION_ID:-}"
[[ "$invocation" =~ ^[0-9a-f]{32}$ ]] || invocation=unknown
printf 'IBT_QUICK_INVOCATION=%s\n' "$invocation" >> "${base}/quick.log"
# Do not inherit named-tunnel or demo-origin settings from the user manager.
unset TUNNEL_NAME TUNNEL_HELLO_WORLD
exec "${base}/bin/cloudflared" tunnel --config "${base}/quick-config.yml" --protocol "$protocol" --no-autoupdate --url "http://127.0.0.1:${port}" >> "${base}/quick.log" 2>&1
EOF
  chmod 700 "$tmp"
  mv -fT -- "$tmp" "$QUICK_LAUNCHER"
}
install_quick_unit() {
  if [[ -e "$QUICK_UNIT" ]]; then
    owned_unit "$QUICK_UNIT" || die 'Quick Tunnel 服务名与已有服务冲突，已停止以免覆盖。'
  else
    install -d -m 700 "$UNIT_DIR"
    cat > "$QUICK_UNIT" <<'EOF'
# Managed-by: InstaBox Tool
[Unit]
Description=InstaBox Tool Cloudflare Quick Tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
UMask=0077
ExecStart=%h/.local/share/insta-box/bin/start-quick-tunnel
Restart=always
RestartSec=5
NoNewPrivileges=yes
[Install]
WantedBy=default.target
EOF
  fi
  systemctl --user daemon-reload
  systemctl --user enable --now "$QUICK_SERVICE" || warn 'Quick Tunnel 服务启动未成功。'
}
wait_quick() {
  [[ -f "$NODE_PROBE" ]] || { warn '连接检查组件缺失，请运行 ibt update。'; return 1; }
  info '正在检查节点连接…'
  # A just-restarted process can briefly leave the old log visible. Wait for
  # the currently bound service instance, within one total deadline.
  if python3 "$NODE_PROBE" check-quick --wait-seconds 60 --timeout 8 --quiet; then
    return 0
  fi
  warn '配置已生成，但链路检查尚未通过；请运行 ibt diagnose。'
  return 1
}
quick_autostart_status() {
  local boot linger node active
  need systemctl
  boot="$(systemctl --user is-enabled "$QUICK_SERVICE" 2>/dev/null || true)"
  node="$(systemctl --user is-enabled "$SB_SERVICE" 2>/dev/null || true)"
  active="$(systemctl --user is-active "$QUICK_SERVICE" 2>/dev/null || true)"
  linger=''
  if command -v loginctl >/dev/null 2>&1; then
    linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
  fi
  case "$boot" in
    enabled)
      if [[ "$linger" == yes && "$node" == enabled ]]; then
        printf '  开机重建： 已开启（完整重启后创建新的临时域名）\n'
      else
        printf '  开机重建： 已设持久自启，依赖待确认\n'
      fi;;
    disabled) printf '  开机重建： 已关闭\n';;
    masked|masked-runtime) printf '  开机重建： 服务已被屏蔽，未更改\n';;
    enabled-runtime) printf '  开机重建： 仅本次运行启用，尚未持久设置\n';;
    *) printf '  开机重建： 尚未配置或无法确认\n';;
  esac
  if [[ "$linger" == yes ]]; then printf '  后台驻留： 已启用\n'
  else printf '  后台驻留： 未确认，需要开启用户 Linger\n'; fi
  if [[ "$node" == enabled ]]; then printf '  节点自启： 已启用\n'
  else printf '  节点自启： 未确认，可用 ibt repair 检查修复\n'; fi
  if [[ "$active" == active ]]; then printf '  当前隧道： 运行中\n'
  elif [[ "$active" == inactive ]]; then printf '  当前隧道： 未运行\n'
  elif [[ "$active" == failed ]]; then printf '  当前隧道： 运行失败\n'
  else printf '  当前隧道： 尚未稳定或无法读取\n'; fi
  printf '  开关只影响下次开机；关闭不会停止当前隧道或其故障重启。\n'
  printf '  平台暂停后恢复不一定重新启动进程；需要时请手动重建。\n'
}
quick_autostart_main() {
  local action="${1:-status}" boot linger node
  [[ "$action" == status || "$action" == enable || "$action" == disable ]] || die '用法：ibt quick-autostart status|enable|disable。'
  if [[ "$action" == status ]]; then quick_autostart_status; return; fi
  preflight; read_state
  [[ -f "$QUICK_UNIT" && ! -L "$QUICK_UNIT" && -O "$QUICK_UNIT" ]] || die '快捷服务缺失、已屏蔽或归属异常，请先通过隧道菜单检查；未修改。'
  [[ "$(stat -c %h -- "$QUICK_UNIT")" == 1 ]] && owned_unit "$QUICK_UNIT" || die '快捷服务不属于本工具的独立文件，未修改。'
  if [[ "$action" == disable ]]; then
    systemctl --user disable "$QUICK_SERVICE" || die '关闭开机重建失败，当前隧道未停止。'
    boot="$(systemctl --user is-enabled "$QUICK_SERVICE" 2>/dev/null || true)"
    [[ "$boot" == disabled ]] || die '未确认开机重建已关闭，请检查服务设置。'
    info '已关闭开机重建；当前隧道与节点配置保持不变。'
  else
    [[ -x "$QUICK_LAUNCHER" && -x "$CF_BIN" ]] || die '快捷组件不完整，请先修复或明确重建节点。'
    ensure_linger
    systemctl --user enable "$QUICK_SERVICE" || die '开启开机重建失败，当前隧道未重启。'
    boot="$(systemctl --user is-enabled "$QUICK_SERVICE" 2>/dev/null || true)"
    [[ "$boot" == enabled ]] || die '未确认持久开机自启，不能保证重启后新建隧道。'
    linger=''
    if command -v loginctl >/dev/null 2>&1; then
      linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
    fi
    node="$(systemctl --user is-enabled "$SB_SERVICE" 2>/dev/null || true)"
    if [[ "$linger" != yes || "$node" != enabled ]]; then
      quick_autostart_status
      warn '快捷服务已设自启，但后台驻留或节点自启尚未确认，请用 ibt repair 检查。'
      return 1
    fi
    info '已开启开机重建；下次完整开机将创建新临时域名，当前隧道未重启。'
  fi
  quick_autostart_status
}
report_quick_connection() {
  local rc=0
  wait_quick || rc=$?
  show_main
  # The last probe is bound to the exact displayed host. A restart between
  # the initial wait and display must never leave a stale success result.
  [[ "$SHOW_QUICK_STATUS" != 0 ]] || return 0
  (( rc != 0 )) || rc=1
  return "$rc"
}
install_main() {
  preflight
  if [[ -f "$STATE" ]]; then
    info '检测到已有节点，保留链接并检查后台服务。'
    local repair_rc=0
    # A separate Bash process retains errexit inside repair helpers. Calling
    # repair_main in an OR-list would suppress it for every nested function.
    bash "$SCRIPT_DIR/install.sh" repair || repair_rc=$?
    return "$repair_rc"
  fi
  [[ ! -e "$CONFIG" && ! -e "$SB_UNIT" ]] || die '检测到旧安装残留，不能安全覆盖；请先检查已有文件。'
  [[ -f "$SCRIPT_DIR/cloud.py" && -f "$SCRIPT_DIR/heartbeat.py" ]] || die '首次安装组件不完整，请通过 setup.sh 重新安装。'
  python3 "$SCRIPT_DIR/cloud.py" key ensure || die 'API Key 验证未通过，尚未安装节点。'
  validate_port
  install_singbox
  MODE='quick'; DOMAIN=''
  if [[ -n "${IBT_DOMAIN:-${IB_DOMAIN:-${SB_DOMAIN:-}}}" ]]; then check_domain "${IBT_DOMAIN:-${IB_DOMAIN:-${SB_DOMAIN:-}}}"; MODE='fixed-pending'; fi
  write_state
  install_singbox_unit
  ensure_linger
  ensure_cloudflared
  install_named_tunnel_unit
  write_quick_launcher
  install_quick_unit
  local probe_rc=0
  if report_quick_connection; then
    :
  else
    probe_rc=$?
    warn '节点组件已经安装，网络连接仍需排查。'
  fi
  section '机器保活'
  info '正在自动配置本机保活…'
  local keepalive_rc=0
  python3 "$SCRIPT_DIR/heartbeat.py" auto-local || keepalive_rc=$?
  if (( keepalive_rc != 0 )); then
    warn '节点已保留，但自动保活尚未完成；请运行 ibt keepalive auto-local 重试。'
    return "$keepalive_rc"
  fi
  field '查看状态' 'ibt keepalive status'
  if (( probe_rc != 0 )); then
    warn '保活已配置，节点链路仍待确认；请运行 ibt diagnose 继续检查。'
    return "$probe_rc"
  fi
}
repair_main() {
  preflight; read_state
  local service_rc=0 probe_rc=0
  [[ -x "$SB_BIN" && -s "$CONFIG" ]] || die '节点文件不完整；请先备份配置再处理，不会覆盖原链接。'
  "$SB_BIN" check -c "$CONFIG" || die '配置校验未通过，请查看节点日志。'
  install_singbox_unit
  ensure_linger
  ensure_cloudflared
  install_named_tunnel_unit
  if [[ -f "$QUICK_UNIT" ]] && owned_unit "$QUICK_UNIT"; then
    if systemctl --user is-active --quiet "$QUICK_SERVICE" ||
       systemctl --user is-enabled --quiet "$QUICK_SERVICE"; then
      write_quick_launcher
      if ! systemctl --user start "$QUICK_SERVICE"; then
        service_rc=1
        warn '快捷隧道未能恢复，请查看日志。'
      fi
      info '已更新快捷启动文件；正在运行的隧道须重建后加载新参数，旧地址暂时保留。'
    else
      info '快捷隧道已停用，保持原设置。需要时可在隧道菜单明确启动。'
    fi
  else
    warn '未找到可管理的快捷服务；如需临时节点，请在隧道菜单选择启动或重建。'
  fi
  info '后台服务检查完成，开始验证节点连接。'
  diagnose_main || probe_rc=$?
  # A restarted VM may be healthy while the client still holds yesterday's
  # temporary hostname. Always present the current link, without restarting it.
  show_main || { (( probe_rc != 0 )) || probe_rc=1; }
  if systemctl --user is-active --quiet "$QUICK_SERVICE" && [[ "$SHOW_QUICK_STATUS" != 0 ]]; then
    (( probe_rc != 0 )) || probe_rc=1
  fi
  if (( probe_rc != 0 )); then
    warn '连接检查尚未通过，请按诊断提示处理；后台启动不代表节点可以上网。'
    return "$probe_rc"
  fi
  if (( service_rc != 0 )); then
    warn '本次仍有服务操作失败，请检查快捷隧道日志。'
    return "$service_rc"
  fi
  return 0
}
refresh_quick_main() {
  preflight; read_state
  ensure_cloudflared
  write_quick_launcher
  install_quick_unit
  systemctl --user restart "$QUICK_SERVICE"
  report_quick_connection
}
quick_main() {
  preflight; read_state
  if [[ -f "$SB_UNIT" ]] && owned_unit "$SB_UNIT"; then
    systemctl --user enable --now "$SB_SERVICE" || warn 'sing-box 服务未能自动启动，请查看 logs。'
  fi
  ensure_linger
  ensure_cloudflared
  write_quick_launcher
  install_quick_unit
  report_quick_connection
}
quick_protocol_main() {
  preflight; read_state
  local protocol="${1:-}" tmp
  [[ "$protocol" == auto || "$protocol" == http2 ]] || die '用法：ibt quick-protocol auto|http2（会重建临时隧道并更换地址）。'
  prepare_quick_directory
  if [[ -e "$QUICK_PROTOCOL" || -L "$QUICK_PROTOCOL" ]]; then
    [[ -f "$QUICK_PROTOCOL" && ! -L "$QUICK_PROTOCOL" && -O "$QUICK_PROTOCOL" ]] || die '临时隧道协议文件归属异常，未修改。'
    [[ "$(stat -c %h -- "$QUICK_PROTOCOL")" == 1 ]] || die '临时隧道协议文件存在额外链接，未修改。'
  fi
  tmp="$(mktemp "${QUICK_PROTOCOL}.tmp.XXXXXX")"
  printf '%s\n' "$protocol" > "$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$QUICK_PROTOCOL"
  info "临时隧道传输已设为 $protocol；正在重建，请重新导入下面的新链接。"
  refresh_quick_main
}
diagnose_main() {
  need python3
  [[ -f "$NODE_PROBE" ]] || die '连接检查组件缺失，请运行 ibt update。'
  python3 "$NODE_PROBE" status "$@"
}
bind_main() {
  read_state
  local d="${IBT_DOMAIN:-${IB_DOMAIN:-${SB_DOMAIN:-${1:-}}}}"
  if [[ -z "$d" ]]; then
    [[ -t 0 ]] || die '需要一个固定域名：IBT_DOMAIN=proxy.example.com bash install.sh bind'
    read -r -p '  代理域名（如 proxy.example.com）： ' d
  fi
  check_domain "$d"
  MODE='fixed-pending'
  write_state
  section 'Cloudflare 域名绑定'
  say '打开 Zero Trust → Networking → Tunnels → 选择已有 Tunnel。'
  say '进入 Routes → Add route → Published application，填写：'
  printf '\n'
  field '代理域名' "${DOMAIN}（Public hostname）"
  field '服务类型' 'HTTP（Service type）'
  field '服务地址' "127.0.0.1:${PORT}（Service URL）"
  field '路径设置' '留空（Path）'
  printf '\n'
  say '保存路由并确认 DNS 后，将固定节点导入客户端验证。'
  say '临时节点继续运行；确认固定节点可用后，可在隧道菜单关闭。'
  show_main
}
bind_auto_main() {
  preflight
  need python3
  read_state
  local d="${IBT_DOMAIN:-${IB_DOMAIN:-${SB_DOMAIN:-${1:-}}}}"
  if [[ -z "$d" ]]; then
    [[ -t 0 ]] || die '自动绑定需要固定域名：IBT_DOMAIN=proxy.example.com bash install.sh bind-auto'
    read -r -p '  代理域名（如 proxy.example.com）： ' d
  fi
  check_domain "$d"
  MODE='fixed-pending'
  write_state
  [[ -t 0 && -r /dev/tty ]] || die '请在交互式 SSH 终端操作；为保护凭据，不支持命令行传入 API Token。'
  section '自动配置域名'
  field '配置目标' '为已有 Cloudflare Tunnel 添加路由及 DNS CNAME。'
  field '所需权限' 'Tunnel 配置读写、Zone Read、DNS Read/Edit。'
  field '配置备份' '修改前自动保存；遇到同名 DNS 或路由冲突时停止。'
  printf '\n'
  local helper token tmp
  tmp="$(mktemp "${APP_DIR}/cf-helper.XXXXXX")"
  if [[ ! -s "$CF_HELPER" ]]; then
    rm -f -- "$tmp"; die '域名组件缺失，请运行 ibt update。'
  fi
  cp -- "$CF_HELPER" "$tmp"
  chmod 600 "$tmp"
  helper="$tmp"
  read -r -s -p '  Cloudflare API Token（输入隐藏，不保存）： ' token < /dev/tty
  printf '\n' > /dev/tty
  if [[ -z "$token" ]]; then rm -f -- "$helper"; die 'Token 为空。'; fi
  if printf '%s\n' "$token" | python3 "$helper" --domain "$DOMAIN" --port "$PORT" --backup-dir "$APP_DIR/cf-backups"; then
    unset token
    rm -f -- "$helper"
    info 'Cloudflare 已自动添加固定域名路由。请用客户端验证新链接。快捷节点仍保持运行。'
    show_main
  else
    unset token
    rm -f -- "$helper"
    warn '自动绑定失败。sing-box 和快捷节点不受影响，可改用 bind 查看手动设置方法。'
    return 1
  fi
}
stop_quick_main() {
  read_state
  [[ -n "$DOMAIN" ]] || die '尚未绑定固定域名；停用 Quick Tunnel 后将没有代理入口。请先使用 bind。'
  if [[ -f "$QUICK_UNIT" ]] && owned_unit "$QUICK_UNIT"; then
    systemctl --user disable --now "$QUICK_SERVICE"
    info '快捷隧道已停止并取消开机启动；固定节点配置保持不变。'
  else
    warn '没有找到本工具的 Quick Tunnel 服务。'
  fi
  MODE='fixed'
  write_state
  show_main
}
status_main() {
  local name label value linger mode_label host
  section '节点运行状态'
  for name in "$SB_SERVICE" "$CF_SERVICE" "$QUICK_SERVICE"; do
    case "$name" in
      "$SB_SERVICE") label='节点服务';;
      "$CF_SERVICE") label='固定隧道';;
      "$QUICK_SERVICE") label='快捷隧道';;
    esac
    value="$(systemctl --user is-active "$name" 2>/dev/null || true)"
    case "$value" in
      active) value='运行中';;
      activating) value='启动中';;
      failed) value='运行异常';;
      deactivating) value='停止中';;
      inactive) value='未运行';;
      *) value='暂不可读';;
    esac
    field "$label" "$value"
  done
  if command -v loginctl >/dev/null 2>&1; then
    linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
    case "$linger" in
      yes) field '后台驻留' '已启用';;
      no) field '后台驻留' '未启用';;
      *) field '后台驻留' '暂不可读';;
    esac
  fi
  if [[ -s "$STATE" ]]; then
    read_state
    case "$MODE" in
      quick) mode_label='临时节点';;
      fixed) mode_label='固定节点';;
      fixed-pending) mode_label='固定域名待验证';;
      *) mode_label='尚未确认';;
    esac
    field '本机入口' "http://127.0.0.1:$PORT"
    field '节点模式' "$mode_label"
    if systemctl --user is-active --quiet "$QUICK_SERVICE"; then
      host="$(quick_host || true)"
      field '临时域名' "${host:-尚未生成}"
    fi
  fi
  printf '\n'
  say '验证连接： ibt diagnose'
  say '整机暂停后，本机后台服务也会停止；可到机器管理中启动。'
}
uninstall_main() {
  if [[ "${CONFIRM:-}" != YES ]]; then
    [[ -t 0 ]] || die '非交互模式卸载请设置 CONFIRM=YES。'
    local answer; read -r -p '  卸载本工具创建的服务及配置？输入 YES 继续： ' answer
    [[ "$answer" == YES ]] || die '卸载已取消。'
  fi
  # Stop the scheduler before removing the stable CLI path it executes.
  local heartbeat="$SCRIPT_DIR/heartbeat.py"
  [[ -f "$heartbeat" ]] || heartbeat="$APP_DIR/cli/heartbeat.py"
  if [[ -f "$HOME/.config/insta-box/heartbeat.json" ||
        -e "$UNIT_DIR/insta-box-heartbeat.timer" ||
        -e "$UNIT_DIR/insta-box-heartbeat.service" ]]; then
    [[ -f "$heartbeat" ]] || die '保活组件缺失，请先更新工具并停用保活后再卸载。'
    need python3
    python3 "$heartbeat" clear || die '保活任务未能安全停用，保留程序目录以便重试。'
  fi
  local service unit
  for service in "$QUICK_SERVICE" "$SB_SERVICE" "$CF_SERVICE"; do
    unit="${UNIT_DIR}/${service}"
    if [[ -f "$unit" ]] && owned_unit "$unit"; then
      systemctl --user disable --now "$service" >/dev/null 2>&1 || true
      rm -f -- "$unit"
    fi
  done
  systemctl --user daemon-reload || true
  rm -rf -- "$APP_DIR"
  info '已卸载本工具。没有删除 Cloudflare 账户路由、Tunnel、Token 或其他应用。'
}
usage() {
  cat <<'EOF'
  InstaBox Tool：一个命令安装 VLESS+WebSocket + Cloudflare Quick Tunnel

  bash install.sh               首次验证 InstaBox API Key，自动创建快捷节点与本机保活
  bash install.sh show          显示当前 Quick/固定域名的节点导入链接
  bash install.sh status        查看所有服务及保活状态
  bash install.sh logs          sing-box 日志
  bash install.sh logs quick    Quick Tunnel 日志
  bash install.sh logs named    固定 Cloudflare Tunnel 日志
  bash install.sh bind          输入已有 Cloudflare 域名，获取唯一一条后台配置说明
  bash install.sh bind-auto     可选：提供受限短期 Cloudflare API Token 自动新增路由
  bash install.sh quick         启动/恢复快捷隧道
  bash install.sh diagnose      分层检查节点与快捷隧道（隐藏凭据）
  bash install.sh quick-protocol auto|http2  选择传输并重建快捷地址
  bash install.sh quick-autostart status|enable|disable  管理开机自动新建临时隧道
  bash install.sh stop-quick    固定域名可用后，关闭快捷隧道
  bash install.sh restart       重启 sing-box
  bash install.sh tunnel        自动托管现有固定 Tunnel 的 cloudflared 服务
  bash install.sh uninstall     只卸载本脚本创建的本地组件

  IBT_DOMAIN=proxy.example.com    可在安装时预先记录固定域名，但不要求立即绑定路由
  IBT_PORT=20000                  默认本地端口 20000
  IBT_NO_SUDO=1                   完全禁止尝试一次 sudo loginctl enable-linger

  快捷地址可能在隧道重建后变化；需要固定地址请绑定自己的域名。
  一键保活运行中的机器：ibt keepalive auto；手动选择目标：ibt keepalive setup。
  平台策略读回请运行 ibt keepalive check。
EOF
}
case "${1:-install}" in
  install) install_main ;;
  show) show_main ;;
  status) status_main ;;
  repair) repair_main ;;
  refresh-quick) refresh_quick_main ;;
  quick) quick_main ;;
  quick-protocol) quick_protocol_main "${2:-}" ;;
  quick-autostart) quick_autostart_main "${2:-status}" ;;
  diagnose) shift; diagnose_main "$@" ;;
  bind) bind_main "${2:-}" ;;
  bind-auto) bind_auto_main "${2:-}" ;;
  stop-quick) stop_quick_main ;;
  tunnel) preflight; read_state; ensure_linger; ensure_cloudflared; install_named_tunnel_unit; status_main ;;
  logs)
    case "${2:-singbox}" in
      quick) [[ -f "$QUICK_LOG" ]] && tail -n 100 "$QUICK_LOG" || warn '尚未生成 Quick Tunnel 日志。' ;;
      named) journalctl --user -u "$CF_SERVICE" -n 100 --no-pager ;;
      singbox) journalctl --user -u "$SB_SERVICE" -n 100 --no-pager ;;
      *) die 'logs 参数仅支持 quick、named 或 singbox。' ;;
    esac
    ;;
  restart) systemctl --user restart "$SB_SERVICE" && status_main ;;
  uninstall) uninstall_main ;;
  help|-h|--help) usage ;;
  *) usage; die "未知命令：$1" ;;
esac
