#!/usr/bin/env python3
# Author: Pre
"""Safely add one public-hostname route to an existing remotely-managed Cloudflare Tunnel.

Requires a short-lived, restricted Cloudflare API token on stdin. Never records it.
Preserves all other ingress routes and refuses DNS collisions.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.cloudflare.com/client/v4"
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.I)
ID_RE = re.compile(r"^[a-f0-9]{32}$", re.I)
HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", re.I)


class ConfigError(Exception):
    pass


def request(method: str, path: str, token: str, data=None):
    body = None if data is None else json.dumps(data, separators=(",", ":")).encode("utf-8")
    url = API_ROOT + path
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        # API errors can include identifiers or long diagnostic dumps. Do not show response bodies.
        raise ConfigError(f"Cloudflare API 请求失败：HTTP {exc.code}，接口 {path.split('?')[0]}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ConfigError(f"Cloudflare API 网络或响应错误：{type(exc).__name__}") from None
    if payload.get("success") is not True:
        codes = ",".join(str(err.get("code", "unknown")) for err in payload.get("errors", []))
        raise ConfigError(f"Cloudflare API 拒绝操作，错误码：{codes or 'unknown'}")
    return payload.get("result")


def ids_from_cloudflared_token() -> tuple[str | None, str | None]:
    home = Path.home()
    for name in ("token", "tunnel.token"):
        path = home / ".config" / "cloudflared" / name
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8").strip()
        try:
            packed = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            obj = json.loads(packed.decode("utf-8"))
            aid, tid = obj.get("a"), obj.get("t")
            if isinstance(aid, str) and isinstance(tid, str) and ID_RE.fullmatch(aid) and UUID_RE.fullmatch(tid):
                return aid.lower(), tid.lower()
        except (ValueError, UnicodeDecodeError, TypeError, KeyError):
            continue
    return None, None


def manual_id(value: str | None, label: str, pattern: re.Pattern) -> str:
    if value is None:
        try:
            # A terminal is not seekable. Separate text streams also keep the
            # piped API token on stdin independent from interactive ID input.
            with open("/dev/tty", "r", encoding="utf-8") as tty_in, \
                    open("/dev/tty", "w", encoding="utf-8") as tty_out:
                tty_out.write(f"  输入 {label}： ")
                tty_out.flush()
                value = tty_in.readline().strip()
        except OSError:
            raise ConfigError(f"无法读取 {label}；请用 --account-id/--tunnel-id 指定。") from None
    if not pattern.fullmatch(value):
        raise ConfigError(f"{label} 格式不正确")
    return value.lower()


def zone_for_hostname(hostname: str, token: str) -> tuple[str, str]:
    labels = hostname.split(".")
    for i in range(1, len(labels) - 1):
        domain = ".".join(labels[i:])
        url = "/zones?" + urllib.parse.urlencode({"name": domain, "per_page": "50"})
        result = request("GET", url, token)
        for zone in result or []:
            if zone.get("name", "").lower() == domain and ID_RE.fullmatch(zone.get("id", "")):
                return zone["id"], domain
    raise ConfigError("无法找到域名对应的 Cloudflare Zone；检查 Token 的 Zone:Read 权限及域名托管状态")


def prepare_ingress(config: dict, hostname: str, destination: str) -> tuple[dict, bool]:
    if not isinstance(config, dict) or not isinstance(config.get("ingress"), list):
        raise ConfigError("Tunnel 配置缺少 ingress 规则，已拒绝自动修改")
    current = config["ingress"]
    for rule in current:
        if not isinstance(rule, dict):
            raise ConfigError("无法识别的旧 ingress 格式")
        if str(rule.get("hostname", "")).lower() == hostname:
            if rule.get("service") == destination and not rule.get("path"):
                return config, False
            raise ConfigError(f"现有 Tunnel 已有 {hostname} 路由，目标不同；为避免覆盖，已终止")
    out = json.loads(json.dumps(config))
    ingress = out["ingress"]
    index = next((i for i, rule in enumerate(ingress) if not rule.get("hostname") and not rule.get("path")), len(ingress))
    ingress.insert(index, {"hostname": hostname, "service": destination})
    if not any(not rule.get("hostname") and not rule.get("path") for rule in ingress):
        ingress.append({"service": "http_status:404"})
    return out, True


def check_dns(zone_id: str, hostname: str, tid: str, token: str) -> bool:
    url = f"/zones/{zone_id}/dns_records?" + urllib.parse.urlencode({"name": hostname, "per_page": "100"})
    found = request("GET", url, token)
    target = f"{tid}.cfargotunnel.com"
    if not found:
        return False
    if len(found) == 1 and found[0].get("type") == "CNAME" and found[0].get("content", "").rstrip(".").lower() == target and found[0].get("proxied") is True:
        return True
    raise ConfigError(f"{hostname} 已有 DNS 记录且不完全匹配目标 Tunnel；为防止覆盖，已终止")


def add_route(domain: str, port: int, token: str, account: str, tunnel: str, backup_path: Path) -> None:
    zone_id, zone_name = zone_for_hostname(domain, token)
    endpoint = f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations"
    original = request("GET", endpoint, token)
    if not isinstance(original, dict):
        raise ConfigError("无法读取现有 Tunnel 配置")
    original_cfg = original.get("config")
    destination = f"http://127.0.0.1:{port}"
    updated_cfg, need_ingress = prepare_ingress(original_cfg, domain, destination)
    dns_exists = check_dns(zone_id, domain, tunnel, token)

    # Save the exact prior ingress configuration before any mutation. This file is local only.
    backup_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with backup_path.open("x", encoding="utf-8") as fp:
        json.dump({"account_id": account, "tunnel_id": tunnel, "config": original_cfg}, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    backup_path.chmod(0o600)

    dns_record_id = None
    if not dns_exists:
        record = request("POST", f"/zones/{zone_id}/dns_records", token,
                         {"type": "CNAME", "name": domain, "content": f"{tunnel}.cfargotunnel.com", "ttl": 1, "proxied": True})
        dns_record_id = record.get("id")
        print(f"  [OK] DNS 已创建： {domain}（区域： {zone_name}）。")
    else:
        print("  [OK] DNS 已匹配，保留原记录。")
    try:
        if need_ingress:
            request("PUT", endpoint, token, {"config": updated_cfg})
            print(f"  [OK] 路由已添加： {domain} → {destination}")
        else:
            print("  [OK] 路由已匹配，保留原配置。")
    except ConfigError:
        if dns_record_id and ID_RE.fullmatch(dns_record_id):
            try:
                request("DELETE", f"/zones/{zone_id}/dns_records/{dns_record_id}", token)
                print("  [信息] 路由更新失败，已撤销本次 DNS 记录。")
            except ConfigError:
                print("  [提示] DNS 回滚失败，请在 Cloudflare 检查。", file=sys.stderr)
        raise
    print("  [OK] 固定域名配置完成。")
    print(f"  配置备份： {backup_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="为已有 Cloudflare Tunnel 添加域名路由")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--account-id")
    parser.add_argument("--tunnel-id")
    parser.add_argument("--backup-dir", required=True)
    opts = parser.parse_args()
    domain = opts.domain.lower().strip()
    if not HOST_RE.fullmatch(domain) or not 1024 <= opts.port <= 65535:
        raise ConfigError("域名或端口格式不正确")
    token = sys.stdin.readline().strip()
    if len(token) < 20 or any(ch.isspace() for ch in token):
        raise ConfigError("未收到有效格式的 Cloudflare API Token")
    ai, ti = ids_from_cloudflared_token()
    account = manual_id(opts.account_id or ai, "Account ID（32 位十六进制）", ID_RE)
    tunnel = manual_id(opts.tunnel_id or ti, "Tunnel UUID（带连字符）", UUID_RE)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup = Path(opts.backup_dir) / f"tunnel-before-{stamp}.json"
    add_route(domain, opts.port, token, account, tunnel, backup)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ConfigError, FileExistsError) as exc:
        print(f"  [失败] {exc}", file=sys.stderr)
        sys.exit(1)
