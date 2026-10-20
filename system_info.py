#!/usr/bin/env python3
# Author: Pre
"""A local, read-only system report. No credentials or external requests."""

import argparse
import datetime as dt
import ipaddress
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import struct
import subprocess
import sys
import time
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


UNITS = {
    "node": "insta-box-node.service",
    "quick": "insta-box-quick.service",
    "fixed": "insta-box-tunnel.service",
    "keepalive": "insta-box-heartbeat.timer",
}
MAX_FILE = 1024 * 1024
MAX_COMMAND = 128 * 1024
COMMAND_TIMEOUT = 1.5
COMMAND_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
ZONE_DIRS = ("/usr/share/zoneinfo", "/usr/lib/zoneinfo", "/usr/share/lib/zoneinfo", "/etc/zoneinfo")
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState")
ACTIVE_STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}


def safe_text(value, width=80):
    """Remove terminal controls and bound visual width, including CJK text."""
    if not isinstance(value, str):
        return None
    value = " ".join("".join(" " if unicodedata.category(c).startswith("C") else c for c in value[:4096]).split())
    result, used = [], 0
    for char in value:
        size = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        if used + size > width:
            while result and display_width("".join(result)) > width - 1:
                result.pop()
            return "".join(result) + "…"
        result.append(char)
        used += size
    return "".join(result) or None


def display_width(value):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in value)


def run_bounded(argv, timeout=COMMAND_TIMEOUT, limit=MAX_COMMAND):
    """Bound both elapsed time and captured bytes without writing temp files."""
    runtime = "/run/user/" + str(os.getuid())
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
        "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "", "SYSTEMD_PAGERSECURE": "1",
        "XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus",
    }
    proc = None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, close_fds=True)
        deadline = time.monotonic() + timeout
        data = bytearray()
        os.set_blocking(proc.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, None
                if not selector.select(remaining):
                    return None, None
                part = os.read(proc.stdout.fileno(), min(8192, limit + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
                if len(data) > limit:
                    return None, None
        code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        return code, data.decode("utf-8", errors="replace")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None, None
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()


def read_os_release(text):
    values = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"PRETTY_NAME", "NAME", "VERSION"} and key not in values:
            try:
                parts = shlex.split(value, comments=True, posix=True)
            except ValueError:
                continue
            if len(parts) == 1:
                values[key] = safe_text(parts[0])
    return values.get("PRETTY_NAME") or safe_text(" ".join(values.get(key) or "" for key in ("NAME", "VERSION")))


def memory_values(text):
    values = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(r"(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)\s+kB\s*", line)
        if match and len(match[2]) <= 19:
            value = int(match[2]) * 1024
            if value <= (1 << 63):
                values[match[1]] = value
    total, available = values.get("MemTotal"), values.get("MemAvailable")
    if total == 0:
        total = None
    if available is not None and (total is None or available > total):
        available = None
    swap_total, swap_free = values.get("SwapTotal"), values.get("SwapFree")
    if swap_free is not None and (swap_total is None or swap_free > swap_total):
        swap_free = None
    return (
        {"total_bytes": total, "available_bytes": available,
         "used_bytes": total - available if total is not None and available is not None else None},
        {"total_bytes": swap_total, "free_bytes": swap_free,
         "used_bytes": swap_total - swap_free if swap_total is not None and swap_free is not None else None},
    )


def parse_interfaces(text):
    try:
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) > 256:
            return None
        result, invalid = [], False
        for row in rows:
            if not isinstance(row, dict):
                return None
            name = row.get("ifname")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", name):
                invalid = True
                continue
            entries = row.get("addr_info", [])
            if not isinstance(entries, list) or len(entries) > 256:
                return None
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("family") not in {"inet", "inet6"}:
                    invalid = True
                    continue
                address, prefix = entry.get("local"), entry.get("prefixlen")
                if not isinstance(address, str) or len(address) > 64 or type(prefix) is not int:
                    invalid = True
                    continue
                if not re.fullmatch(r"[0-9A-Fa-f:.]+", address):
                    invalid = True
                    continue
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    invalid = True
                    continue
                family = 4 if entry["family"] == "inet" else 6
                if parsed.version != family or not 0 <= prefix <= parsed.max_prefixlen:
                    invalid = True
                    continue
                if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
                    continue
                value = {"interface": name, "family": family, "address": parsed.compressed, "prefixlen": prefix}
                if value not in result:
                    result.append(value)
                if len(result) >= 64:
                    return result
        return result if result or not invalid else None
    except (TypeError, ValueError, RecursionError):
        return None


def parse_routes(text, family):
    try:
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) > 256:
            return None
        result = []
        for row in rows:
            if not isinstance(row, dict):
                return None
            if row.get("dst") != "default":
                continue
            hops = row.get("nexthops", [row])
            if not isinstance(hops, list) or len(hops) > 64:
                return None
            for hop in hops:
                if not isinstance(hop, dict):
                    return None
                name = hop.get("dev")
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", name):
                    if row.get("type") not in {"unreachable", "blackhole", "prohibit", "throw"}:
                        return None
                    continue
                item = {"family": family, "interface": name}
                if item not in result:
                    result.append(item)
        return result[:16]
    except (TypeError, ValueError, RecursionError):
        return None


def unavailable_service(unit):
    return {"unit": unit, "state": "unavailable", "active": None, "sub": None, "enabled": None}


def parse_services(text):
    result = {name: unavailable_service(unit) for name, unit in UNITS.items()}
    if not isinstance(text, str):
        return result
    by_unit = {unit: name for name, unit in UNITS.items()}
    seen = set()
    for block in re.split(r"\n\s*\n", text.strip()):
        values = {}
        duplicate = False
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep and key in PROPERTIES:
                if key in values:
                    duplicate = True
                values[key] = value
        unit = values.get("Id")
        if unit not in by_unit:
            continue
        name = by_unit[unit]
        if duplicate or unit in seen:
            result[name] = unavailable_service(unit)
            seen.add(unit)
            continue
        seen.add(unit)
        load, active = values.get("LoadState"), values.get("ActiveState")
        item = unavailable_service(unit)
        if load == "not-found":
            item["state"] = "not_installed"
        elif load == "masked":
            item["state"] = "masked"
        elif load == "loaded" and active in ACTIVE_STATES:
            item["active"] = active
            item["state"] = {"active": "running", "inactive": "inactive", "failed": "failed", "activating": "starting",
                             "deactivating": "stopping", "reloading": "running", "refreshing": "running"}.get(active, "other")
            sub = values.get("SubState", "")
            if re.fullmatch(r"[a-z-]{1,40}", sub):
                item["sub"] = sub
        enabled = values.get("UnitFileState")
        if enabled in {"enabled", "enabled-runtime"}:
            item["enabled"] = True
        elif enabled in {"disabled", "masked", "masked-runtime"}:
            item["enabled"] = False
        result[name] = item
    return result


class Host:
    def __init__(self, root=Path("/"), runner=run_bounded, disk=os.statvfs, uname=os.uname,
                 cores=os.cpu_count, now=None, finder=None):
        self.root = Path(root)
        self.runner, self.disk, self.uname, self.cores = runner, disk, uname, cores
        self.now = now or (lambda: dt.datetime.now().astimezone())
        self.finder = finder or self.find_command

    def path(self, name):
        return self.root / name.lstrip("/")

    def read_bytes(self, name, limit=MAX_FILE):
        fd = None
        try:
            fd = os.open(self.path(name), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as file:
                data = file.read(limit + 1)
            return data if len(data) <= limit else None
        except (OSError, ValueError):
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def read(self, name, limit=MAX_FILE):
        data = self.read_bytes(name, limit)
        return data.decode("utf-8", errors="replace") if data is not None else None

    @staticmethod
    def find_command(name):
        if name not in {"ip", "systemctl"}:
            return None
        for directory in COMMAND_DIRS:
            path = Path(directory) / name
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        return None

    def command(self, name, *args, accept_failure=False):
        path = self.finder(name)
        if path is None:
            return None
        try:
            code, text = self.runner([path, *args])
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        if type(code) is not int or not isinstance(text, str) or len(text.encode("utf-8")) > MAX_COMMAND:
            return None
        return text if code == 0 or accept_failure else None

    def disk_info(self, mount):
        item = {"mount": mount, "state": "unavailable", "total_bytes": None, "used_bytes": None, "available_bytes": None}
        try:
            value = self.disk(self.path(mount))
            fields = (value.f_frsize, value.f_blocks, value.f_bfree, value.f_bavail)
            if not all(type(v) is int and 0 <= v < (1 << 63) for v in fields) or value.f_frsize == 0:
                return item
            total, free, available = (v * value.f_frsize for v in fields[1:])
            if not 0 <= available <= free <= total or total == 0 or total >= (1 << 63):
                return item
            item.update(state="ok", total_bytes=total, used_bytes=total - free, available_bytes=available)
        except (OSError, ValueError, AttributeError):
            pass
        return item

    def system_timezone(self):
        # /etc/timezone is a packaging hint and can be stale. Confirm the file
        # actually used by libc before giving it a name; the process TZ does
        # not participate in this check.
        current = self.read_bytes("/etc/localtime", 65536)
        if current is None or not current.startswith(b"TZif"):
            return None
        try:
            ZoneInfo.from_file(io.BytesIO(current))
        except (ValueError, EOFError, OSError, OverflowError, struct.error):
            return None
        try:
            target = os.readlink(self.path("/etc/localtime"))
        except OSError:
            target = None
        if target is not None:
            target = os.path.normpath(os.path.join("/etc", target))
            for directory in ZONE_DIRS:
                if target.startswith(directory + "/"):
                    value = target[len(directory) + 1:]
                    if re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value) and self.read_bytes(target, 65536) == current:
                        return value
        # A copied /etc/localtime has no zone name. A hint is reliable only if
        # its existing zoneinfo bytes match the actual TZ file exactly.
        value = (self.read("/etc/timezone", 256) or "").strip()
        if re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value):
            for directory in ZONE_DIRS:
                if self.read_bytes(directory + "/" + value, 65536) == current:
                    return value
        return None

    def collect(self):
        warnings = []
        collected = self.now()
        if collected.tzinfo is None:
            collected = collected.astimezone()
        display_timezone = safe_text(collected.tzname())
        configured = os.environ.get("TZ", "")
        if re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", configured):
            try:
                if collected.astimezone(ZoneInfo(configured)).utcoffset() == collected.utcoffset():
                    display_timezone = configured
            except (ZoneInfoNotFoundError, ValueError):
                pass
        try:
            uname = self.uname()
            hostname, kernel, architecture = (safe_text(v) for v in (uname.nodename, uname.release, uname.machine))
        except (OSError, AttributeError):
            hostname = kernel = architecture = None
        system = {"hostname": hostname, "os": read_os_release(self.read("/etc/os-release", 65536)),
                  "kernel": kernel, "architecture": architecture, "uptime_seconds": None,
                  "system_timezone": self.system_timezone(), "display_timezone": display_timezone}
        if system["system_timezone"] is None:
            warnings.append("system_timezone_unconfirmed")
        try:
            uptime = float((self.read("/proc/uptime", 1024) or "").split()[0])
            if math.isfinite(uptime) and 0 <= uptime < 1e12:
                system["uptime_seconds"] = int(uptime)
        except (ValueError, IndexError):
            pass
        cpu = {"model": None, "logical_cores": None, "load": None}
        text = self.read("/proc/cpuinfo")
        for line in (text or "").splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() in {"model name", "Hardware", "Processor"} and value.strip():
                cpu["model"] = safe_text(value.strip())
                break
        try:
            cores = self.cores()
            if type(cores) is int and 0 < cores <= 1048576:
                cpu["logical_cores"] = cores
        except (OSError, ValueError):
            pass
        try:
            load = [float(v) for v in (self.read("/proc/loadavg", 1024) or "").split()[:3]]
            if len(load) == 3 and all(math.isfinite(v) and v >= 0 for v in load):
                cpu["load"] = load
        except ValueError:
            pass
        memory, swap = memory_values(self.read("/proc/meminfo", 65536))
        disks = [self.disk_info("/")]
        mounts = self.read("/proc/self/mountinfo")
        if mounts is not None and any(len(fields := line.split()) > 6 and fields[4] == "/data" and "-" in fields[6:]
                                      for line in mounts.splitlines()):
            disks.append(self.disk_info("/data"))
        elif mounts is None:
            warnings.append("mounts_unavailable")
        addresses = parse_interfaces(self.command("ip", "-j", "address", "show"))
        routes4 = parse_routes(self.command("ip", "-j", "-4", "route", "show", "default"), 4)
        routes6 = parse_routes(self.command("ip", "-j", "-6", "route", "show", "default"), 6)
        network = {"default_ipv4": routes4, "default_ipv6": routes6, "addresses": addresses,
                   "tcp_congestion_control": None, "default_qdisc": None}
        for key, file in (("tcp_congestion_control", "/proc/sys/net/ipv4/tcp_congestion_control"),
                          ("default_qdisc", "/proc/sys/net/core/default_qdisc")):
            value = (self.read(file, 1024) or "").strip()
            if re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", value):
                network[key] = value
        service_text = self.command("systemctl", "--user", "show", "--no-pager",
                                    *("--property=" + field for field in PROPERTIES), *UNITS.values(), accept_failure=True)
        services = parse_services(service_text)
        for name, value in (("system", system), ("cpu", cpu), ("memory", memory), ("swap", swap), ("network", network)):
            if any(v is None for v in value.values()):
                warnings.append(name + "_partial")
        if any(disk["state"] != "ok" for disk in disks):
            warnings.append("disks_partial")
        if any(service["state"] == "unavailable" for service in services.values()):
            warnings.append("services_partial")
        return {"schema": 1, "collected_at": collected.isoformat(timespec="seconds"), "system": system, "cpu": cpu,
                "memory": memory, "swap": swap, "disks": disks, "network": network, "services": services,
                "warnings": warnings}


def size(value):
    if value is None:
        return "未读取"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}"
        value /= 1024


def uptime_label(seconds):
    if seconds is None:
        return None
    days, remaining = divmod(seconds, 86400)
    hours, minutes = divmod(remaining // 60, 60)
    return f"{days} 天 {hours} 小时 {minutes} 分钟"


def render(report):
    lines = []

    def row(label, value):
        padding = " " * max(0, 8 - display_width(label))
        lines.append("  " + label + padding + "： " + (safe_text(str(value), 88) if value is not None else "未读取"))

    def section(title):
        if lines:
            lines.append("")
        lines.append("  " + title)

    system, cpu, memory, swap = (report[key] for key in ("system", "cpu", "memory", "swap"))
    section("基本信息")
    row("当前时间", report["collected_at"])
    row("显示时区", system["display_timezone"])
    row("系统时区", system["system_timezone"] or "未确认（未能核对 /etc/localtime）")
    for label, key in (("本机名称", "hostname"), ("系统版本", "os"), ("内核版本", "kernel"), ("系统架构", "architecture")):
        row(label, system[key])
    row("运行时长", uptime_label(system["uptime_seconds"]))
    section("资源用量")
    row("CPU 型号", cpu["model"])
    row("逻辑核心", cpu["logical_cores"])
    row("系统负载", " / ".join(f"{v:.2f}" for v in cpu["load"]) + "（1 / 5 / 15 分钟）" if cpu["load"] is not None else None)
    row("内存用量", f"{size(memory['used_bytes'])} / {size(memory['total_bytes'])}（使用 / 总量）")
    row("可用内存", size(memory["available_bytes"]))
    row("交换空间", "未启用（0 B）" if swap["total_bytes"] == 0 else
        f"{size(swap['used_bytes'])} / {size(swap['total_bytes'])}（使用 / 总量）")
    for disk in report["disks"]:
        label = "根盘" if disk["mount"] == "/" else "数据"
        row(label + "用量", f"{size(disk['used_bytes'])} / {size(disk['total_bytes'])}（{disk['mount']}）")
        row(label + "可用", size(disk["available_bytes"]))
    section("本机网络")
    net = report["network"]
    for key, family in (("default_ipv4", 4), ("default_ipv6", 6)):
        routes = net[key]
        row("默认网卡", f"IPv{family} " + ("未读取" if routes is None else ", ".join(v["interface"] for v in routes) or "未配置"))
    for family in (4, 6):
        addresses = net["addresses"]
        if addresses is None:
            row(f"IPv{family}地址", None)
            continue
        values = [a for a in addresses if a["family"] == family]
        if not values:
            row(f"IPv{family}地址", "未配置（不含回环地址）")
        for value in values[:4]:
            row(f"IPv{family}地址", value["address"] + "/" + str(value["prefixlen"]) + " · " + value["interface"])
        if len(values) > 4:
            row(f"IPv{family}地址", f"另有 {len(values) - 4} 项，ibt info --json 可查看更多地址")
    row("拥塞算法", net["tcp_congestion_control"])
    row("默认队列", net["default_qdisc"])
    lines.append("  地址来自本机网卡，未查询公网出口。")
    section("本机服务")
    labels = {"running": "运行中", "inactive": "未运行", "failed": "运行失败", "not_installed": "尚未配置",
              "unavailable": "未读取", "starting": "启动中", "stopping": "停止中", "masked": "已屏蔽", "other": "需要检查"}
    for label, name in (("节点服务", "node"), ("快捷隧道", "quick"), ("固定隧道", "fixed"), ("自动保活", "keepalive")):
        service = report["services"][name]
        text = labels[service["state"]]
        if name == "keepalive" and service["state"] == "running" and service["sub"] == "waiting":
            text = "等待执行"
        if service["state"] in {"running", "inactive", "failed", "starting", "stopping"}:
            if service["enabled"] is True:
                text += " · 已设自启"
            elif service["enabled"] is False:
                text += " · 自启关闭"
        row(label, text)
    lines.append("  服务状态表示本机进程或定时器；保活结果请查看机器保活。")
    if report["warnings"]:
        lines.append("")
        row("读取提示", "部分信息不可读取，已逐项标明。")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="只读查看本机系统、资源、网络与服务信息")
    parser.add_argument("--json", action="store_true", help="输出结构化报告")
    args = parser.parse_args(argv)
    try:
        report = Host().collect()
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) if args.json else render(report))
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
