#!/usr/bin/env python3
# Author: Pre
"""InstaBox Tool activity leases and optional SSH probes, using only the stdlib.

Private configuration is never executed. API leases are controller-scoped;
SSH success means only that this round's fixed command completed.
"""
import concurrent.futures
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings


API_BASE = "https://api.instabox.sh"
GATEWAY = "api.instabox.sh"
SERVICE = "insta-box-heartbeat.service"
TIMER = "insta-box-heartbeat.timer"
UNIT_MARKER = "# Managed-by: InstaBox Tool Heartbeat"
OWNED_UNIT_MARKERS = {UNIT_MARKER, "# Managed-by: Insta Box Heartbeat"}
SSH_MARKER = "IB_HEARTBEAT_OK"
MAX_TARGETS = 20
DEFAULT_INTERVAL = 300
ROUND_TIMEOUT_SECONDS = 650
MACHINE_STATES = {"creating", "starting", "running", "stopping", "stopped", "suspending",
                  "suspended", "resuming", "deleting", "deleted", "error", "unknown"}
MACHINE_LABELS = {"creating": "创建中", "starting": "启动中", "running": "运行中", "stopping": "停止中",
                  "stopped": "已停止", "suspending": "暂停中", "suspended": "已暂停", "resuming": "恢复中",
                  "deleting": "删除中", "deleted": "已删除", "error": "异常", "unknown": "状态未知"}
TOKEN_RE = re.compile(r"ibssh_[A-Za-z0-9_-]{1,4096}\Z")
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
SECRET_RE = re.compile(r"ib(?:ssh|k)_[A-Za-z0-9._~+/=%-]+")


class HeartbeatError(Exception):
    def __init__(self, message, code="error"):
        super().__init__(message)
        self.code = code


class Cancelled(Exception):
    pass


def tty_prompt(prompt):
    try:
        stream = open("/dev/tty", "r", encoding="utf-8")
    except OSError:
        raise HeartbeatError("此操作需要交互终端；请通过 SSH 登录后运行。", "tty") from None
    with stream:
        print(prompt, end="", flush=True)
        answer = stream.readline()
    if not answer:
        raise EOFError()
    return answer.rstrip("\n")


def secret_prompt(prompt):
    # getpass otherwise falls back to echoed stdin when no usable terminal exists.
    try:
        fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
        os.close(fd)
    except OSError:
        raise HeartbeatError("输入授权需要可关闭回显的交互终端；请通过 SSH 登录后运行。", "tty") from None
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise HeartbeatError("当前终端无法安全关闭回显，未读取授权。", "tty") from None


def clean(value, limit=200):
    text = SECRET_RE.sub("[已隐藏]", str(value))
    return "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf"))[:limit]


def iso_time(value):
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid timestamp")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return parsed.timestamp()


def format_timestamp(value):
    """Display a validated timestamp in the local timezone; never echo raw input."""
    try:
        parsed = dt.datetime.fromtimestamp(parse_time(value), dt.timezone.utc).astimezone()
        offset = parsed.strftime("%z")
        zone = "UTC" if offset == "+0000" else offset[:3] + ":" + offset[3:]
        return parsed.strftime("%Y-%m-%d %H:%M:%S ") + zone
    except (ValueError, OverflowError, TypeError, OSError):
        return "未记录"


def automatic_description(summary):
    """Pure presentation shared by local status and the cloud overview."""
    if not isinstance(summary, dict) or summary.get("configured") is not True:
        return "尚未配置" if isinstance(summary, dict) and summary.get("configured") is False else "状态未读取，尚未确认自动执行"
    timer = summary.get("timer")
    if not isinstance(timer, dict):
        return "状态未读取，尚未确认自动执行"
    active, enabled = timer.get("active"), timer.get("enabled")
    if active == "active" and enabled == "enabled":
        return "已开启，后台自动执行"
    if active == "inactive" and enabled == "disabled":
        return "已停用"
    if active == "inactive" and enabled == "enabled":
        return "已启用自启，但定时任务当前未运行"
    if active == "active" and enabled == "disabled":
        return "当前会话运行中，尚未启用自启"
    return "状态未读取，尚未确认自动执行"


def schedule_description(summary):
    """Only describe the observed systemd plan, never calculate one from interval."""
    if isinstance(summary, dict) and summary.get("configured") is False:
        return "尚未配置"
    if not isinstance(summary, dict) or summary.get("configured") is not True:
        return "未读取，尚未确认定时计划"
    schedule = summary.get("schedule") if isinstance(summary, dict) else None
    if not isinstance(schedule, dict):
        return "未读取，systemd 查询失败或当前版本不支持"
    state = schedule.get("state")
    if state == "scheduled" and format_timestamp(schedule.get("nextRunAt")) != "未记录":
        return format_timestamp(schedule["nextRunAt"]) + "（systemd 计划）"
    if state == "running":
        return "本轮执行中，完成后再读取定时计划"
    if state == "disabled":
        return "自动保活未完整开启，不承诺下次自动执行"
    if state == "unscheduled":
        return "尚未排定，systemd 未提供下一次时间"
    return "未读取，systemd 查询失败或当前版本不支持"


def interval_value(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 60 <= value <= 900:
        raise HeartbeatError("保活间隔必须为 60–900 秒的整数。", "interval")
    return value


def lease_ttl(interval):
    return min(3600, max(900, interval_value(interval) * 3))


def lease_id(controller, machine_id, prefix="ib"):
    if not isinstance(prefix, str) or prefix not in {"ib", "isb"}:
        raise HeartbeatError("保活配置的租约标识前缀无效。", "config")
    return prefix + "-" + controller + "-" + hashlib.sha256(machine_id.encode()).hexdigest()[:16]


def parse_ssh_command(command):
    """Parse a tiny allowlist; never execute user-provided shell syntax."""
    if not isinstance(command, str) or not command.strip() or len(command) > 8192:
        raise HeartbeatError("请粘贴控制台提供的 SSH 或 Mosh 连接命令。", "ssh_format")
    if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in command):
        raise HeartbeatError("连接命令不能包含换行或控制字符。", "ssh_format")
    if any(c in command for c in ";&|`$<>()"):
        raise HeartbeatError("连接命令包含不允许的 shell 语法。", "ssh_format")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        raise HeartbeatError("连接命令引号不完整，请重新粘贴。", "ssh_format") from None
    if not parts or parts[0] not in ("ssh", "mosh"):
        raise HeartbeatError("只接受控制台提供的 ssh 或 mosh 命令。", "ssh_format")

    def ssh_options(words):
        port, family, seen_port = 22, None, False
        i = 0
        while i < len(words):
            word = words[i]
            if word in ("-4", "-6"):
                if family is not None:
                    raise HeartbeatError("IP 协议选项重复或冲突。", "ssh_format")
                family = "inet" if word == "-4" else "inet6"
            elif word == "-p" or re.fullmatch(r"-p[0-9]+", word):
                if seen_port:
                    raise HeartbeatError("SSH 端口重复。", "ssh_format")
                if word == "-p":
                    i += 1
                    if i >= len(words):
                        raise HeartbeatError("SSH 端口缺失。", "ssh_format")
                    raw = words[i]
                else:
                    raw = word[2:]
                if not re.fullmatch(r"[0-9]{1,5}", raw) or not 1 <= int(raw) <= 65535:
                    raise HeartbeatError("SSH 端口必须在 1–65535 之间。", "ssh_format")
                port, seen_port = int(raw), True
            else:
                raise HeartbeatError("连接命令包含不支持的选项或远程命令。", "ssh_format")
            i += 1
        return port, family

    if parts[0] == "ssh":
        if len(parts) < 2:
            raise HeartbeatError("SSH 目标缺失。", "ssh_format")
        destination = parts[-1]
        port, family = ssh_options(parts[1:-1])
    else:
        destination, ssh_words, family = None, None, None
        i = 1
        while i < len(parts):
            word = parts[i]
            if word.startswith("--ssh=") or word == "--ssh":
                if ssh_words is not None:
                    raise HeartbeatError("Mosh SSH 选项重复。", "ssh_format")
                if word == "--ssh":
                    i += 1
                    if i >= len(parts):
                        raise HeartbeatError("Mosh SSH 选项缺失。", "ssh_format")
                    nested = parts[i]
                else:
                    nested = word[len("--ssh="):]
                try:
                    ssh_words = shlex.split(nested, posix=True)
                except ValueError:
                    raise HeartbeatError("Mosh 内部 SSH 引号不完整。", "ssh_format") from None
                if not ssh_words or ssh_words[0] != "ssh":
                    raise HeartbeatError("Mosh 只允许标准 ssh 传输。", "ssh_format")
            elif word in ("-4", "-6"):
                if family is not None:
                    raise HeartbeatError("IP 协议选项重复或冲突。", "ssh_format")
                family = "inet" if word == "-4" else "inet6"
            elif word == "--no-init" or word in ("--predict=never", "--predict=always", "--predict=adaptive"):
                pass
            elif word.startswith("-") or destination is not None or i != len(parts) - 1:
                raise HeartbeatError("Mosh 命令包含不支持的选项或远程命令。", "ssh_format")
            else:
                destination = word
            i += 1
        if not destination:
            raise HeartbeatError("Mosh 目标缺失。", "ssh_format")
        port, nested_family = ssh_options((ssh_words or ["ssh"])[1:])
        if family and nested_family and family != nested_family:
            raise HeartbeatError("IP 协议选项冲突。", "ssh_format")
        family = family or nested_family
    if destination.count("@") != 1:
        raise HeartbeatError("目标必须是 ibssh_ 授权与官方网关。", "ssh_format")
    user, host = destination.split("@")
    if not TOKEN_RE.fullmatch(user) or host.lower() != GATEWAY:
        raise HeartbeatError("仅支持 ibssh_ 授权及 api.instabox.sh 官方网关。", "ssh_format")
    return {"user": user, "host": GATEWAY, "port": port, "family": family}


def token_expiry(hours, now):
    if hours is None or str(hours).strip() == "":
        return {"kind": "unknown"}
    try:
        number = float(hours)
    except (TypeError, ValueError):
        raise HeartbeatError("剩余小时应为正数；不知道可直接留空。", "token_expiry") from None
    if not math.isfinite(number) or not 0 < number <= 87600:
        raise HeartbeatError("剩余小时应为有效正数；不知道可直接留空。", "token_expiry")
    return {"kind": "estimated", "expiresAt": iso_time(now + number * 3600)}


def check_owned(path, directory=False, private=True):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
        raise HeartbeatError("配置路径是符号链接或不属于当前用户，已停止。", "unsafe_path")
    proper_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not proper_type:
        raise HeartbeatError("配置路径类型异常，已停止。", "unsafe_path")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise HeartbeatError("私有配置权限过宽；目录应为 700、文件应为 600。", "permissions")
    return True


def ensure_directory(path, private=True):
    path = Path(path)
    if not check_owned(path, directory=True, private=False):
        path.mkdir(mode=0o700)
    if private:
        os.chmod(path, 0o700)
    check_owned(path, directory=True, private=private)


def read_private(path, default=None):
    if not check_owned(path):
        return default
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise HeartbeatError("私有文件归属或权限异常，已停止。", "unsafe_path")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = None
            text = stream.read(1024 * 1024 + 1)
        if len(text) > 1024 * 1024:
            raise HeartbeatError("配置文件过大，已停止。", "config")
        return text
    finally:
        if fd is not None:
            os.close(fd)


def atomic_text(path, text):
    path = Path(path)
    check_owned(path.parent, directory=True)
    check_owned(path, private=False)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.lexists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_error(status):
    messages = {
        401: ("API Key 已失效；请用 ibt key set 更新授权。", "unauthorized"),
        403: ("当前授权、账号或套餐策略不允许此操作；API 保活需要 machines:write 或 machines:exec，SSH 换新需要 machines:write 或 machines:ssh。", "forbidden"),
        404: ("目标机器不存在或当前授权无法访问。", "not_found"),
        409: ("当前状态暂不接受保活；可能有平台操作正在进行，请在云端查看状态，下一轮会继续检查。", "conflict"),
        429: ("平台请求额度受限，将在下一轮再试。", "rate_limited"),
    }
    message, code = messages.get(status, ("平台请求失败（HTTP " + str(status) + "）。", "http_error"))
    if 300 <= status < 400:
        message, code = "平台返回重定向，已拒绝转发 API Key。", "redirect"
    return HeartbeatError(message, code)


class APIClient:
    """No redirects, no mutation retries, and no response-body error logging."""
    def __init__(self, opener_factory=None):
        self.opener_factory = opener_factory or (lambda: urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()))

    def request(self, method, route, key, body=None):
        if not route.startswith("/v1/") or "\r" in route or "\n" in route:
            raise HeartbeatError("API 路径无效。", "api_path")
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(API_BASE + route, data=payload, method=method,
                                         headers={"X-API-Key": key, "Accept": "application/json"})
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self.opener_factory().open(request, timeout=20) as response:
                status_code = response.status
                if method == "DELETE" and status_code in (204, 404):
                    return None
                expected_status = 201 if method == "POST" else 200
                if method == "DELETE":
                    raise HeartbeatError("平台尚未确认本次保活清理。", "invalid_response")
                if status_code != expected_status:
                    raise http_error(status_code)
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if method == "DELETE" and error.code == 404:
                return None
            raise http_error(error.code) from None
        except (TimeoutError, socket.timeout):
            raise HeartbeatError("平台请求超时，将在下一轮再试。", "timeout") from None
        except urllib.error.URLError:
            raise HeartbeatError("无法连接平台；请检查网络、DNS 与系统时间。", "network") from None
        except OSError:
            raise HeartbeatError("平台连接失败，将在下一轮再试。", "network") from None
        if len(raw) > 1024 * 1024:
            raise HeartbeatError("平台响应过大，未确认成功。", "invalid_response")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise HeartbeatError("平台响应格式异常，未确认成功。", "invalid_response") from None
        if not isinstance(value, dict):
            raise HeartbeatError("平台响应格式异常，未确认成功。", "invalid_response")
        return value


class Manager:
    def __init__(self, home=None, client=None, runner=None, clock=None, output=None,
                 prompt=None, secret=None, env=None, rotation_hook=None):
        self.home = Path(home) if home is not None else Path.home()
        self.cfg = self.home / ".config" / "insta-box"
        self.config_file = self.cfg / "heartbeat.json"
        self.state_file = self.cfg / "heartbeat-state.json"
        self.key_file = self.cfg / "api-key"
        self.known_hosts = self.cfg / "heartbeat_known_hosts"
        self.unit_dir = self.home / ".config" / "systemd" / "user"
        self.client = client or APIClient()
        self.runner = runner or subprocess.run
        self.clock = clock or time.time
        if output is None:
            from cloud import console_line
            output = console_line
        self.output = output
        self.prompt = prompt or tty_prompt
        self.secret = secret or secret_prompt
        self.env = dict(os.environ if env is None else env)
        self.rotation_hook = rotation_hook
        self._config_mutex = threading.RLock()
        self._file_lock_held = False

    def say(self, text):
        self.output(clean(text, 4000))

    def ensure_cfg(self, create=False):
        if not check_owned(self.home, directory=True, private=False):
            raise HeartbeatError("用户目录不存在。", "unsafe_path")
        parent = self.home / ".config"
        if create:
            ensure_directory(parent, private=False)
            ensure_directory(self.cfg)
            return True
        if not check_owned(parent, directory=True, private=False):
            return False
        return check_owned(self.cfg, directory=True)

    def new_config(self):
        return {"schema": 1, "controllerId": uuid.uuid4().hex,
                "leasePrefix": "ib", "intervalSeconds": DEFAULT_INTERVAL, "targets": []}

    def read_json(self, filename, default):
        if not self.ensure_cfg():
            return default
        raw = read_private(filename)
        if raw is None:
            return default
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise HeartbeatError("本地保活配置或状态损坏，未使用旧成功记录。", "config") from None
        if not isinstance(result, dict):
            raise HeartbeatError("本地保活配置格式异常。", "config")
        return result

    def load_config(self, required=False):
        config = self.read_json(self.config_file, None)
        if config is None:
            if required:
                raise HeartbeatError("尚未配置持续保活；请运行 ibt keepalive setup。", "not_configured")
            return self.new_config()
        self.validate_config(config)
        return config

    def validate_config(self, config):
        if config.get("schema") != 1 or not re.fullmatch(r"[a-f0-9]{32}", str(config.get("controllerId", ""))):
            raise HeartbeatError("保活配置版本或控制器标识无效。", "config")
        # Missing means a pre-3.0 controller: keep its remote lease identity.
        prefix = config.get("leasePrefix", "isb")
        if not isinstance(prefix, str) or prefix not in {"ib", "isb"}:
            raise HeartbeatError("保活配置的租约标识前缀无效。", "config")
        interval_value(config.get("intervalSeconds"))
        targets = config.get("targets")
        if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
            raise HeartbeatError("保活目标列表无效；最多支持 20 个目标。", "config")
        seen, machines = set(), set()
        for target in targets:
            if not isinstance(target, dict) or not ID_RE.fullmatch(str(target.get("id", ""))):
                raise HeartbeatError("保活目标标识无效。", "config")
            if target["id"] in seen:
                raise HeartbeatError("保活目标标识重复。", "config")
            seen.add(target["id"])
            if not isinstance(target.get("label"), str) or not target["label"] or len(target["label"]) > 80:
                raise HeartbeatError("保活目标名称无效。", "config")
            if not re.fullmatch(r"[a-f0-9]{32}", str(target.get("revision", ""))):
                raise HeartbeatError("保活目标版本无效。", "config")
            if target.get("kind") == "api":
                machine = target.get("machineId")
                if not isinstance(machine, str) or not ID_RE.fullmatch(machine) or machine in machines:
                    raise HeartbeatError("平台目标标识无效或重复。", "config")
                machines.add(machine)
                if "waitingStart" in target and not isinstance(target["waitingStart"], bool):
                    raise HeartbeatError("平台目标待启动记录无效。", "config")
                if "observedState" in target and (not isinstance(target["observedState"], str) or target["observedState"] not in MACHINE_STATES):
                    raise HeartbeatError("平台目标运行状态记录无效。", "config")
            elif target.get("kind") == "ssh":
                ssh = target.get("ssh")
                if not isinstance(ssh, dict) or not TOKEN_RE.fullmatch(str(ssh.get("user", ""))):
                    raise HeartbeatError("SSH 授权格式无效。", "config")
                if ssh.get("host") != GATEWAY or isinstance(ssh.get("port"), bool) or not isinstance(ssh.get("port"), int) or not 1 <= ssh["port"] <= 65535:
                    raise HeartbeatError("SSH 网关或端口无效。", "config")
                if ssh.get("family") not in (None, "inet", "inet6"):
                    raise HeartbeatError("SSH 协议选项无效。", "config")
                expiry = target.get("tokenExpiry", {"kind": "unknown"})
                if not isinstance(expiry, dict) or expiry.get("kind") not in ("unknown", "estimated", "verified"):
                    raise HeartbeatError("SSH 到期记录无效。", "config")
                if expiry["kind"] in ("estimated", "verified"):
                    try:
                        parse_time(expiry.get("expiresAt"))
                    except (ValueError, OverflowError, TypeError):
                        raise HeartbeatError("SSH 预计到期时间无效。", "config") from None
            else:
                raise HeartbeatError("保活目标类型无效。", "config")

    @contextlib.contextmanager
    def lock(self):
        self.ensure_cfg(create=True)
        lock_file = self.cfg / "heartbeat.lock"
        check_owned(lock_file)
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        acquired = False
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise HeartbeatError("保活锁归属或权限异常。", "unsafe_path")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                self._file_lock_held = True
            except BlockingIOError:
                pass
            yield acquired
        finally:
            if acquired:
                self._file_lock_held = False
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def read_key(self):
        environment_key = self.env.get("INSTABOX_API_KEY", "").strip()
        if environment_key:
            if not re.fullmatch(r"ibk_[A-Za-z0-9_-]{1,4096}", environment_key):
                raise HeartbeatError("环境中的 API Key 格式无效，请更新授权。", "key_invalid")
            return environment_key
        if not self.ensure_cfg():
            raise HeartbeatError("缺少本机 API Key，请运行 ibt keepalive setup-api。", "key_missing")
        key = read_private(self.key_file)
        if key is None:
            raise HeartbeatError("缺少本机 API Key，请运行 ibt keepalive setup-api。", "key_missing")
        key = key.strip()
        if not re.fullmatch(r"ibk_[A-Za-z0-9_-]{1,4096}", key):
            raise HeartbeatError("本机 API Key 格式无效，请更新授权。", "key_invalid")
        return key

    def persistent_key_matches(self, key):
        """A shell environment is not inherited by the systemd user service."""
        if not self.ensure_cfg():
            return False
        stored = read_private(self.key_file)
        return stored is not None and stored.strip() == key

    def authorize(self):
        try:
            key = self.read_key()
        except HeartbeatError as error:
            if error.code != "key_missing":
                raise
            key = self.secret("输入 InstaBox API Key（不回显）：").strip()
            if not key:
                raise Cancelled()
            if not re.fullmatch(r"ibk_[A-Za-z0-9_-]{1,4096}", key):
                raise HeartbeatError("API Key 格式无效，应以 ibk_ 开头。", "key_invalid")
            me = self.client.request("GET", "/v1/me", key)
            if not isinstance(me, dict):
                raise HeartbeatError("授权响应格式异常。", "invalid_response")
            self.ensure_cfg(create=True)
            atomic_text(self.key_file, key + "\n")
            self.say("授权已验证并保存在本机；云端管理、API 保活和 SSH 凭据换新共用，无需重复输入。")
        else:
            me = self.client.request("GET", "/v1/me", key)
            if not isinstance(me, dict):
                raise HeartbeatError("授权响应格式异常。", "invalid_response")
        self.say("平台空闲暂停规则保持原样，脚本定时保活。")
        return key

    def list_machines(self, key):
        machines, seen_ids, seen_cursors, cursor = [], set(), set(), None
        for _ in range(100):
            route = "/v1/machines" + ("?" + urllib.parse.urlencode({"cursor": cursor}) if cursor else "")
            response = self.client.request("GET", route, key)
            if not isinstance(response, dict) or not isinstance(response.get("machines"), list):
                raise HeartbeatError("机器列表格式异常。", "invalid_response")
            for machine in response["machines"]:
                if not isinstance(machine, dict) or not ID_RE.fullmatch(str(machine.get("id", ""))):
                    raise HeartbeatError("机器标识格式异常。", "invalid_response")
                if machine["id"] not in seen_ids:
                    seen_ids.add(machine["id"])
                    machines.append({"id": machine["id"], "name": clean(machine.get("name") or machine["id"], 80),
                                     "state": clean(machine.get("state", "未知"), 40)})
            cursor = response.get("nextCursor")
            if cursor in (None, ""):
                return machines
            if not isinstance(cursor, str) or len(cursor) > 2048 or cursor in seen_cursors or len(machines) > 10000:
                raise HeartbeatError("机器列表分页异常。", "invalid_response")
            seen_cursors.add(cursor)
        raise HeartbeatError("机器列表分页超出限制。", "invalid_response")

    def call(self, args, timeout=30):
        try:
            return self.runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            raise HeartbeatError("本地操作超时。", "local_timeout") from None
        except (FileNotFoundError, OSError):
            raise HeartbeatError("所需本地命令不可用。", "local_command") from None

    def check_api(self, target, config, key):
        expected = lease_id(config["controllerId"], target["machineId"], config.get("leasePrefix", "isb"))
        route = "/v1/machines/" + urllib.parse.quote(target["machineId"], safe="") + "/activity-leases/" + expected
        response = self.client.request("PUT", route, key, {"ttlSeconds": lease_ttl(config["intervalSeconds"])})
        if not isinstance(response, dict) or response.get("id") != expected or response.get("machineId") != target["machineId"]:
            raise HeartbeatError("平台响应与目标不一致，未确认保活成功。", "invalid_response")
        try:
            expiry = parse_time(response.get("expiresAt"))
        except (ValueError, OverflowError, TypeError):
            raise HeartbeatError("平台返回的有效期无效，未确认保活成功。", "invalid_response") from None
        if expiry <= self.clock():
            raise HeartbeatError("平台返回的保活有效期已过，未确认成功；请检查系统时间。", "invalid_response")
        return {"expiresAt": iso_time(expiry)}

    def check_waiting_machine(self, target, config, key):
        """Only preconfigured non-running targets need a state read before PUT.

        This allows a later start from the web console to take effect without
        automatically starting or waking a machine merely because it was selected.
        """
        machine = self.client.request("GET", "/v1/machines/" + urllib.parse.quote(target["machineId"], safe=""), key)
        if not isinstance(machine, dict) or machine.get("id") != target["machineId"] or not isinstance(machine.get("state"), str) or machine["state"] not in MACHINE_STATES:
            raise HeartbeatError("运行状态响应与目标不一致，尚未执行保活。", "invalid_response")
        if machine["state"] != "running":
            return machine["state"]
        updated = {**target, "waitingStart": False, "observedState": "running", "revision": uuid.uuid4().hex}
        self.persist_target(config, updated)
        target.clear()
        target.update(updated)
        return "running"

    def check_ssh(self, target):
        self.validate_config({"schema": 1, "controllerId": "0" * 32,
                              "intervalSeconds": DEFAULT_INTERVAL, "targets": [target]})
        self.ensure_cfg(create=True)
        if not check_owned(self.known_hosts):
            try:
                fd = os.open(self.known_hosts, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            check_owned(self.known_hosts)
        ssh = target["ssh"]
        hosts_path = str(self.known_hosts).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
        config = ["Host ib-heartbeat", "  HostName " + GATEWAY, "  Port " + str(ssh["port"]),
                  "  User " + ssh["user"], "  BatchMode yes", "  ConnectTimeout 15", "  ConnectionAttempts 1",
                  "  StrictHostKeyChecking accept-new", '  UserKnownHostsFile "' + hosts_path + '"',
                  "  GlobalKnownHostsFile /dev/null", "  HashKnownHosts yes", "  UpdateHostKeys no",
                  "  IdentityAgent none", "  IdentityFile none", "  IdentitiesOnly yes", "  PubkeyAuthentication no",
                  "  PasswordAuthentication no", "  KbdInteractiveAuthentication no", "  GSSAPIAuthentication no",
                  "  HostbasedAuthentication no", "  ForwardAgent no", "  ForwardX11 no", "  ClearAllForwardings yes",
                  "  PermitLocalCommand no", "  ProxyCommand none", "  ProxyJump none", "  RequestTTY no",
                  "  ControlMaster no", "  ControlPath none", "  ControlPersist no", "  LogLevel ERROR"]
        if ssh.get("family"):
            config.append("  AddressFamily " + ssh["family"])
        fd, filename = tempfile.mkstemp(prefix=".heartbeat-ssh-", dir=str(self.cfg))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = None
                stream.write("\n".join(config) + "\n")
            try:
                result = self.call(["ssh", "-F", filename, "-T", "--", "ib-heartbeat",
                                    "printf '%s\\n' '" + SSH_MARKER + "'"], timeout=45)
            except HeartbeatError as error:
                if error.code == "local_timeout":
                    raise HeartbeatError("SSH 本轮超时；请检查网络及控制台连接命令。", "ssh_timeout") from None
                raise
            if result.returncode != 0:
                stderr = (result.stderr or "").lower()
                if "host key verification failed" in stderr or "remote host identification has changed" in stderr:
                    raise HeartbeatError("SSH 网关主机密钥校验失败；请核实平台主机密钥后处理。", "ssh_host_key")
                raise HeartbeatError("SSH 本轮未连通；请核对网络、授权和端口，必要时重贴控制台命令；不会扫描端口。", "ssh_failed")
            if SSH_MARKER not in (result.stdout or "").splitlines():
                raise HeartbeatError("SSH 未返回预期执行标记，未确认本轮连通。", "ssh_marker")
            return {}
        finally:
            if fd is not None:
                os.close(fd)
            if os.path.lexists(filename):
                os.unlink(filename)

    def persist_target(self, config, target):
        """Rotation adapter; caller must already hold the process-wide lock."""
        if not self._file_lock_held:
            raise HeartbeatError("目标修改未持有保活锁，已停止。", "busy")
        with self._config_mutex:
            replacement = json.loads(json.dumps(target))
            if not any(row["id"] == replacement.get("id") for row in config["targets"]):
                raise HeartbeatError("待更新目标已经移除。", "config_changed")
            candidate = {**config, "targets": [replacement if row["id"] == replacement["id"] else row for row in config["targets"]]}
            self.validate_config(candidate)
            atomic_json(self.config_file, candidate)
            config.update(candidate)

    def rotate_target(self, target, config):
        rotation = target.get("rotation", {})
        if not isinstance(rotation, dict) or not (rotation.get("enabled") or rotation.get("armed")):
            return {"status": "disabled", "changed": False, "message": ""}
        hook = self.rotation_hook
        if hook is None:
            try:
                from ssh_tokens import maybe_rotate
                hook = maybe_rotate
            except ImportError:
                return {"status": "blocked", "changed": False, "message": "SSH 自动更新组件缺失，请更新管理工具。"}

        def api(method, route, body=None):
            return self.client.request(method, route, self.read_key(), body)

        try:
            return hook(config, target, api, self.check_ssh,
                        lambda updated: self.persist_target(config, updated), now=self.clock())
        except Exception:
            return {"status": "blocked", "changed": False, "message": "SSH 自动更新本轮未完成，请检查授权更新状态。"}

    def check_target(self, target, config, key, key_error=None):
        record = {"id": target["id"], "revision": target["revision"], "kind": target["kind"],
                  "label": clean(target["label"], 80), "checkedAt": iso_time(self.clock())}
        try:
            if target["kind"] == "api":
                if key_error:
                    raise key_error
                if target.get("waitingStart"):
                    observed = self.check_waiting_machine(target, config, key)
                    record["revision"] = target["revision"]
                    record["observedState"] = observed
                    if observed != "running":
                        record.update(result="waiting", errorCode="waiting_start", error="当前未运行，保活待启动；脚本不会自动开机。")
                        return record
                detail = self.check_api(target, config, key)
            else:
                rotation = self.rotate_target(target, config)
                record["revision"] = target["revision"]
                record["rotationStatus"] = clean(rotation.get("status", "blocked"), 40)
                if rotation.get("message"):
                    record["rotationMessage"] = clean(rotation["message"])
                detail = {} if rotation.get("status") == "rotated" else self.check_ssh(target)
                expiry = target.get("tokenExpiry", {"kind": "unknown"})
                record["tokenExpiry"] = {"kind": expiry["kind"]}
                if expiry.get("expiresAt"):
                    record["tokenExpiry"]["expiresAt"] = expiry["expiresAt"]
            record.update(detail)
            record.update(result="success", lastSuccessAt=iso_time(self.clock()))
        except HeartbeatError as error:
            result = "waiting" if target["kind"] == "api" and error.code == "conflict" else "error"
            prefix = "运行状态检查失败：" if target["kind"] == "api" and target.get("waitingStart") and result == "error" else ""
            record.update(result=result, errorCode=clean(error.code, 40), error=prefix + clean(str(error)))
        except Exception:
            record.update(result="error", errorCode="unexpected", error="本轮操作异常，未确认成功。")
        return record

    def cleanup_ssh_files(self):
        # A killed process cannot run its finally block. Only our private temporary
        # configs are eligible, and the caller holds the same lock used by run.
        for filename in self.cfg.iterdir():
            if filename.name.startswith(".heartbeat-ssh-"):
                if check_owned(filename):
                    filename.unlink()

    def run_once(self):
        self.load_config(required=True)
        with self.lock() as acquired:
            if not acquired:
                self.say("已有保活轮次正在运行，未重复执行。")
                return 2
            config = self.load_config(required=True)
            return self._run_locked(config)

    def _run_locked(self, config, target_ids=None):
        """Validate selected targets without restarting unrelated SSH rotation."""
        if not self._file_lock_held:
            raise HeartbeatError("本轮操作未持有保活锁，已停止。", "busy")
        if not config["targets"]:
            raise HeartbeatError("没有保活目标，请先添加目标。", "not_configured")
        selected = [target for target in config["targets"] if target_ids is None or target["id"] in target_ids]
        if not selected:
            return 0
        self.cleanup_ssh_files()
        try:
            previous = self.read_json(self.state_file, {})
        except HeartbeatError as error:
            if error.code != "config":
                raise
            previous = {}
            self.say("旧状态记录损坏，将以本轮实际结果重建。")
        old = {entry["id"]: entry for entry in previous.get("targets", []) if isinstance(entry, dict) and isinstance(entry.get("id"), str)} if isinstance(previous.get("targets", []), list) else {}
        if previous.get("schema") != 1 or previous.get("controllerId") != config["controllerId"]:
            old = {}
        key, key_error, persistent_key = None, None, False
        if any(target["kind"] == "api" for target in selected):
            try:
                key = self.read_key()
                persistent_key = self.persistent_key_matches(key)
            except HeartbeatError as error:
                key_error = error
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            ordered = sorted(selected, key=lambda target: target["kind"] != "api")
            selected_ids = [target["id"] for target in selected]
            futures = {target["id"]: pool.submit(self.check_target, target, config, key, key_error) for target in ordered}
            records = [futures[target_id].result() for target_id in selected_ids]
        for record in records:
            prior = old.get(record["id"], {})
            if record["kind"] == "api":
                record["credentialPersistent"] = persistent_key
            if record["result"] != "success" and prior.get("revision") == record["revision"] and prior.get("lastSuccessAt"):
                try:
                    record["lastSuccessAt"] = iso_time(parse_time(prior["lastSuccessAt"]))
                except (ValueError, OverflowError, TypeError):
                    pass
        shown = []
        for record in records:
            code = "healthy" if record["result"] == "success" else "waiting_start" if record.get("errorCode") == "waiting_start" else "unverified" if record.get("errorCode") == "conflict" else "failed"
            message = record.get("error", "")
            if record.get("rotationStatus") in ("pending", "ambiguous", "blocked"):
                code, message = "token_pending", record.get("rotationMessage", "SSH 自动更新尚未完成。")
            shown.append({"kind": record["kind"], "label": record["label"], "status": code, "message": message,
                          "lastSuccessAt": record.get("lastSuccessAt"),
                          "leaseExpiresAt": record.get("expiresAt") if record["result"] == "success" and record["kind"] == "api" else None})
        self.display_targets(shown, details=False)
        for index, row in enumerate(shown, 1):
            if row["status"] != "healthy" and row.get("message"):
                self.say("")
                self.say(str(index) + ". " + clean(row["label"], 80))
                self.say("  状态详情： " + clean(row["message"], 400))
        by_id = {**old, **{record["id"]: record for record in records}}
        merged = [by_id[target["id"]] for target in config["targets"] if target["id"] in by_id]
        atomic_json(self.state_file, {"schema": 1, "controllerId": config["controllerId"],
                                     "checkedAt": iso_time(self.clock()), "targets": merged})
        return 0 if all(record["result"] == "success" and record.get("rotationStatus") not in ("pending", "ambiguous", "blocked") for record in records) else 2

    def release(self, target, config, key):
        route = "/v1/machines/" + urllib.parse.quote(target["machineId"], safe="") + "/activity-leases/" + lease_id(config["controllerId"], target["machineId"], config.get("leasePrefix", "isb"))
        self.client.request("DELETE", route, key)

    def release_targets(self, targets, config):
        targets = [target for target in targets if target["kind"] == "api"]
        if not targets:
            return 0
        try:
            key = self.read_key()
        except HeartbeatError as error:
            self.say("远端保活清理未完成：" + str(error) + " 本轮保活会在有限有效期内自动结束（最长 3600 秒）。")
            return 2
        def release_one(target):
            try:
                self.release(target, config, key)
            except HeartbeatError as error:
                return clean(target["label"], 80) + "：远端保活清理失败；" + str(error)
            except Exception:
                return clean(target["label"], 80) + "：远端保活清理失败。"
            return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            errors = list(pool.map(release_one, targets))
        failed = any(errors)
        for error in errors:
            if error:
                self.say(error)
        if failed:
            self.say("已移除或停用的目标不会因此重开；远端本轮保活会在有限有效期内自动结束（最长 3600 秒）。")
        return 2 if failed else 0

    def timer_state(self):
        try:
            active = self.call(["systemctl", "--user", "is-active", TIMER], timeout=10)
            enabled = self.call(["systemctl", "--user", "is-enabled", TIMER], timeout=10)
        except HeartbeatError:
            return "unknown", "unknown"
        active_word, enabled_word = (active.stdout or "").strip(), (enabled.stdout or "").strip()
        active_state = "active" if active.returncode == 0 and active_word == "active" else "inactive" if active.returncode != 0 and active_word in ("inactive", "failed", "unknown") else "unknown"
        enabled_state = "enabled" if enabled.returncode == 0 and enabled_word == "enabled" else "disabled" if enabled_word in ("disabled", "masked", "not-found") else "unknown"
        return active_state, enabled_state

    def operation_running(self):
        """Observe an existing lock, including a manual run, without creating it."""
        filename = self.cfg / "heartbeat.lock"
        try:
            if not check_owned(filename):
                return False
            fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            try:
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
                    return None
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    return True
                fcntl.flock(fd, fcntl.LOCK_UN)
                return False
            finally:
                os.close(fd)
        except (HeartbeatError, OSError):
            return None

    def timer_schedule(self, active, enabled, last_completed=None):
        """Read systemd's actual timer deadline, already converted to wall time.

        list-timers JSON uses microseconds for next/last (not seconds). systemd
        performs the CLOCK_MONOTONIC conversion and includes RandomizedDelaySec.
        Older versions that print a text table, bad data, and failed commands are
        unknown; we deliberately do not parse localized human-readable output.
        """
        schedule = {"state": "unknown", "nextRunAt": None, "lastRunAt": None,
                    "lastCompletedAt": last_completed, "source": None}
        if active == "inactive" or enabled == "disabled":
            schedule["state"] = "disabled"
            return schedule
        if active != "active" or enabled != "enabled":
            return schedule
        locked = self.operation_running()
        service_running = None
        try:
            result = self.call(["systemctl", "--user", "show", SERVICE,
                                "--property=Id,LoadState,ActiveState,SubState", "--no-pager"], timeout=3)
            if result.returncode == 0 and len(result.stdout or "") <= 4096:
                lines = (result.stdout or "").splitlines()
                properties = dict(line.split("=", 1) for line in lines if "=" in line)
                if len(properties) == len(lines) and properties.get("Id") == SERVICE and properties.get("LoadState") == "loaded":
                    word = properties.get("ActiveState")
                    if word in ("active", "activating", "reloading", "deactivating", "refreshing"):
                        service_running = True
                    elif word in ("inactive", "failed"):
                        service_running = False
        except (HeartbeatError, ValueError):
            pass
        running = locked is True or service_running is True
        if running:
            schedule["state"] = "running"
        try:
            result = self.call(["systemctl", "--user", "list-timers", "--all", "--output=json",
                                "--no-pager", "--no-legend", TIMER], timeout=3)
            if result.returncode != 0 or len(result.stdout or "") > 65536:
                return schedule
            rows = json.loads(result.stdout or "")
            if not isinstance(rows, list) or len(rows) > 1:
                return schedule
            if not rows:
                if service_running is False and locked is False:
                    schedule.update(state="unscheduled", source="systemd")
                return schedule
            row = rows[0]
            if not isinstance(row, dict) or row.get("unit") != TIMER or row.get("activates") not in (SERVICE, [SERVICE]):
                return schedule
            if "next" not in row or "last" not in row:
                return schedule

            def timer_timestamp(value):
                # Both 0 (not triggered yet) and infinity mean unset in systemd.
                if value is None or type(value) is int and value in (0, 2**64 - 1):
                    return None
                if type(value) is not int or not 0 < value < 2**63:
                    raise ValueError("invalid timer timestamp")
                return iso_time(value / 1000000)

            next_at, last_at = timer_timestamp(row["next"]), timer_timestamp(row["last"])
            schedule["source"] = "systemd"
            if last_at is not None and parse_time(last_at) <= self.clock():
                schedule["lastRunAt"] = last_at
            if running:
                return schedule
            if service_running is None or locked is None:
                return schedule
            if next_at is not None and parse_time(next_at) > self.clock():
                schedule.update(state="scheduled", nextRunAt=next_at)
            else:
                schedule["state"] = "unscheduled"
        except (HeartbeatError, ValueError, OverflowError, TypeError, OSError):
            pass
        return schedule

    def summary(self):
        """Read-only, credential-free local health for the cloud overview."""
        return self._summary(self.load_config())

    def _summary(self, config):
        def timestamp(value):
            try:
                return iso_time(parse_time(value))
            except (ValueError, OverflowError, TypeError, OSError):
                return None

        if not config["targets"]:
            return {"configured": False, "timer": {"active": "inactive", "enabled": "disabled"},
                    "checkedAt": None, "intervalSeconds": config["intervalSeconds"], "targets": [],
                    "schedule": {"state": "disabled", "nextRunAt": None, "lastRunAt": None,
                                 "lastCompletedAt": None, "source": None}}
        state = self.read_json(self.state_file, {})
        active, enabled = self.timer_state()
        valid = state.get("schema") == 1 and state.get("controllerId") == config["controllerId"]
        rows = {row["id"]: row for row in state.get("targets", []) if isinstance(row, dict) and isinstance(row.get("id"), str)} if valid and isinstance(state.get("targets"), list) else {}
        result = {"configured": True, "timer": {"active": active, "enabled": enabled},
                  "checkedAt": timestamp(state.get("checkedAt")) if valid else None,
                  "intervalSeconds": config["intervalSeconds"], "targets": []}
        result["schedule"] = self.timer_schedule(active, enabled, result["checkedAt"])
        now = self.clock()
        for target in config["targets"]:
            record = rows.get(target["id"], {})
            if record.get("revision") != target["revision"]:
                record = {}
            last_success = timestamp(record.get("lastSuccessAt"))
            lease_expires = timestamp(record.get("expiresAt")) if target["kind"] == "api" and record.get("result") == "success" else None
            code, message = "unverified", "尚无此授权/配置的有效验证记录"
            if record.get("result") == "error":
                code, message = "failed", "最近一轮失败：" + clean(record.get("error", "未确认成功"))
            elif record.get("errorCode") == "conflict":
                code, message = "unverified", "当前状态暂不接受保活；请到机器管理检查运行状态。"
            elif target.get("waitingStart") or record.get("errorCode") == "waiting_start":
                code, message = "waiting_start", "当前未运行，保活待启动；脚本不会自动开机。"
            elif record.get("result") == "success":
                fresh = last_success is not None and 0 <= now - parse_time(last_success) <= config["intervalSeconds"] * 2 + 60
                if target["kind"] == "api":
                    fresh = fresh and lease_expires is not None and parse_time(lease_expires) > now
                code = "healthy" if fresh else "stale"
                message = ("API 保活成功" if target["kind"] == "api" else "最近一轮 SSH 连通；不代表持续在线") if fresh else "旧成功记录已过期或时钟异常，需要重新验证"
                if fresh and target["kind"] == "api" and record.get("credentialPersistent") is False:
                    code, message = "unverified", "本轮 API 保活成功；定时任务尚缺持久授权，请运行 ibt key set。"
            rotation = target.get("rotation", {})
            machine_id = target.get("machineId") if target["kind"] == "api" else rotation.get("machineId") if isinstance(rotation, dict) else None
            if not isinstance(machine_id, str) or not ID_RE.fullmatch(machine_id) or SECRET_RE.search(machine_id):
                machine_id = None
            if target["kind"] == "ssh":
                if record.get("rotationStatus") in ("pending", "ambiguous", "blocked"):
                    code, message = "token_pending", clean(record.get("rotationMessage", "SSH 自动更新尚未完成。"))
                expiry = target.get("tokenExpiry", {"kind": "unknown"})
                if expiry["kind"] == "verified" and parse_time(expiry["expiresAt"]) <= now:
                    code, message = "token_expired", "SSH 授权已到期，请更新授权。"
            if code == "healthy" and (active != "active" or enabled != "enabled"):
                code = "disabled" if active == "inactive" or enabled == "disabled" else "unknown"
                message += ("；定时任务仅在当前会话运行，尚未启用自启" if active == "active" and enabled == "disabled" else
                            "；本机定时保活未运行" if active == "inactive" else "；定时任务状态无法读取")
            result["targets"].append({"id": clean(target["id"], 128), "kind": target["kind"], "label": clean(target["label"], 80),
                                      "machineId": machine_id, "status": code, "message": clean(message, 400),
                                      "lastSuccessAt": last_success, "checkedAt": timestamp(record.get("checkedAt")),
                                      "leaseExpiresAt": lease_expires})
        return result

    def display_targets(self, rows, details=True, targets=None):
        """Use a compact result table or one complete, aligned group per target."""
        from cloud import fit_text, table_lines
        labels = {"healthy": "保活成功", "stale": "需要复查", "failed": "执行失败", "disabled": "未完整开启",
                  "unverified": "待确认", "waiting_start": "待启动", "token_pending": "授权待处理",
                  "token_expired": "授权已到期", "unknown": "未确认"}

        def result_label(row):
            return "本轮连通" if row["status"] == "healthy" and row["kind"] == "ssh" else labels.get(row["status"], "未确认")

        if not details:
            table = [[str(index), fit_text(clean(row["label"], 80), 24),
                      "API" if row["kind"] == "api" else "SSH", result_label(row)]
                     for index, row in enumerate(rows, 1)]
            for line in table_lines(["编号", "目标名称", "方式", "保活结果"], table):
                self.say(line)
            return
        settings = {target["id"]: target for target in targets or []}
        for index, row in enumerate(rows, 1):
            if index > 1:
                self.say("")
            self.say(str(index) + ". " + clean(row["label"], 80))
            self.say("  保活方式： " + ("API" if row["kind"] == "api" else "SSH"))
            self.say("  保活结果： " + result_label(row))
            self.say("  最近成功： " + format_timestamp(row.get("lastSuccessAt")))
            if row["kind"] == "api":
                expiry = format_timestamp(row.get("leaseExpiresAt"))
                if expiry == "未记录":
                    expiry = "本轮未确认"
                elif parse_time(row["leaseExpiresAt"]) <= self.clock():
                    expiry += "（已过期）"
                self.say("  本轮有效： " + expiry)
            else:
                self.say("  验证范围： 仅确认单轮 SSH 连通")
                target = settings.get(row.get("id"))
                if target is not None:
                    expiry = target.get("tokenExpiry", {"kind": "unknown"})
                    rotation = target.get("rotation", {})
                    rotating = isinstance(rotation, dict) and (rotation.get("enabled") or rotation.get("armed"))
                    if expiry["kind"] == "unknown":
                        self.say("  授权到期： 未知（无法从 SSH token 推算）")
                    else:
                        remaining = parse_time(expiry["expiresAt"]) - self.clock()
                        verified = expiry["kind"] == "verified"
                        suffix = ("（已到期，请更新授权）" if verified else "（预计已到期，请更新授权）") if remaining <= 0 else "（24 小时内，请准备更新）" if remaining <= 86400 else "（平台读回）" if verified else "（用户估计）"
                        self.say(("  授权到期： " if verified else "  预计到期： ") + format_timestamp(expiry["expiresAt"]) + suffix)
                    self.say("  授权说明： " + ("已配置自动换新，原 token 本身不会延长。" if rotating else "未配置自动换新；可用 ibt keepalive rotate-setup 开启。"))
            if row["status"] != "healthy" and row.get("message"):
                self.say("  状态详情： " + clean(row["message"], 400))

    def status(self, brief=False):
        config = self.load_config()
        summary = self._summary(config)
        if not summary["configured"]:
            self.say("持续保活尚未配置；请在保活页 1 一键保活机器，或在 2 管理目标。" if brief else "持续保活尚未配置。")
            return 0
        self.say("自动保活： " + automatic_description(summary))
        self.say("最近完成： " + format_timestamp(summary["schedule"]["lastCompletedAt"]))
        self.say("下次执行： " + schedule_description(summary))
        self.say("检查间隔： " + str(config["intervalSeconds"]) + " 秒（本轮完成后计时）")
        if not brief:
            self.say("后台驻留： " + ("已确认（Linger）" if self.linger() else "未确认，退出终端后可能停止"))
        self.say("")
        self.display_targets(summary["targets"], details=not brief, targets=config["targets"])
        result = 0 if all(row["status"] == "healthy" for row in summary["targets"]) else 2
        if brief:
            self.say("详情与有效期可在保活页 7 查看。")
            return result
        if any(row["status"] == "waiting_start" or row["message"].startswith("当前状态暂不接受保活") for row in summary["targets"]):
            self.say("")
            self.say("请先检查机器状态；需要启动时可按以下路径操作。")
            self.say("操作提示： 保活页 6 → 机器管理 → 2 启动所选机器。")
        self.say("")
        self.say("当前控制器维护已选目标；控制器暂停或停止后，本机任务无法继续执行。")
        self.say("请从其它机器或平台控制台恢复控制器。")
        return result

    def write_units(self, interval):
        parent = self.home / ".config"
        ensure_directory(parent, private=False)
        ensure_directory(parent / "systemd", private=False)
        ensure_directory(self.unit_dir, private=False)
        for name in (SERVICE, TIMER):
            unit = self.unit_dir / name
            if check_owned(unit, private=False):
                # Units are not secrets, but never overwrite a foreign service.
                with open(unit, encoding="utf-8") as stream:
                    if not OWNED_UNIT_MARKERS.intersection(stream.read(10000).splitlines()):
                        raise HeartbeatError("同名 systemd 单元不属于本工具，不会覆盖。", "unit_conflict")
        python_path = os.path.abspath(sys.executable)
        escaped_python = python_path.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
        service = "\n".join([UNIT_MARKER, "[Unit]", "Description=InstaBox Tool activity heartbeat", "After=network-online.target", "", "[Service]", "Type=oneshot",
                              'ExecStart="' + escaped_python + '" "%h/.local/share/insta-box/cli/heartbeat.py" run',
                              "TimeoutStartSec=" + str(ROUND_TIMEOUT_SECONDS), "UMask=0077", "NoNewPrivileges=true", ""])
        timer = "\n".join([UNIT_MARKER, "[Unit]", "Description=InstaBox Tool periodic activity heartbeat", "", "[Timer]", "OnStartupSec=30s",
                            "OnUnitInactiveSec=" + str(interval_value(interval)) + "s", "RandomizedDelaySec=15s", "AccuracySec=1s", "Unit=" + SERVICE,
                            "", "[Install]", "WantedBy=timers.target", ""])
        # atomic_text requires a private parent. User units may legitimately use 755;
        # making this user-owned directory private does not affect systemd access.
        os.chmod(self.unit_dir, 0o700)
        atomic_text(self.unit_dir / SERVICE, service)
        atomic_text(self.unit_dir / TIMER, timer)

    def linger(self):
        try:
            result = self.call(["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"], timeout=15)
            return result.returncode == 0 and result.stdout.strip() == "yes"
        except HeartbeatError:
            return False

    def enable_timer(self):
        config = self.load_config(required=True)
        if not config["targets"]:
            raise HeartbeatError("没有保活目标，未启用定时任务。", "not_configured")
        result = self.call(["systemctl", "--user", "show-environment"], timeout=15)
        if result.returncode != 0:
            raise HeartbeatError("用户级 systemd 不可用，未启用定时任务；请从 SSH 会话检查。", "systemd")
        lingering = self.linger()
        if not lingering and not any(self.env.get(name) == "1" for name in ("IBT_NO_SUDO", "IB_NO_SUDO", "SB_NO_SUDO")):
            try:
                username = pwd.getpwuid(os.getuid()).pw_name
                self.call(["sudo", "-n", "loginctl", "enable-linger", username], timeout=15)
            except (HeartbeatError, KeyError):
                pass
            lingering = self.linger()
        self.write_units(config["intervalSeconds"])
        for command in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", TIMER]):
            if self.call(command).returncode != 0:
                raise HeartbeatError("定时任务启用失败；目标已保存，请检查 systemd 后运行 ibt keepalive start。", "systemd")
        active, enabled = self.timer_state()
        if active != "active" or enabled != "enabled":
            raise HeartbeatError("定时任务未读回运行和自启状态，不会标记成功。", "systemd")
        needs_api = any(target["kind"] == "api" or isinstance(target.get("rotation"), dict) and (target["rotation"].get("enabled") or target["rotation"].get("armed")) for target in config["targets"])
        if self.env.get("INSTABOX_API_KEY", "").strip() and needs_api:
            if not self.persistent_key_matches(self.read_key()):
                self.say("本轮使用环境中的 API Key，定时任务尚缺相同的持久授权；请运行 ibt key set 后再运行 ibt keepalive start。")
                return 2
        if lingering:
            self.say("后台任务： 已启用，退出终端后继续运行。")
            return 0
        self.say("后台任务： 已启用，退出终端后持续运行尚未确认。")
        return 2

    def start(self):
        result = self.run_once()
        timer_result = self.enable_timer()
        summary = self.summary()
        self.say("自动保活： " + automatic_description(summary))
        self.say("下次执行： " + schedule_description(summary))
        if result:
            self.say("配置已保存；仍有待启动或未确认目标，请查看各项状态。")
        return max(result, timer_result)

    def stop_timer(self):
        # A colliding unit name is not permission to stop another application.
        parents = (self.home / ".config", self.home / ".config" / "systemd", self.unit_dir)
        for parent in parents:
            if not check_owned(parent, directory=True, private=False):
                break
        else:
            for name in (SERVICE, TIMER):
                unit = self.unit_dir / name
                if check_owned(unit, private=False):
                    with open(unit, encoding="utf-8") as stream:
                        if not OWNED_UNIT_MARKERS.intersection(stream.read(10000).splitlines()):
                            raise HeartbeatError("同名 systemd 单元不属于本工具，不会停用。", "unit_conflict")
        failed = False
        for command in (["systemctl", "--user", "disable", "--now", TIMER], ["systemctl", "--user", "stop", SERVICE]):
            try:
                if self.call(command, timeout=45).returncode != 0:
                    failed = True
            except HeartbeatError:
                failed = True
        active, enabled = self.timer_state()
        stopped = self.service_stopped()
        if active == "inactive" and enabled == "disabled" and stopped:
            failed = False
        elif active != "inactive" or enabled != "disabled" or not stopped:
            failed = True
        if failed:
            self.say("定时任务停止未完全确认；请检查用户级 systemd。")
        else:
            self.say("定时任务已停用。")
        return 2 if failed else 0

    def service_stopped(self):
        try:
            result = self.call(["systemctl", "--user", "is-active", SERVICE], timeout=10)
            return result.returncode != 0 and (result.stdout or "").strip() in ("inactive", "failed", "unknown")
        except HeartbeatError:
            return False

    def stop(self):
        timer_result = self.stop_timer()
        try:
            config = self.load_config()
        except HeartbeatError as error:
            if error.code not in ("config", "interval"):
                raise
            self.say("本地目标配置损坏，无法逐项清理远端保活；已先处理定时任务，远端本轮保活最长 3600 秒后结束。")
            return 2
        if not self.ensure_cfg():
            return timer_result
        with self.lock() as acquired:
            if not acquired:
                self.say("仍有保活轮次运行，暂未清理远端保活；请稍后重试停止。")
                return 2
            self.cleanup_ssh_files()
            lease_result = self.release_targets(config["targets"], config)
            if check_owned(self.state_file):
                atomic_json(self.state_file, {"schema": 1, "controllerId": config["controllerId"], "stoppedAt": iso_time(self.clock()), "targets": []})
        return max(timer_result, lease_result)

    def clear(self):
        cfg_exists = self.ensure_cfg()
        private_artifacts = any(check_owned(filename) for filename in (self.config_file, self.state_file, self.known_hosts)) if cfg_exists else False
        if cfg_exists and any(filename.name.startswith(".heartbeat-ssh-") for filename in self.cfg.iterdir()):
            private_artifacts = True
        units_exist = False
        if check_owned(self.home / ".config", directory=True, private=False) and check_owned(self.home / ".config" / "systemd", directory=True, private=False) and check_owned(self.unit_dir, directory=True, private=False):
            units_exist = any(check_owned(self.unit_dir / name, private=False) for name in (SERVICE, TIMER))
        if not private_artifacts and not units_exist:
            self.say("持续保活尚未配置，无需清理。")
            return 0
        self.stop()
        active, enabled = self.timer_state()
        if active != "inactive" or enabled != "disabled" or not self.service_stopped():
            raise HeartbeatError("未确认定时任务已停用，保留配置供排查；请先运行 ibt keepalive stop。", "systemd")
        result = 0  # Remote lease release is best-effort once local renewal is stopped.
        if self.ensure_cfg():
            with self.lock() as acquired:
                if not acquired:
                    raise HeartbeatError("保活仍在运行，未清理配置。", "busy")
                self.cleanup_ssh_files()
                for filename in (self.config_file, self.state_file, self.known_hosts, self.cfg / "heartbeat_known_hosts.old"):
                    if check_owned(filename):
                        filename.unlink()
        if check_owned(self.home / ".config" / "systemd", directory=True, private=False) and check_owned(self.unit_dir, directory=True, private=False):
            for name in (TIMER, SERVICE):
                unit = self.unit_dir / name
                if check_owned(unit, private=False):
                    with open(unit, encoding="utf-8") as stream:
                        owned = bool(OWNED_UNIT_MARKERS.intersection(stream.read(10000).splitlines()))
                    if owned:
                        unit.unlink()
            try:
                if self.call(["systemctl", "--user", "daemon-reload"]).returncode:
                    result = 2
            except HeartbeatError:
                result = 2
        self.say("持续保活目标、SSH 凭据和记录已清除；共享 API Key 保留。")
        return result

    def logs(self):
        result = self.call(["journalctl", "--user", "-u", SERVICE, "-n", "80", "--no-pager", "-o", "cat"], timeout=15)
        if result.returncode:
            raise HeartbeatError("无法读取保活日志。", "logs")
        for line in (result.stdout or "").splitlines():
            self.say(line)
        return 0

    def choose_interval(self, config):
        answer = self.prompt("检查间隔 60–900 秒 [" + str(config["intervalSeconds"]) + "]：").strip()
        if not answer:
            return config["intervalSeconds"]
        if not re.fullmatch(r"[0-9]{2,3}", answer):
            raise HeartbeatError("检查间隔必须是 60–900 秒的整数。", "interval")
        return interval_value(int(answer))

    def selected_machines(self, machines):
        """Normalize only the explicit selection; never expand to the account."""
        if not isinstance(machines, list) or not machines or len(machines) > MAX_TARGETS:
            raise HeartbeatError("请明确选择 1–20 台机器。", "selection")
        result, seen = [], set()
        for machine in machines:
            if not isinstance(machine, dict) or not isinstance(machine.get("id"), str) or not ID_RE.fullmatch(machine["id"]):
                raise HeartbeatError("已选机器标识无效。", "selection")
            if machine["id"] in seen:
                continue
            seen.add(machine["id"])
            state = machine.get("state", "unknown")
            if not isinstance(state, str) or state not in MACHINE_STATES:
                state = "unknown"
            result.append({"id": machine["id"], "name": clean(machine.get("name") or machine["id"], 80), "state": state})
        return result

    def api_target_for_machine(self, machine, old=None):
        target = dict(old) if old else {"id": "api_" + uuid.uuid4().hex[:12], "kind": "api", "machineId": machine["id"],
                                        "revision": uuid.uuid4().hex}
        waiting = machine["state"] != "running"
        if old is not None and bool(old.get("waitingStart")) != waiting:
            target["revision"] = uuid.uuid4().hex
        target.update(label=machine["name"] or "InstaBox", waitingStart=waiting, observedState=machine["state"])
        return target

    def assert_config_snapshot(self, previous, existed):
        if check_owned(self.config_file) != existed or (existed and self.load_config(required=True) != previous):
            raise HeartbeatError("配置刚被其他操作修改，请重新选择。", "config_changed")

    def retain_current_state(self, config):
        """Remove only obsolete health records while the configuration lock is held."""
        try:
            state = self.read_json(self.state_file, {})
        except HeartbeatError as error:
            if error.code != "config":
                raise
            state = {}
        revisions = {target["id"]: target["revision"] for target in config["targets"]}
        rows = state.get("targets", [])
        valid = state.get("schema") == 1 and state.get("controllerId") == config["controllerId"]
        kept = [row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str) and row["id"] in revisions and row.get("revision") == revisions[row["id"]]] if valid and isinstance(rows, list) else []
        atomic_json(self.state_file, {"schema": 1, "controllerId": config["controllerId"],
                                     "checkedAt": state.get("checkedAt") if valid else None, "targets": kept})

    def set_api_targets(self, machines, enabled=True):
        """Enable/disable only machines explicitly selected in the cloud UI.

        SSH and other API targets survive unchanged. A non-running selection is
        preconfigured, never started; a later observed running state unlocks PUT.
        """
        if not isinstance(enabled, bool):
            raise HeartbeatError("保活开关参数无效。", "arguments")
        selected = self.selected_machines(machines)
        existed = self.ensure_cfg() and check_owned(self.config_file)
        previous = self.load_config()
        selected_ids = {machine["id"] for machine in selected}
        existing = {target["machineId"]: target for target in previous["targets"] if target["kind"] == "api"}
        if enabled:
            replacements = {machine["id"]: self.api_target_for_machine(machine, existing.get(machine["id"])) for machine in selected}
            targets = [replacements.get(target.get("machineId"), target) if target["kind"] == "api" else target for target in previous["targets"]]
            targets.extend(replacements[machine["id"]] for machine in selected if machine["id"] not in existing)
            removed = []
        else:
            targets = [target for target in previous["targets"] if target["kind"] != "api" or target["machineId"] not in selected_ids]
            removed = [target for target in previous["targets"] if target["kind"] == "api" and target["machineId"] in selected_ids]
        config = {**previous, "targets": targets}
        self.validate_config(config)
        if not enabled and not removed and not existed:
            self.say("所选机器尚未在本机开启 API 保活。")
            return 0
        with self.lock() as acquired:
            if not acquired:
                raise HeartbeatError("保活轮次正在运行，未修改目标；请稍后重试。", "busy")
            self.assert_config_snapshot(previous, existed)
            if not enabled and not removed:
                self.say("所选机器尚未在本机开启 API 保活。")
                return 0
            if not enabled and not targets and self.stop_timer():
                return 2
            atomic_json(self.config_file, config)
            self.retain_current_state(config)
            if enabled:
                self.say("已保存所选机器的 API 保活；暂停或停止的机器会等待启动，脚本不会自动开机。")
                result = self._run_locked(config, {target["id"] for target in targets if target["kind"] == "api" and target["machineId"] in selected_ids})
            else:
                result = self.release_targets(removed, previous)
                self.say("已关闭所选机器在本机的 API 保活；其它目标及 SSH 探测保持原样。")
        return max(result, self.enable_timer()) if enabled else result

    def refresh_observed_targets(self, machines):
        """Apply an explicit cloud lifecycle observation to existing targets only.

        A disabled timer remains disabled. The overview must never call this
        mutator; ordinary web-console starts are observed by waiting targets.
        """
        selected = self.selected_machines(machines)
        if not self.ensure_cfg() or not check_owned(self.config_file):
            return 0
        previous = self.load_config(required=True)
        observations = {machine["id"]: machine for machine in selected}
        matching = [target for target in previous["targets"] if target["kind"] == "api" and target["machineId"] in observations]
        if not matching:
            return 0
        targets = [self.api_target_for_machine(observations[target["machineId"]], target) if target["kind"] == "api" and target["machineId"] in observations else target for target in previous["targets"]]
        config = {**previous, "targets": targets}
        with self.lock() as acquired:
            if not acquired:
                raise HeartbeatError("保活轮次正在运行，将由后续检查确认目标状态。", "busy")
            self.assert_config_snapshot(previous, True)
            if config != previous:
                self.validate_config(config)
                atomic_json(self.config_file, config)
                self.retain_current_state(config)
            active, enabled = self.timer_state()
            running_ids = {target["id"] for target in targets if target["kind"] == "api" and target["machineId"] in observations and observations[target["machineId"]]["state"] == "running"}
            if running_ids and active == "active" and enabled == "enabled":
                return self._run_locked(config, running_ids)
        return 0

    def save_and_start(self, config, previous):
        self.validate_config(config)
        if not config["targets"]:
            raise Cancelled()
        with self.lock() as acquired:
            if not acquired:
                raise HeartbeatError("保活轮次正在运行，未修改目标；请稍后重试。", "busy")
            current = self.load_config()
            if check_owned(self.config_file) and current != previous:
                raise HeartbeatError("配置刚被其他操作修改，请重新选择。", "config_changed")
            atomic_json(self.config_file, config)
            new_machines = {target.get("machineId") for target in config["targets"] if target["kind"] == "api"}
            removed = [target for target in previous["targets"] if target["kind"] == "api" and target["machineId"] not in new_machines]
            release_result = self.release_targets(removed, previous)
        self.say("保活目标已保存，正在验证本轮连接。")
        return max(release_result, self.start())

    def automatic_machines(self):
        """Validate and persist shared authorization before changing any targets."""
        from cloud import Cloud, CloudError, ensure_api
        try:
            api = ensure_api(self.cfg)
            if not self.persistent_key_matches(api.key):
                raise HeartbeatError("API Key 未持久保存，后台保活尚无可用授权。", "key_missing")
            machines = Cloud(api, self.cfg, say=self.say).list_machines()
        except CloudError as error:
            raise HeartbeatError(str(error), "authorization") from None
        if not machines:
            raise HeartbeatError("当前授权下没有可选择的机器。", "no_machines")
        return machines

    def auto(self):
        """Add currently running API machines without replacing other targets."""
        machines = self.automatic_machines()
        running = [machine for machine in machines if machine.get("state") == "running"]
        if not running:
            raise HeartbeatError("当前没有运行中的机器；请先在机器管理中启动需要保活的机器。", "not_running")
        self.say("保活范围： 当前运行中的 " + str(len(running)) + " 台机器。")
        return self.set_api_targets(running)

    def auto_local(self):
        """Bind the local host by exact API name, or require an explicit choice."""
        machines = self.automatic_machines()
        hostname = socket.gethostname()
        matches = [machine for machine in machines
                   if isinstance(machine.get("name"), str) and hostname == "instabox-" + machine["name"]]
        if len(matches) == 1:
            selected = matches[0]
        else:
            from cloud import fit_text, table_lines
            self.say("本机名称无法唯一对应平台机器，请明确选择当前登录的机器。")
            rows = [[str(index), fit_text(clean(machine.get("name") or machine["id"], 80), 28),
                     MACHINE_LABELS.get(str(machine.get("state", "unknown")), "状态未知"), machine["id"]]
                    for index, machine in enumerate(machines, 1)]
            for line in table_lines(["编号", "机器名称", "机器状态", "机器 ID"], rows):
                self.say(line)
            answer = self.prompt("确认本机编号（0 或空行取消）：").strip()
            if not answer or answer == "0":
                raise Cancelled()
            if not answer.isascii() or not answer.isdigit() or not 1 <= int(answer) <= len(machines):
                raise HeartbeatError("请输入当前机器的一个有效编号。", "selection")
            selected = machines[int(answer) - 1]
        if selected.get("state") != "running":
            raise HeartbeatError("所选机器当前未运行；请先在机器管理中启动，再重新选择本机。", "not_running")
        self.say("本机目标： " + clean(selected.get("name") or selected["id"], 80))
        return self.set_api_targets([selected])

    def setup_api(self, add=False):
        previous = self.load_config()
        key = self.authorize()
        machines = self.list_machines(key)
        if not machines:
            raise HeartbeatError("当前授权下没有可选择的机器。", "no_machines")
        existing = {target["machineId"]: target for target in previous["targets"] if target["kind"] == "api"}
        defaults = [str(index + 1) for index, machine in enumerate(machines) if machine["id"] in existing and machine["state"] == "running"] if not add else []
        from cloud import fit_text, table_lines
        rows = []
        for index, machine in enumerate(machines, 1):
            state = MACHINE_LABELS.get(machine["state"], "状态未知")
            rows.append([str(index), fit_text(machine["name"], 28), state, "已配置" if machine["id"] in existing else "未配置"])
        for line in table_lines(["编号", "目标名称", "机器状态", "API 保活"], rows):
            self.say(line)
        self.say("仅维护明确选择的目标；不会自动选择账号内所有机器。")
        self.say("暂停或停止的机器可预先配置为待启动；脚本不会替你开机，启动后将自动继续保活。")
        if defaults:
            self.say("空行默认保留已选且运行中的机器；待启动目标需明确输入编号。")
        suffix = " [" + ",".join(defaults) + "]" if defaults else "（空行取消）"
        answer = self.prompt("选择编号，多个用逗号分隔" + suffix + "：").strip()
        if not answer and defaults:
            answer = ",".join(defaults)
        if not answer or answer == "0":
            raise Cancelled()
        if not re.fullmatch(r"[0-9]+(?:\s*[,，]\s*[0-9]+)*", answer):
            raise HeartbeatError("请输入明确的机器编号，例如 1,2。", "selection")
        indices = list(dict.fromkeys(int(number) for number in re.split(r"[,，]\s*", answer)))
        if any(index < 1 or index > len(machines) for index in indices):
            raise HeartbeatError("机器编号超出列表范围。", "selection")
        selected = self.selected_machines([machines[index - 1] for index in indices])
        replacements = {machine["id"]: self.api_target_for_machine(machine, existing.get(machine["id"])) for machine in selected}
        targets = [replacements.get(target.get("machineId"), target) if target["kind"] == "api" else target for target in previous["targets"]] if add else [target for target in previous["targets"] if target["kind"] != "api"]
        added_ids = {target.get("machineId") for target in targets if target["kind"] == "api"}
        targets.extend(replacements[machine["id"]] for machine in selected if machine["id"] not in added_ids)
        config = {**previous, "targets": targets, "intervalSeconds": self.choose_interval(previous)}
        return self.save_and_start(config, previous)

    def read_ssh_target(self, label_default, old=None):
        command = self.secret("粘贴 SSH/Mosh 命令（不回显；空行结束）：")
        if not command.strip():
            return None
        ssh = parse_ssh_command(command)
        label = clean(self.prompt("目标名称 [" + label_default + "]：").strip() or label_default, 80)
        if not label:
            label = label_default
        self.say("无法从连接授权可靠推算到期时间；留空会记为未知。")
        expiry = token_expiry(self.prompt("预计剩余小时（可选）：").strip(), self.clock())
        target = {"id": old["id"] if old else "ssh_" + uuid.uuid4().hex[:12], "kind": "ssh", "label": label,
                  "revision": uuid.uuid4().hex, "ssh": ssh, "tokenExpiry": expiry}
        if old and old.get("ssh", {}).get("user") == ssh["user"]:
            if old.get("tokenExpiry", {}).get("kind") == "verified":
                target["tokenExpiry"] = dict(old["tokenExpiry"])
            if old.get("rotation"):
                target["rotation"] = dict(old["rotation"])
        elif old and old.get("rotation"):
            self.say("已替换连接授权；原机器的自动更新绑定已清除，如需自动更新请重新配置。")
        return target

    def setup_ssh(self, add=False):
        previous = self.load_config()
        targets = list(previous["targets"]) if add else [target for target in previous["targets"] if target["kind"] != "ssh"]
        new_targets = []
        self.say("SSH 基础心跳执行固定探测，只确认每轮连通，不会签发新授权；可通过 rotate-setup 配置到期前自动换新。")
        self.say("当前控制器维护你选择的目标；控制器暂停或停止后，任务需要从外部恢复。")
        while len(targets) + len(new_targets) < MAX_TARGETS:
            try:
                target = self.read_ssh_target("SSH " + str(len(targets) + len(new_targets) + 1))
            except HeartbeatError as error:
                self.say(str(error))
                continue
            if target is None:
                break
            if any(row.get("ssh", {}).get("user") == target["ssh"]["user"] for row in targets + new_targets):
                self.say("该连接授权已经在列表中，未重复添加。")
                continue
            new_targets.append(target)
            self.say("已暂存目标 " + target["label"] + "；可继续粘贴或输入空行完成。")
        if not new_targets:
            raise Cancelled()
        config = {**previous, "targets": targets + new_targets, "intervalSeconds": self.choose_interval(previous)}
        return self.save_and_start(config, previous)

    def select_target(self, config, selector=None, kind=None):
        targets = [target for target in config["targets"] if kind is None or target["kind"] == kind]
        if not targets:
            raise HeartbeatError("没有符合条件的保活目标。", "selection")
        if selector:
            matches = [target for target in targets if selector in (target["id"], target["label"], target.get("machineId"))]
            if len(matches) != 1:
                raise HeartbeatError("目标名称或标识未匹配到唯一目标；请不带目标参数重试，再按编号选择。", "selection")
            return matches[0]
        from cloud import fit_text, table_lines
        rows = [[str(index), fit_text(clean(target["label"], 80), 28), "API" if target["kind"] == "api" else "SSH"]
                for index, target in enumerate(targets, 1)]
        for line in table_lines(["编号", "目标名称", "方式"], rows):
            self.say(line)
        answer = self.prompt("选择目标编号（空行返回）：").strip()
        if not answer or answer == "0":
            raise Cancelled()
        if not answer.isdigit() or not 1 <= int(answer) <= len(targets):
            raise HeartbeatError("目标编号无效。", "selection")
        return targets[int(answer) - 1]

    def renew(self, selector=None):
        previous = self.load_config(required=True)
        old = self.select_target(previous, selector, kind="ssh")
        target = self.read_ssh_target(clean(old["label"], 80), old=old)
        if target is None:
            raise Cancelled()
        if any(row["id"] != old["id"] and row.get("ssh", {}).get("user") == target["ssh"]["user"] for row in previous["targets"]):
            raise HeartbeatError("该连接授权已经属于另一个目标。", "selection")
        config = {**previous, "targets": [target if row["id"] == old["id"] else row for row in previous["targets"]]}
        return self.save_and_start(config, previous)

    def remove(self, selector=None):
        previous = self.load_config(required=True)
        target = self.select_target(previous, selector)
        config = {**previous, "targets": [row for row in previous["targets"] if row["id"] != target["id"]]}
        if not config["targets"]:
            timer_result = self.stop_timer()
        else:
            timer_result = 0
        with self.lock() as acquired:
            if not acquired:
                raise HeartbeatError("保活轮次仍在运行，未删除目标，请稍后重试。", "busy")
            if self.load_config(required=True) != previous:
                raise HeartbeatError("配置刚被其他操作修改，请重新选择。", "config_changed")
            self.cleanup_ssh_files()
            atomic_json(self.config_file, config)
            result = self.release_targets([target], previous)
            state = self.read_json(self.state_file, {})
            if isinstance(state.get("targets"), list):
                state["targets"] = [row for row in state["targets"] if isinstance(row, dict) and row.get("id") != target["id"]]
                atomic_json(self.state_file, state)
        self.say("已移除目标 " + clean(target["label"], 80) + "。")
        return max(result, timer_result)

    def dispatch(self, args):
        command = args[0] if args else "status"
        if args == ["status", "--brief"]:
            return self.status(brief=True)
        if "--brief" in args or len(args) > 2 or (len(args) > 1 and command not in ("renew", "remove")):
            raise HeartbeatError("参数无效；凭据仅通过不回显交互输入。", "arguments")
        selector = args[1] if len(args) > 1 else None
        if command == "setup":
            self.say("1 API 保活（推荐，使用已保存的 API Key）")
            self.say("2 SSH 定期连通探测（粘贴控制台命令）")
            choice = self.prompt("选择方式 [1]；0 返回：").strip() or "1"
            if choice == "0":
                raise Cancelled()
            if choice not in ("1", "2"):
                raise HeartbeatError("请输入 1 或 2。", "selection")
            return self.setup_api() if choice == "1" else self.setup_ssh()
        commands = {"auto": self.auto, "auto-local": self.auto_local,
                    "setup-api": self.setup_api, "setup-ssh": self.setup_ssh,
                    "add": lambda: self.setup_ssh(add=True), "add-api": lambda: self.setup_api(add=True),
                    "renew": lambda: self.renew(selector), "remove": lambda: self.remove(selector),
                    "run": self.run_once, "status": self.status, "start": self.start,
                    "stop": self.stop, "clear": self.clear, "logs": self.logs}
        if command not in commands:
            raise HeartbeatError("使用 auto|auto-local|setup|setup-api|setup-ssh|add|add-api|renew|remove|run|status|start|stop|clear|logs。", "arguments")
        return commands[command]()


def main(args=None, manager=None):
    manager = manager or Manager()
    arguments = sys.argv[1:] if args is None else args
    command = arguments[0] if arguments else "status"
    try:
        return manager.dispatch(arguments)
    except KeyboardInterrupt:
        manager.say("已中断；已发出的请求或已保存的配置可能仍然存在，操作未完成确认。")
        return 130
    except Cancelled:
        manager.say("已取消；未提交的目标修改未保存。")
        return 2 if command in ("auto", "auto-local") else 0
    except EOFError:
        if command in ("auto", "auto-local"):
            manager.say("已取消；自动保活尚未配置完成。")
            return 2
        if command in ("setup", "setup-api", "setup-ssh", "add", "add-api", "renew", "remove"):
            manager.say("已取消；未提交的目标修改未保存。")
            return 0
        manager.say("[失败] 操作意外结束；停止或清理尚未确认完成。")
        return 1
    except HeartbeatError as error:
        manager.say("[失败] " + str(error))
        return 2
    except Exception:
        manager.say("[失败] 本地保活操作异常；未输出私有配置或凭据。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
