#!/usr/bin/env python3
# Author: Pre
"""InstaBox Tool cloud management. Uses only the Python standard library."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import getpass
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings


API_ROOT = "https://api.instabox.sh"
MACHINE_ID = re.compile(r"m_[A-Za-z0-9_-]{1,128}\Z")
OPERATION_ID = re.compile(r"op_[A-Za-z0-9_-]{1,128}\Z")
PENDING = {"prepared", "unknown", "queued", "running"}
OP_STATES = {"queued", "running", "succeeded", "failed"}
ACTIONS = {"start": "start", "pause": "suspend", "resume": "resume", "stop": "stop"}
EXPECTED = {"start": "running", "resume": "running", "pause": "suspended", "stop": "stopped"}
STATE_LABELS = {
    "creating": "创建中", "starting": "启动中", "running": "运行中",
    "stopping": "停止中", "stopped": "已停止", "suspending": "暂停中",
    "suspended": "已暂停", "resuming": "恢复中", "deleting": "删除中",
    "deleted": "已删除", "error": "异常",
}
ERROR_CODES = {
    "invalid_request", "invalid_argument", "unauthenticated", "permission_denied",
    "not_found", "machine_not_found", "operation_conflict", "idempotency_conflict",
    "machine_not_running", "quota_exceeded", "no_capacity", "internal", "unavailable",
    "invite_required", "api_key_expired", "api_key_revoked", "insufficient_scope",
    "runtime_not_ready", "credit_exhausted", "spend_limit_reached",
    "subscription_required", "rate_limited", "concurrency_limit", "payment_failed",
}


class CloudError(Exception):
    """Messages in this exception are locally composed, never raw API messages."""


class APIError(CloudError):
    def __init__(self, status=0, code="", operation_id=""):
        self.status = status
        self.code = code if isinstance(code, str) and code in ERROR_CODES else ""
        self.operation_id = operation_id if isinstance(operation_id, str) and OPERATION_ID.fullmatch(operation_id) else ""
        self.uncertain = status == 0 or status >= 500 or status == 408 or 300 <= status < 400
        messages = {
            0: "网络中断、请求超时或响应格式异常；请求结果尚未确认。",
            400: "请求被平台拒绝，请检查参数与当前平台规则。",
            401: "API Key 无效、已过期或已撤销；请更新本机授权。",
            402: "账号余额、额度或订阅条件不满足。",
            403: "当前授权、账号或套餐策略不允许此操作；也可能缺少权限或尚未激活。",
            404: "目标不存在，或当前授权无法访问。",
            409: "机器状态、进行中的操作或幂等请求发生冲突。",
            429: "平台请求频率、并发或资源配额受限，请稍后再试。",
            503: "平台暂不可用或容量不足，请稍后查询请求结果。",
        }
        message = "平台返回重定向，已拒绝跟随，凭据未发送到跳转地址。" if 300 <= status < 400 else messages.get(status, "平台请求失败，未显示原始响应。")
        prefix = f"HTTP {status}：" if status else ""
        if self.code:
            message += f" 错误码：{self.code}。"
        if self.operation_id:
            message += f" 相关操作：{self.operation_id}；可用 ibt cloud operation 查询。"
        super().__init__(prefix + message)


def clean(value, secret="", limit=160):
    if not isinstance(value, (str, int, float, bool, BaseException)):
        return "未知"
    text = str(value)
    if secret:
        text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"(?:ibk|ibssh)_[A-Za-z0-9_.-]+", "[已隐藏]", text)
    text = re.sub(r"https?://\S+", "[地址已隐藏]", text)
    text = re.sub(r"(?i)(?:bearer\s+|(?:token|password|secret|api[_-]?key|authorization)\s*[:=]\s*)[^\s,;]+", "[凭据已隐藏]", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[已隐藏]", text)
    return "".join(c for c in text if unicodedata.category(c) not in {"Cc", "Cf", "Cs"})[:limit]


def display_width(value):
    return sum(0 if unicodedata.combining(c) or unicodedata.category(c) in {"Mn", "Me"}
               else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in value)


def fit_text(value, width):
    if display_width(value) <= width:
        return value
    result = ""
    for character in value:
        if display_width(result + character) > width - 1:
            break
        result += character
    return result + "…"


def table_lines(headers, rows):
    widths = [max(display_width(row[i]) for row in [headers] + rows) for i in range(len(headers))]
    return ["  ".join(value + " " * (widths[i] - display_width(value)) for i, value in enumerate(row)).rstrip()
            for row in [headers] + rows]


def console_line(message=""):
    """Use the same left margin as the shell menus without changing TTY I/O."""
    print("  " + str(message) if message else "")


def number(value):
    if type(value) is int:
        return str(value) if 0 <= value <= 2**63 - 1 else "未知"
    return str(value) if type(value) is float and math.isfinite(value) and value >= 0 else "未知"


def boolean(value):
    return "是" if value is True else "否" if value is False else "未知"


def timestamp(value, absent="未知"):
    if value is None:
        return absent
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return "未知"
        local = parsed.astimezone()
        offset = local.strftime("%z")
        zone = "UTC" if offset == "+0000" else offset[:3] + ":" + offset[3:]
        return local.strftime("%Y-%m-%d %H:%M:%S ") + zone
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
        return "未知"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def check_path(path):
    """Reject symlinks in the directory chain as well as at a private file."""
    path = Path(path).absolute()
    for part in [*reversed(path.parents), path]:
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise CloudError("本机配置路径包含符号链接，已拒绝访问。")


def private_dir(path):
    check_path(path)
    try:
        if not path.parent.exists():
            private_dir(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise CloudError("本机配置目录不属于当前用户，已拒绝访问。")
        path.chmod(0o700)
    except OSError:
        raise CloudError("无法建立本机私有配置目录。") from None


def read_private(path, *, json_data=True):
    check_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {} if json_data else ""
    except OSError:
        raise CloudError("无法读取本机私有配置。") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise CloudError("本机私有配置必须是当前用户独有的普通文件。")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise CloudError("本机私有配置权限必须为 600，请先修正文件权限。")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            text = stream.read(262145)
        if len(text) > 262144:
            raise ValueError()
        if not json_data:
            return text.strip()
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (OSError, UnicodeError, ValueError):
        raise CloudError("本机私有配置格式异常，已停止。") from None
    finally:
        if fd >= 0:
            os.close(fd)


def atomic_private(path, data):
    private_dir(path.parent)
    check_path(path)
    temp = path.parent / ("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = None
    try:
        if path.exists() and not path.is_file():
            raise CloudError("本机配置目标不是普通文件。")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        check_path(path)
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise CloudError("无法原子保存本机私有配置；如已有提交，请先查询云端状态。") from None
    finally:
        if fd is not None:
            os.close(fd)
        if temp.exists():
            temp.unlink()


@contextmanager
def request_lock(path):
    private_dir(path.parent)
    check_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise CloudError("本机请求锁不安全，已停止。")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CloudError("本机另一个命令正在处理这台机器，请稍后查询 operation。") from None
        yield
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, key, opener=None):
        if not isinstance(key, str) or not key or len(key) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise CloudError("未提供有效格式的 InstaBox API Key。")
        self.key = key
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None, *, idempotency_key=None, timeout=30):
        if not path.startswith("/v1/") or "#" in path:
            raise CloudError("无效的 API 路径。")
        headers = {"X-API-Key": self.key, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            if not re.fullmatch(r"[!-~]{1,200}", idempotency_key):
                raise CloudError("本机幂等请求记录格式异常。")
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(API_ROOT + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=max(0.01, timeout)) as response:
                status = response.status
                if 300 <= status < 400:
                    raise APIError(status)
                raw = response.read(2097153)
                if len(raw) > 2097152:
                    raise ValueError()
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError()
                return status, payload
        except urllib.error.HTTPError as exc:
            try:
                error = json.loads(exc.read(65536)).get("error", {})
                error = error if isinstance(error, dict) else {}
            except (ValueError, OSError, AttributeError, http.client.HTTPException, RecursionError):
                error = {}
            raise APIError(exc.code, error.get("code"), error.get("operationId")) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError, http.client.HTTPException, RecursionError):
            raise APIError() from None

    def get(self, path, **kwargs):
        status, result = self.request("GET", path, **kwargs)
        if status != 200:
            raise APIError(status)
        return result


class Cloud:
    def __init__(self, api, config, *, say=console_line, ask=None, clock=None, sleep=None, heartbeat_manager=None):
        self.api, self.config, self.say = api, Path(config), say
        self.ask = ask or self.terminal_ask
        self.clock, self.sleep = clock or time.monotonic, sleep or time.sleep
        self.heartbeat_manager = heartbeat_manager
        self.last_lifecycle_result = "failed"

    @staticmethod
    def terminal_ask(prompt):
        if not sys.stdin.isatty():
            raise CloudError("此步骤需要交互输入；请指定目标，暂停/停止的自动化需明确传 --yes。")
        return input("  " + prompt).strip()

    def text(self, value):
        return clean(value, self.api.key)

    def list_machines(self):
        result, seen_ids, cursors = [], set(), set()
        cursor = None
        for _ in range(1000):
            path = "/v1/machines" + ("?" + urllib.parse.urlencode({"cursor": cursor}) if cursor else "")
            page = self.api.get(path)
            if not isinstance(page.get("machines"), list):
                raise CloudError("平台机器列表格式异常。")
            for machine in page["machines"]:
                if not isinstance(machine, dict) or not MACHINE_ID.fullmatch(str(machine.get("id", ""))):
                    raise CloudError("平台返回了无效的机器标识。")
                if machine["id"] not in seen_ids:
                    seen_ids.add(machine["id"])
                    result.append(machine)
            cursor = page.get("nextCursor")
            if cursor is None or cursor == "":
                return result
            if not isinstance(cursor, str) or len(cursor) > 4096 or cursor in cursors:
                raise CloudError("平台分页游标异常，已停止读取。")
            cursors.add(cursor)
        raise CloudError("平台分页过多，已停止读取。")

    def show_list(self, machines=None):
        machines = self.list_machines() if machines is None else machines
        self.say("可访问的机器（可能含组织其他成员的机器；所有动作仅作用于所选一台）：")
        if not machines:
            self.say("没有可访问的机器。")
            return
        rows = [[str(index), fit_text(self.text(machine.get("name") or "未命名"), 24),
                 STATE_LABELS.get(str(machine.get("state", "")), "未知"), self.text(machine["id"])]
                for index, machine in enumerate(machines, 1)]
        for line in table_lines(["编号", "名称", "状态", "机器 ID"], rows):
            self.say(line)

    def heartbeat(self):
        if self.heartbeat_manager is None:
            from heartbeat import Manager
            self.heartbeat_manager = Manager(home=self.config.parent.parent, output=self.say, prompt=self.ask)
        return self.heartbeat_manager

    def heartbeat_error(self, error, fallback):
        try:
            from heartbeat import HeartbeatError
        except ImportError:
            return fallback
        return self.text(error) if isinstance(error, HeartbeatError) else fallback

    def protection_summary(self):
        try:
            summary = self.heartbeat().summary()
            if not isinstance(summary, dict) or not isinstance(summary.get("targets"), list):
                raise ValueError()
            return summary
        except Exception as error:
            return {"configured": None, "timer": {}, "targets": [], "unavailable": True,
                    "reason": self.heartbeat_error(error, "本机保活记录暂时无法读取，请查看保活状态。")}

    @staticmethod
    def protection_label(machine, summary):
        if summary.get("unavailable"):
            return "本机状态未确认"
        targets = [target for target in summary["targets"] if isinstance(target, dict) and target.get("machineId") == machine["id"]]
        if not targets:
            return "未配置"
        # A confirmed API target is the primary protection; SSH is only a probe.
        targets.sort(key=lambda target: target.get("kind") != "api")
        target = targets[0]
        prefix = "SSH·" if target.get("kind") == "ssh" else ""
        timer = summary.get("timer", {})
        if not isinstance(timer, dict) or timer.get("active") != "active" or timer.get("enabled") != "enabled":
            if isinstance(timer, dict) and timer.get("active") == "inactive":
                return prefix + "已停用"
            if isinstance(timer, dict) and timer.get("active") == "active" and timer.get("enabled") == "disabled":
                return prefix + "尚未启用自启"
            return prefix + "调度未确认"
        state = machine.get("state") if isinstance(machine.get("state"), str) else ""
        if state in {"suspended", "stopped"}:
            return prefix + ("暂停待启动" if state == "suspended" else "停止待启动")
        if state != "running":
            return prefix + "等待机器就绪"
        labels = {"healthy": "最近连通" if prefix else "最近保活正常", "stale": "记录已过期",
                  "failed": "最近失败", "disabled": "已停用", "unverified": "等待验证",
                  "waiting_start": "等待下轮检查", "token_pending": "凭据待处理",
                  "token_expired": "凭据已到期", "unknown": "未确认"}
        return prefix + labels.get(str(target.get("status", "")), "未确认")

    def overview(self, machines=None):
        from heartbeat import automatic_description, format_timestamp, schedule_description

        machines = self.list_machines() if machines is None else machines
        summary = self.protection_summary()
        running = sum(machine.get("state") == "running" for machine in machines)
        suspended = sum(machine.get("state") == "suspended" for machine in machines)
        self.say(f"机器总览： 共 {len(machines)} 台 · 运行 {running} 台 · 暂停 {suspended} 台")
        self.say("自动保活： " + automatic_description(summary))
        schedule = summary.get("schedule")
        schedule = schedule if isinstance(schedule, dict) else {}
        self.say("最近完成： " + format_timestamp(schedule.get("lastCompletedAt") or summary.get("checkedAt")))
        self.say("下次执行： " + schedule_description(summary))
        self.say("")
        names = [fit_text(self.text(machine.get("name") or "未命名"), 24) for machine in machines]
        rows = [[str(index), names[index - 1], STATE_LABELS.get(str(machine.get("state", "")), "未知"), self.protection_label(machine, summary)]
                for index, machine in enumerate(machines, 1)]
        for line in table_lines(["编号", "名称", "状态", "本机保活"], rows):
            self.say(line)
        duplicates = [f"{index}={machine['id']}" for index, machine in enumerate(machines, 1) if names.count(names[index - 1]) > 1]
        if duplicates:
            self.say("同名或截断后同名的目标：" + "，".join(duplicates))
        self.say("保活任务由当前机器统一运行，目标机器无需分别安装；表中只显示本机任务状态。")
        if summary.get("reason"):
            self.say(self.text(summary["reason"]))
        unbound = sum(isinstance(target, dict) and target.get("kind") == "ssh" and not target.get("machineId") for target in summary["targets"])
        if unbound:
            self.say(f"另有 {unbound} 个 SSH 目标未明确绑定机器，未猜测它们对应哪台机器。")
        return 0

    def choose_many(self, selectors=None):
        machines = self.list_machines()
        if not machines:
            raise CloudError("没有可访问的机器。")
        if selectors:
            selected = []
            for selector in selectors:
                matches = [machine for machine in machines if selector in (machine["id"], machine.get("name"))]
                if len(matches) != 1:
                    raise CloudError("批量目标必须逐个唯一匹配；同名机器请使用完整机器 ID。")
                if matches[0] not in selected:
                    selected.append(matches[0])
            return selected
        self.overview(machines)
        self.say("可访问列表可能包含组织其他成员的机器；仅处理你明确选择的编号。")
        while True:
            answer = self.ask("选择机器编号，多个用逗号分隔（如 1,2；空行取消）：").strip()
            if answer in {"", "0"}:
                return []
            if re.fullmatch(r"[0-9]+(?:\s*[,，]\s*[0-9]+)*", answer):
                indices = list(dict.fromkeys(int(value) for value in re.split(r"[,，]\s*", answer)))
                if all(1 <= index <= len(machines) for index in indices):
                    return [machines[index - 1] for index in indices]
            self.say("请输入列表中的编号，用逗号分隔；不会自动选择全部机器。")

    def preview_targets(self, label, machines):
        self.say(label + f"，共 {len(machines)} 台，按以下顺序处理：")
        rows = [[str(index), fit_text(self.text(machine.get("name") or "未命名"), 24), machine["id"]]
                for index, machine in enumerate(machines, 1)]
        for line in table_lines(["编号", "名称", "机器 ID"], rows):
            self.say(line)

    def refresh_protection(self, machine):
        if self.heartbeat_manager is None and not (self.config / "heartbeat.json").exists():
            return
        try:
            if self.heartbeat().refresh_observed_targets([machine]):
                self.say("机器已运行；本机保活仍需确认，请刷新总览查看。")
        except Exception:
            self.say("机器已运行；本机保活状态尚未更新，请查看保活状态。")

    def batch(self, action, selectors=None, *, yes=False, wait=120, shutdown_timeout=None):
        if action not in {"start", "pause", "stop"}:
            raise CloudError("批量操作仅支持启动、暂停或停止。")
        if action in {"pause", "stop"}:
            self.say("如果目标包含当前终端所在机器，连接可能中断并使后续机器尚未处理；请将它的编号放在最后。")
        machines = self.choose_many(selectors)
        if not machines:
            self.say("已取消，未提交批量操作。")
            return 0
        label = {"start": "批量启动", "pause": "批量暂停", "stop": "批量停止"}[action]
        self.preview_targets(label, machines)
        if action in {"pause", "stop"}:
            self.say("停止将结束运行中的进程，磁盘文件保留。" if action == "stop" else "暂停会中断所选机器上的服务。")
            if not yes and self.ask("确认对以上机器执行此操作？[y/N]：").strip().lower() not in {"y", "yes"}:
                self.say("已取消，未提交批量操作。")
                return 0
        counts = {"completed": 0, "skipped": 0, "failed": 0, "unconfirmed": 0}
        labels = {"completed": "完成", "skipped": "跳过", "failed": "失败", "unconfirmed": "未确认"}
        try:
            for machine in machines:
                self.last_lifecycle_result = "failed"
                self.say(f"正在处理：{self.text(machine.get('name') or '未命名')} ({machine['id']})")
                try:
                    current = self.machine_info(machine["id"])
                    self.lifecycle(action, current, yes=True, wait=wait, shutdown_timeout=shutdown_timeout, batch=True)
                except (CloudError, OSError) as error:
                    # A preflight failure does not erase a previous unknown request.
                    try:
                        if self.read_record(machine["id"]).get("state") in PENDING:
                            self.last_lifecycle_result = "unconfirmed"
                    except (CloudError, OSError):
                        self.last_lifecycle_result = "unconfirmed"
                    self.say((self.text(error) if isinstance(error, CloudError) else "本机记录操作失败；原始错误已隐藏。"))
                counts[self.last_lifecycle_result] += 1
                self.say(f"[{labels[self.last_lifecycle_result]}] {self.text(machine.get('name') or '未命名')}")
        except KeyboardInterrupt:
            self.say("批次已中断；后续机器未继续处理，已经发出的请求需查询操作进度。")
            raise
        self.say("批量结果：" + " · ".join(f"{labels[key]} {value} 台" for key, value in counts.items()))
        return 3 if counts["unconfirmed"] else 1 if counts["failed"] else 0

    def protect(self, enabled, selectors=None, *, yes=False):
        machines = self.choose_many(selectors)
        if not machines:
            self.say("已取消，未修改本机保活。")
            return 0
        self.preview_targets("开启本机保活" if enabled else "关闭本机保活", machines)
        self.say("本次只修改本机的 API 保活任务；开启保活不会开机，关闭保活不会关机。")
        if not enabled and not yes and self.ask("确认关闭以上机器在本机的保活？[y/N]：").strip().lower() not in {"y", "yes"}:
            self.say("已取消，未修改本机保活。")
            return 0
        if not enabled:
            selected = {machine["id"] for machine in machines}
            summary = self.protection_summary()
            ssh = [target for target in summary["targets"] if isinstance(target, dict) and target.get("kind") == "ssh" and target.get("machineId") in selected]
            if ssh:
                self.say("所选机器还绑定了 SSH 探测；本次仅关闭平台保活，SSH 探测与凭据仍保留，可在保活菜单另行移除。")
        try:
            result = self.heartbeat().set_api_targets(machines, enabled=enabled)
        except (KeyboardInterrupt, EOFError):
            raise
        except Exception as error:
            raise CloudError(self.heartbeat_error(error, "本机保活设置未确认完成；请刷新总览或查看保活状态，未显示原始错误。")) from None
        return result if type(result) is int and result in {0, 2} else 2

    def select_target(self, target=None, *, choose=False):
        machines = self.list_machines()
        if not machines:
            raise CloudError("没有可访问的机器。")
        previous = read_private(self.config / "machine.json")
        selected = None
        if target:
            matches = [m for m in machines if m["id"] == target or m.get("name") == target]
            if len(matches) != 1:
                raise CloudError("未找到唯一的目标机器；同名机器请使用完整机器 ID。")
            selected = matches[0]
        elif not choose and previous.get("sandboxId"):
            selected = next((m for m in machines if m["id"] == previous["sandboxId"]), None)
            if selected is None:
                raise CloudError("之前选定的机器已不在可访问列表中；请用 ibt cloud select 重新选择。")
        elif len(machines) == 1 and not choose:
            selected = machines[0]
        if selected is None:
            self.show_list(machines)
            while selected is None:
                answer = self.ask("选择机器序号 [0 返回]：").strip()
                if answer in {"", "0"}:
                    return None
                if answer.isascii() and answer.isdigit() and 1 <= int(answer) <= len(machines):
                    selected = machines[int(answer) - 1]
                else:
                    self.say("请输入列表内的序号。")
        if previous.get("sandboxId") != selected["id"]:
            cache = self.config / "keepalive-state.json"
            check_path(cache)
            if cache.exists():
                cache.unlink()
            atomic_private(self.config / "machine.json", {"sandboxId": selected["id"], "name": self.text(selected.get("name", ""))})
        return selected

    def machine_info(self, machine_id):
        machine = self.api.get("/v1/machines/" + urllib.parse.quote(machine_id, safe=""))
        if machine.get("id") != machine_id:
            raise CloudError("平台机器详情与所选目标不符。")
        return machine

    def show_info(self, machine):
        spec = machine.get("spec") if isinstance(machine.get("spec"), dict) else {}
        runtime = machine.get("runtime") if isinstance(machine.get("runtime"), dict) else {}
        state = str(machine.get("state", ""))
        self.say(f"机器名称： {self.text(machine.get('name', '未知'))}")
        self.say(f"机器标识： {self.text(machine.get('id', '未知'))}")
        self.say(f"运行状态： {STATE_LABELS.get(state, '未知')} ({state if state in STATE_LABELS else 'unknown'})")
        self.say(f"运行就绪： {boolean(runtime.get('ready'))}")
        self.say(f"计算资源： CPU {number(spec.get('vcpus'))} 核 · 内存 {number(spec.get('memMiB'))} MiB")
        self.say(f"磁盘资源： 数据盘 {number(spec.get('persistentDiskGiB'))} GiB · 系统盘 {number(spec.get('rootDiskGiB'))} GiB")
        idle = machine.get("autoSuspendAfterSeconds", "missing")
        idle_text = "关闭" if idle is None or (type(idle) is int and idle == 0) else number(idle) + " 秒"
        self.say(f"免费机器： {boolean(machine.get('free'))}")
        self.say(f"空闲暂停： {idle_text}")
        timeout = timestamp(machine.get("timeoutAt"), "未设置" if "timeoutAt" in machine else "未知")
        on_timeout = {"pause": "暂停", "kill": "删除"}.get(str(machine.get("onTimeout", "")), "未知")
        self.say(f"运行期限： {timeout} · 到期动作：{on_timeout}")
        self.say(f"停止期限： {timestamp(machine.get('archiveAt'), '未设置')}")
        self.say(f"空闲记录： {timestamp(machine.get('autoSuspendedAt'), '无记录')}")
        operation_id = machine.get("operationId")
        self.say("当前操作： " + (self.text(operation_id) if isinstance(operation_id, str) and OPERATION_ID.fullmatch(operation_id) else "无" if operation_id is None and "operationId" in machine else "未知"))
        if runtime.get("processesPreserved") is False:
            self.say("最近一次启动/恢复未保留原进程，平台进行了冷启动；文件保留。")

    def account(self):
        me = self.api.get("/v1/me")
        self.say("个人账号的运行与空闲规则：")
        self.say(f"自主调整： {boolean(me.get('manualLifecycle'))}（空闲规则与运行期限）")
        self.say(f"允许常开： {boolean(me.get('alwaysOnAllowed'))}（关闭空闲暂停）")
        self.say(f"固定空闲： {number(me.get('fixedAutoSuspendSeconds'))} 秒")
        choices = me.get("idleChoicesSeconds")
        rendered = ", ".join(str(v) for v in choices) if isinstance(choices, list) and len(choices) <= 100 and all(type(v) is int and v >= 0 for v in choices) else "未知"
        self.say(f"可选空闲： {rendered} 秒")
        self.say(f"期限上限： {number(me.get('maxTimeoutSeconds'))} 秒（可设置的运行期限上限，非机器强制寿命）")
        usage = self.api.get("/v1/usage")
        limits = usage.get("limits") if isinstance(usage.get("limits"), dict) else {}
        self.say("")
        self.say("个人组织用量/配额（其他组织的配额不包含在这里）：")
        self.say(f"机器配额： {number(usage.get('machines'))} / {number(limits.get('maxMachines'))}")
        self.say(f"快照配额： {number(usage.get('snapshots'))} / {number(limits.get('maxSnapshots'))}")
        self.say(f"已用存储： {number(usage.get('storedBytes'))} bytes")
        self.say(f"存储上限： {number(limits.get('maxStoredGiB'))} GiB")
        self.say(f"统计时间： {timestamp(usage.get('computedAt'))}（平台约每小时统计）")

    def record_path(self, machine_id):
        if not MACHINE_ID.fullmatch(machine_id):
            raise CloudError("无效的机器 ID。")
        return self.config / "cloud-requests" / (machine_id + ".json")

    def save_record(self, record):
        record["updatedAt"] = utc_now()
        atomic_private(self.record_path(record["machineId"]), record)

    def read_record(self, machine_id):
        record = read_private(self.record_path(machine_id))
        if not record:
            return {}
        action, state = record.get("action"), record.get("state")
        op_id, body = record.get("operationId"), record.get("body")
        valid_body = body is None or (action == "stop" and isinstance(body, dict)
                                     and set(body) == {"timeoutSeconds"}
                                     and type(body["timeoutSeconds"]) is int
                                     and 0 <= body["timeoutSeconds"] <= 600)
        if (record.get("schema") != 1 or record.get("machineId") != machine_id
                or not isinstance(action, str) or action not in ACTIONS
                or not isinstance(state, str) or state not in PENDING | {"succeeded", "failed", "rejected"}
                or not re.fullmatch(r"(?:ib|isb)-cloud-[a-f0-9]{32}", str(record.get("idempotencyKey", "")))
                or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("authFingerprint", "")))
                or not isinstance(record.get("createdAt"), str) or not valid_body
                or (op_id is not None and (not isinstance(op_id, str) or not OPERATION_ID.fullmatch(op_id)))
                or (state in OP_STATES and not op_id)):
            raise CloudError("本机云端请求记录损坏；为避免重复动作，已停止提交。请先核查云端状态。")
        return record

    def show_operation(self, operation):
        labels = {"queued": "已受理，等待执行", "running": "执行中", "succeeded": "已成功完成", "failed": "已失败"}
        phase = self.text(operation.get("phase", "未知"))
        self.say(f"操作标识： {self.text(operation['id'])}")
        self.say(f"操作状态： {labels[operation['state']]}")
        self.say(f"当前阶段： {phase}")

    def validate_operation(self, operation, operation_id=None, machine_id=None, action=None):
        op_id = operation.get("id")
        state = operation.get("state")
        if not isinstance(op_id, str) or not OPERATION_ID.fullmatch(op_id) or not isinstance(state, str) or state not in OP_STATES:
            raise APIError()
        if operation_id and op_id != operation_id:
            raise APIError()
        if machine_id and operation.get("machineId") != machine_id:
            raise APIError()
        if action and (not isinstance(action, str) or action not in ACTIONS or operation.get("type") != ACTIONS[action]):
            raise APIError()

    def watch_operation(self, operation, *, record=None, wait=120, refresh=False):
        self.last_lifecycle_result = "unconfirmed"
        self.validate_operation(operation, operation_id=record.get("operationId") if record else None,
                                machine_id=record.get("machineId") if record else None,
                                action=record.get("action") if record else None)
        op_id = operation["id"]
        deadline = self.clock() + wait
        last = None
        while True:
            self.validate_operation(operation, op_id, record.get("machineId") if record else None, record.get("action") if record else None)
            state = operation["state"]
            if record:
                record.update(operationId=op_id, state=state)
                self.save_record(record)
            marker = (state, self.text(operation.get("phase", "未知")))
            if marker != last:
                self.show_operation(operation)
                last = marker
            if state == "failed":
                error = operation.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                self.say("[失败] 云端操作失败" + (f"（{code}）" if isinstance(code, str) and code in ERROR_CODES else "；原始错误内容已隐藏") + "。")
                self.last_lifecycle_result = "failed"
                return 1
            if state == "succeeded":
                machine_id = operation.get("machineId")
                if not isinstance(machine_id, str) or not MACHINE_ID.fullmatch(machine_id):
                    self.say("操作已完成，但无法确认机器当前状态。")
                    return 3
                try:
                    machine = self.machine_info(machine_id)
                except CloudError as exc:
                    self.say("操作已完成；机器当前状态未确认：" + self.text(exc))
                    return 3
                self.show_info(machine)
                if record and machine.get("state") != EXPECTED[record["action"]]:
                    self.say("操作已成功结束，但机器当前状态与该动作的目标不同；可能已有后续操作，请核查。")
                    return 3
                if refresh and record and record.get("action") in {"start", "resume"}:
                    self.refresh_protection(machine)
                self.last_lifecycle_result = "completed"
                return 0
            remaining = deadline - self.clock()
            if remaining <= 0:
                self.say(f"[待确认] 等待期限已到，操作仍未完成：{op_id}。稍后运行 ibt cloud operation {op_id}。")
                return 3
            started = self.clock()
            seconds = min(25, remaining)
            duration = str(max(1, int(seconds * 1000))) + "ms"
            try:
                operation = self.api.get(f"/v1/operations/{op_id}?" + urllib.parse.urlencode({"wait": duration}), timeout=min(30, remaining))
            except CloudError as exc:
                self.say(f"[待确认] {self.text(exc)} 操作 ID：{op_id}；稍后用 ibt cloud operation 查询。")
                return 3
            # A broken server returning unchanged results immediately must not spin.
            if self.clock() - started < 0.1:
                self.sleep(min(0.2, max(0, deadline - self.clock())))

    def lifecycle(self, action, machine, *, yes=False, wait=120, shutdown_timeout=None, batch=False):
        self.last_lifecycle_result = "failed"
        machine_id = machine["id"]
        body = {"timeoutSeconds": shutdown_timeout} if action == "stop" and shutdown_timeout is not None else None
        path = self.record_path(machine_id)
        with request_lock(path.with_suffix(".lock")):
            record = self.read_record(machine_id)
            auth = hashlib.sha256(self.api.key.encode("ascii")).hexdigest()
            retry = isinstance(record.get("state"), str) and record["state"] in PENDING
            if retry:
                self.last_lifecycle_result = "unconfirmed"
                if record.get("machineId") != machine_id or record.get("action") != action or record.get("body") != body:
                    raise CloudError("这台机器还有未确认的请求；先查询 operation，或原样重复原命令，不可用新请求覆盖。")
                if record.get("authFingerprint") != auth:
                    raise CloudError("当前授权与未确认请求不同；先用 operation 查询已有操作，避免重复提交。")
                if record.get("operationId"):
                    op_id = record["operationId"]
                    if not isinstance(op_id, str) or not OPERATION_ID.fullmatch(op_id):
                        raise CloudError("本机请求记录中的操作 ID 无效。")
                    operation = self.api.get("/v1/operations/" + op_id)
                    return self.watch_operation(operation, record=record, wait=wait, refresh=True)
                try:
                    created = dt.datetime.fromisoformat(record["createdAt"])
                    elapsed = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
                    expired = elapsed >= 7 * 86400 or elapsed < -60
                except (KeyError, TypeError, ValueError):
                    expired = True
                if expired:
                    raise CloudError("未确认请求已超出平台 7 天幂等窗口或记录时间无效；请先核查云端状态，不能自动重发。")
                if not re.fullmatch(r"(?:ib|isb)-cloud-[a-f0-9]{32}", str(record.get("idempotencyKey", ""))):
                    raise CloudError("本机幂等请求记录无效，已停止。")
                self.say("沿用已保存的同一请求与幂等键，确认上次提交结果。")
            else:
                state = str(machine.get("state", ""))
                if state == EXPECTED[action]:
                    self.say("机器已处于所需状态，未提交新的生命周期动作。")
                    if action in {"start", "resume"}:
                        self.refresh_protection(machine)
                    self.last_lifecycle_result = "skipped"
                    return 0
                allowed = {"start": {"stopped", "suspended"}, "resume": {"suspended"}, "pause": {"running"}, "stop": {"running"}}
                if state not in allowed[action]:
                    if batch and action == "stop" and state == "suspended":
                        self.say("此机器已暂停，停止操作不适用；未自动启动它。")
                        self.last_lifecycle_result = "skipped"
                        return 0
                    hint = "已停止的机器请使用 start。" if action == "resume" and state == "stopped" else "暂停中的机器不能直接 stop；请先决定是否使用 start。" if action == "stop" and state == "suspended" else "请先查看 info 或 operation。"
                    raise CloudError("当前机器状态不适合此动作。" + hint)
                if action in {"pause", "stop"} and not yes:
                    consequence = "停止将结束运行中的进程，文件保留" if action == "stop" else "暂停将中断服务可用性，平台保存运行状态"
                    self.say(consequence + "。")
                    answer = self.ask(f"确认{('停止' if action == 'stop' else '暂停')} {self.text(machine.get('name', '未知'))} ({machine_id})？[y/N]：")
                    if answer.strip().lower() not in {"y", "yes"}:
                        self.say("已取消，未发送生命周期请求。")
                        return 0
                record = {"schema": 1, "machineId": machine_id, "action": action, "body": body,
                          "idempotencyKey": "ib-cloud-" + uuid.uuid4().hex, "authFingerprint": auth,
                          "createdAt": utc_now(), "state": "prepared", "operationId": None}
                # Must be durable before POST: a lost response may already have changed the VM.
                self.save_record(record)
            self.last_lifecycle_result = "unconfirmed"
            try:
                status, operation = self.api.request("POST", f"/v1/machines/{machine_id}/{ACTIONS[action]}", body, idempotency_key=record["idempotencyKey"])
                if status != 202:
                    raise APIError()
                self.validate_operation(operation, machine_id=machine_id, action=action)
            except APIError as exc:
                # A new rejection cannot disprove an earlier lost response.
                record["state"] = "unknown" if retry or exc.uncertain else "rejected"
                self.last_lifecycle_result = "unconfirmed" if retry or exc.uncertain else "failed"
                self.save_record(record)
                if retry or exc.uncertain:
                    self.say("[待确认] 提交结果未知；请求记录已保留，原样重试会复用同一幂等键。")
                raise
            record.update(operationId=operation["id"], state=operation["state"])
            self.save_record(record)
            self.say(f"[已受理] {operation['id']}；HTTP 202 仅表示受理，正在确认执行结果。")
            return self.watch_operation(operation, record=record, wait=wait, refresh=True)

    def wake(self, machine):
        try:
            status, current = self.api.request("POST", f"/v1/machines/{machine['id']}/wake", timeout=60)
        except APIError as exc:
            if exc.status == 409:
                self.say("wake 未完成：不会改用 resume/start，也不会覆盖手动暂停、停止、到期或 archive 策略。")
            raise
        if status != 200 or current.get("id") != machine["id"] or current.get("state") != "running":
            raise CloudError("wake 返回结果未确认机器处于运行状态；未执行额外恢复操作。")
        self.say("wake 已确认机器运行；此请求仅按平台规则恢复空闲暂停或记录活动。")
        self.show_info(current)
        return 0

    def operation(self, operation_id=None, *, wait=120, choose=False):
        expected_machine_id = None
        if operation_id:
            if not OPERATION_ID.fullmatch(operation_id):
                raise CloudError("操作 ID 格式不正确。")
        else:
            target = self.select_target(choose=choose)
            if target is None:
                return 0
            expected_machine_id = target["id"]
            machine = self.machine_info(target["id"])
            candidate = self.read_record(target["id"])
            operation_id = candidate.get("operationId") or machine.get("operationId")
            if not operation_id:
                self.say("尚未取得操作 ID，请原样重复上次命令以确认提交结果。" if candidate.get("state") in PENDING else "所选机器没有可查询的操作记录。")
                return 3 if candidate.get("state") in PENDING else 0
            if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
                raise CloudError("操作 ID 格式不正确。")
        operation = self.api.get("/v1/operations/" + operation_id)
        self.validate_operation(operation, operation_id=operation_id, machine_id=expected_machine_id)
        machine_id = operation.get("machineId")
        if isinstance(machine_id, str) and MACHINE_ID.fullmatch(machine_id):
            with request_lock(self.record_path(machine_id).with_suffix(".lock")):
                candidate = self.read_record(machine_id)
                if candidate.get("operationId") == operation_id:
                    # A lifecycle command may have finished or replaced the journal
                    # while the first GET was in flight. Refresh under the same lock.
                    operation = self.api.get("/v1/operations/" + operation_id)
                    self.validate_operation(operation, operation_id=operation_id)
                    return self.watch_operation(operation, record=candidate, wait=wait)
        return self.watch_operation(operation, wait=wait)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal error echoes supplied values, which can be credentials.
        self.exit(2, "参数无效；运行 ibt cloud --help 查看用法。\n")


def parser():
    result = Parser(description="InstaBox Tool 机器总览与管理；总览、详情和账户查询不会唤醒机器。")
    result.set_defaults(command="overview")
    commands = result.add_subparsers(dest="command", parser_class=Parser)
    commands.add_parser("overview", help="一屏查看全部机器及当前控制器的保活状态")
    for name, help_text in [("info", "查看目标机器及策略"), ("status", "info 的别名"), ("select", "选择一台管理目标"), ("wake", "按需唤醒空闲暂停，最多等待45秒；不覆盖手动停止或到期策略")]:
        child = commands.add_parser(name, help=help_text, description=help_text)
        child.add_argument("target", nargs="?", help="完整机器 ID 或唯一机器名；省略使用已选目标")
        if name in {"info", "status"}:
            child.add_argument("--choose", action="store_true", help="重新从列表选择一台机器，不沿用上次目标")
    commands.add_parser("list", help="列出全部可访问机器，仅展示，不批量操作")
    commands.add_parser("account", help="查看个人账号策略与用量，隐藏身份信息")
    for name, description in [("start", "启动已停止或已暂停的机器；恢复进程失败时可能冷启动"), ("pause", "暂停运行中的机器，服务会中断"), ("resume", "恢复已暂停的机器；已停止机器请用 start"), ("stop", "关闭运行中的机器；进程结束，文件保留")]:
        child = commands.add_parser(name, help=description, description=description)
        child.add_argument("target", nargs="?", help="完整机器 ID 或唯一机器名；省略使用已选目标")
        child.add_argument("--wait", type=int, default=120, metavar="秒", help="等待异步操作的总时长，0–600秒，默认120；0仅提交")
        if name in {"pause", "stop"}:
            child.add_argument("--yes", action="store_true", help="明确确认对目标的暂停/停止，供无人值守自动化；否则交互确认")
        if name == "stop":
            child.add_argument("--shutdown-timeout", type=int, metavar="秒", help="等待正常关机0–600秒，省略用平台默认60；这是关机等待，不是机器寿命")
    operation = commands.add_parser("operation", help="查询异步操作；省略ID时查询所选机器")
    operation.add_argument("operation_id", nargs="?")
    operation.add_argument("--wait", type=int, default=120, metavar="秒", help="总等待0–600秒，默认120；0不继续轮询")
    operations = commands.add_parser("operations", help="从机器列表选一台，查询它的操作进度")
    operations.add_argument("--wait", type=int, default=120, metavar="秒", help="总等待0–600秒，默认120")
    batch = commands.add_parser("batch", help="明确多选后逐台启动、暂停或停止")
    batch.add_argument("action", choices=["start", "pause", "stop"])
    batch.add_argument("targets", nargs="*", help="可选：逐个指定完整机器 ID 或唯一名称；省略则按编号多选")
    batch.add_argument("--yes", action="store_true", help="明确确认所选机器的暂停/停止，跳过一次总确认")
    batch.add_argument("--wait", type=int, default=120, metavar="秒", help="每台操作的等待上限0–600秒，默认120")
    batch.add_argument("--shutdown-timeout", type=int, metavar="秒", help="仅stop适用：优雅关机等待0–600秒")
    protect = commands.add_parser("protect", help="为明确选择的机器开启或关闭当前控制器的保活")
    protect.add_argument("mode", choices=["on", "off"])
    protect.add_argument("targets", nargs="*", help="可选机器 ID 或唯一名称；省略则按编号多选")
    protect.add_argument("--yes", action="store_true", help="明确确认所选机器关闭本机保活，跳过总确认")
    key = commands.add_parser("key", help="设置、查看或清除本机共享 API 授权；无需 SDK")
    key.add_argument("key_action", choices=["set", "status", "forget", "ensure"], nargs="?", default="status")
    return result


def key_file_info(config):
    """Inspect metadata only; status/forget never need to read the secret."""
    path = config / "api-key"
    check_path(path)
    if config.exists():
        info = config.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise CloudError("本机授权目录不属于当前用户，已拒绝访问。")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise CloudError("本机授权目录权限必须为 700，请先修正目录权限。")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise CloudError("无法检查本机授权文件。") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise CloudError("本机授权必须是当前用户独有的普通文件。")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise CloudError("本机授权文件权限必须为 600，请先修正文件权限。")
        return info
    finally:
        os.close(fd)


def prompt_api_key():
    """getpass reads the controlling TTY even when the installer uses a pipe."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            key = getpass.getpass("  InstaBox API Key（输入不回显）：").strip()
        except getpass.GetPassWarning:
            raise CloudError("当前终端无法关闭输入回显，未读取授权；请在 SSH 终端运行，或设置 INSTABOX_API_KEY。") from None
        except (EOFError, OSError):
            raise CloudError("未读取到 API Key；请在 SSH 终端粘贴，或设置 INSTABOX_API_KEY。") from None
    return key


def ensure_api(config):
    """Require a usable account and machine-list access before first install.

    Only read-only requests run here. The initial activity lease separately
    confirms write access. A verified environment key is persisted because the
    systemd user timer will not inherit the current shell's environment.
    """
    config = Path(config)
    key_file_info(config)
    saved = read_private(config / "api-key", json_data=False)
    key = os.environ.get("INSTABOX_API_KEY", "").strip() or saved
    if not key:
        console_line("首次安装需要 InstaBox API Key，用于识别本机并自动配置保活。")
        console_line("创建入口：https://dashboard.instabox.sh/ → API Keys → Create Key")
        console_line("选择 Restricted 时请授予 machines:write（含读取权限）；粘贴时不显示字符。")
        key = prompt_api_key()
    if not re.fullmatch(r"ibk_[A-Za-z0-9_-]{1,4092}", key):
        raise CloudError("API Key 格式无效，应为 ibk_ 开头的完整密钥；安装尚未继续。")
    api = API(key)
    me = api.get("/v1/me")
    if any(field in me and type(me[field]) is not bool for field in ("inviteRequired", "activated")):
        raise CloudError("平台账号资格响应格式异常；安装尚未继续。")
    if me.get("inviteRequired") is True and me.get("activated") is not True:
        raise CloudError("当前账号尚未通过平台开通要求；请先在 Dashboard 按提示激活，再重新安装。")
    Cloud(api, config).list_machines()
    if saved != key:
        atomic_private(config / "api-key", key + "\n")
        console_line("账户授权： 已验证并保存，自动保活将复用此授权。")
    return api


def prompt_and_save_api(config):
    key_file_info(config)
    console_line("一次输入，云端管理、API 保活和 SSH token 自动换新共用；SSH/Mosh 命令仍可独立使用。")
    key = prompt_api_key()
    api = API(key)
    api.get("/v1/me")
    atomic_private(config / "api-key", key + "\n")
    console_line("共享授权已验证并保存在本机；后续无需为每台机器重复输入。")
    return api


def manage_key(config, action):
    if action == "ensure":
        ensure_api(config)
        return 0
    if action == "set":
        prompt_and_save_api(config)
        return 0
    info = key_file_info(config)
    if action == "status":
        console_line("共享授权： 已保存在本机（仅检查缓存和权限，未联网验证有效性）。" if info and info.st_size else "共享授权： 尚未保存在本机。")
        return 0
    if info:
        path = config / "api-key"
        check_path(path)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise CloudError("授权文件刚被其他操作修改，未删除；请重试。")
        path.unlink()
    console_line("本机缓存授权已清除；云端授权未撤销，SSH/Mosh 连接命令未修改。")
    if os.environ.get("INSTABOX_API_KEY"):
        console_line("当前会话另有环境授权，未修改该环境变量。")
    return 0


def load_api(config):
    key = os.environ.get("INSTABOX_API_KEY", "") or read_private(config / "api-key", json_data=False)
    if key:
        return API(key)
    return prompt_and_save_api(config)


def main(argv=None):
    args = parser().parse_args(argv)
    if not 0 <= getattr(args, "wait", 120) <= 600 or (getattr(args, "shutdown_timeout", None) is not None and not 0 <= args.shutdown_timeout <= 600):
        raise CloudError("等待时间须在 0–600 秒范围内。")
    if args.command == "batch" and args.action != "stop" and args.shutdown_timeout is not None:
        raise CloudError("关机等待参数仅适用于 batch stop。")
    config = Path.home() / ".config" / "insta-box"
    if args.command == "key":
        return manage_key(config, args.key_action)
    cloud = Cloud(load_api(config), config)
    if args.command in {None, "overview"}:
        return cloud.overview()
    if args.command == "list":
        cloud.show_list()
        return 0
    if args.command == "account":
        cloud.account()
        return 0
    if args.command == "operation":
        return cloud.operation(args.operation_id, wait=args.wait)
    if args.command == "operations":
        return cloud.operation(wait=args.wait, choose=True)
    if args.command == "batch":
        return cloud.batch(args.action, args.targets, yes=args.yes, wait=args.wait, shutdown_timeout=args.shutdown_timeout)
    if args.command == "protect":
        return cloud.protect(args.mode == "on", args.targets, yes=args.yes)
    target = cloud.select_target(args.target, choose=args.command == "select" or getattr(args, "choose", False))
    if target is None:
        return 0
    if args.command == "select":
        cloud.say(f"已选择：{cloud.text(target.get('name', '未知'))} ({target['id']})")
        return 0
    current = cloud.machine_info(target["id"])
    if args.command in {"info", "status"}:
        cloud.show_info(current)
        op_id = current.get("operationId")
        if isinstance(op_id, str) and OPERATION_ID.fullmatch(op_id):
            operation = cloud.api.get("/v1/operations/" + op_id)
            cloud.validate_operation(operation, operation_id=op_id, machine_id=current["id"])
            cloud.show_operation(operation)
        return 0
    if args.command == "wake":
        return cloud.wake(current)
    return cloud.lifecycle(args.command, current, yes=getattr(args, "yes", False), wait=args.wait, shutdown_timeout=getattr(args, "shutdown_timeout", None))


def entrypoint(argv=None):
    try:
        return main(argv)
    except (CloudError, OSError) as exc:
        message = clean(exc, os.environ.get("INSTABOX_API_KEY", "")) if isinstance(exc, CloudError) else "本机文件操作失败；未显示底层路径或原始错误。"
        print("  [失败] " + message, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("  已取消；已发出的请求可能仍在执行，请用 operation 查询。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(entrypoint())
