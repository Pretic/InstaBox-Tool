#!/usr/bin/env python3
# Author: Pre
"""Conservative, reversible host tuning for InstaBox Tool (stdlib only).

No downloads, kernel replacement, interface qdisc replacement, or foreign swap
management. See kernel ip-sysctl/default_qdisc docs and util-linux swapon(8).
All persisted recovery instructions use a fixed asset/key allowlist.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import fcntl
import fnmatch
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


MIB = 1024 * 1024
BASE = "/var/lib/insta-box-tool"
SWAP = BASE + "/swapfile"
MARKER = "# Managed-by: InstaBox Tool machine optimization"
BLOCK = "# BEGIN InstaBox Tool swap\n" + SWAP + " none swap sw,nofail 0 0\n# END InstaBox Tool swap\n"
KEYS = ("net.core.default_qdisc", "net.ipv4.tcp_congestion_control")
DESIRED = dict(zip(KEYS, ("fq", "bbr")))
BBR_TEXT = MARKER + "\n" + "".join(key + " = " + DESIRED[key] + "\n" for key in KEYS)
ASSETS = {"state": BASE + "/state.json", "journal": BASE + "/transaction.json",
          "lock": BASE + "/lock", "swap": SWAP, "fstab": "/etc/fstab",
          "bbr": "/etc/sysctl.d/90-insta-box-tool-bbr.conf"}
TOOLS = {"sysctl": "/usr/sbin/sysctl", "mkswap": "/usr/sbin/mkswap",
         "swapon": "/usr/sbin/swapon", "swapoff": "/usr/sbin/swapoff",
         "modprobe": "/usr/sbin/modprobe", "findmnt": "/usr/bin/findmnt",
         "tc": "/usr/sbin/tc", "virt": "/usr/bin/systemd-detect-virt"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
COMMANDS = ("status", "recommend", "apply", "swap-on", "swap-off", "bbr-on", "bbr-off", "restore")
UNSET = object()


class OptError(Exception):
    """Only locally composed messages; never raw subprocess output."""


def say(message=""):
    print("  " + message if message else "")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,32}", value) and not value.startswith(("ibk_", "ibssh_"))


def size_mib(value):
    if type(value) is not int or not 256 <= value <= 8192:
        raise OptError("Swap 大小应为 256–8192 MiB 的整数。")
    return value


def reserve_bytes(total):
    return max(2048 * MIB, (total + 9) // 10)


def suggested_swap(facts):
    """A small optional buffer, not an assertion of an optimal RAM/swap ratio."""
    if facts["swaps"]:
        return 0
    ram = facts["ram"]
    desired = 1024 if ram <= 2 * 1024 * MIB else 2048 if ram <= 8 * 1024 * MIB else 4096
    budget = max(0, facts["free"] - reserve_bytes(facts["disk"])) // MIB
    return min(desired, budget // 256 * 256)


def allocate_filled(fd, length):
    """Write every byte. fallocate/truncate alone can leave unusable extents."""
    chunk = b"\0" * MIB
    remaining = length
    while remaining:
        view = memoryview(chunk)[:min(remaining, len(chunk))]
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OptError("Swap 文件分配未完成。")
            remaining -= written
            view = view[written:]
    os.fsync(fd)
    info = os.fstat(fd)
    if info.st_size != length or info.st_blocks * 512 < length:
        raise OptError("Swap 文件未完整分配，未启用。")


class Host:
    """Injectable OS boundary. Production always uses root=/ and owner=0."""
    def __init__(self, root="/", *, runner=None, owner=0, allocator=None, disk=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.owner = owner
        self.allocator = allocator or allocate_filled
        self.disk = disk

    def path(self, absolute):
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise OptError("内部路径不在允许范围。")
        return self.root / absolute.lstrip("/")

    def asset(self, name):
        if name not in ASSETS:
            raise OptError("恢复记录包含未知资源。")
        return self.path(ASSETS[name])

    def parents(self, path):
        relative = path.relative_to(self.root)
        current = self.root
        for part in (None, *relative.parts[:-1]):
            if part is not None:
                current = current / part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or stat.S_IMODE(info.st_mode) & 0o022:
                raise OptError("系统目录归属、类型或写入权限异常，未修改。")

    def info(self, name, *, missing=True):
        path = self.asset(name)
        try:
            self.parents(path)
        except FileNotFoundError:
            if missing:
                return None
            raise OptError("所需系统目录不存在。") from None
        try:
            info = path.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise OptError("所需系统文件不存在。") from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
            raise OptError("受管文件的类型、归属或链接数异常，未修改。")
        if name in {"state", "journal", "lock", "swap"} and stat.S_IMODE(info.st_mode) != 0o600:
            raise OptError("本工具私有文件权限应为 600，未自动接管。")
        return info

    def read(self, name):
        info = self.info(name)
        if info is None:
            return None
        fd = os.open(self.asset(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino, actual.st_nlink, actual.st_uid, actual.st_mode) != (info.st_dev, info.st_ino, 1, info.st_uid, info.st_mode):
                raise OptError("系统文件刚发生变化，请重试。")
            data = os.read(fd, 1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise OptError("受管配置超出大小限制。")
            return data.decode("utf-8")
        except UnicodeError:
            raise OptError("受管配置不是有效文本，未修改。") from None
        finally:
            os.close(fd)

    def write(self, name, data, *, expected=UNSET):
        if name not in {"state", "journal", "bbr", "fstab"}:
            raise OptError("不允许写入此资源。")
        old = self.read(name)
        if expected is not UNSET and old != expected:
            raise OptError("配置已被其它操作修改，未覆盖。")
        if data == old:
            return
        path = self.asset(name)
        if data is None:
            if old is not None:
                self.info(name, missing=False)
                if self.read(name) != old:
                    raise OptError("配置刚发生变化，未删除。")
                path.unlink()
                self.sync_directory(path.parent)
            return
        mode = 0o600 if name in {"state", "journal"} else (stat.S_IMODE(self.info(name).st_mode) if old is not None else 0o644)
        temporary = path.parent / ("." + path.name + ".ibt-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if self.read(name) != old:
                raise OptError("配置刚发生变化，未覆盖。")
            os.replace(temporary, path)
            self.sync_directory(path.parent)
        finally:
            if fd is not None:
                os.close(fd)
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def ensure_base(self):
        directory = self.path(BASE)
        self.parents(directory)
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o700:
            raise OptError("本工具系统目录必须为管理员所有的 700 普通目录。")

    def publish_swap(self, fd):
        """Publish an already journaled anonymous inode, without replacing a path."""
        directory = os.open(self.path(BASE), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o700:
                raise OptError("Swap 系统目录刚发生变化，未发布文件。")
            libc = ctypes.CDLL(None, use_errno=True)
            linkat = libc.linkat
            linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
            linkat.restype = ctypes.c_int
            if linkat(fd, b"", directory, b"swapfile", 0x1000) != 0:  # AT_EMPTY_PATH
                error = ctypes.get_errno()
                if error not in {errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOENT}:
                    raise OptError("Swap 路径出现冲突或无法安全发布，未覆盖。")
                # open(2)'s documented alternative when CAP_DAC_READ_SEARCH is
                # unavailable: link this process's own O_TMPFILE descriptor.
                try:
                    os.link("/proc/self/fd/" + str(fd), "swapfile", dst_dir_fd=directory, follow_symlinks=True)
                except OSError:
                    raise OptError("当前内核或文件系统不支持安全发布 Swap，未启用。") from None
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextlib.contextmanager
    def lock(self):
        self.ensure_base()
        self.info("lock")
        fd = os.open(self.asset("lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise OptError("优化锁文件不安全。")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OptError("另一项机器优化正在执行，请稍后重试。") from None
            yield
        finally:
            os.close(fd)

    def call(self, name, *args, timeout=15):
        try:
            return self.runner([TOOLS[name], *map(str, args)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace", timeout=timeout, env=ENV)
        except (OSError, subprocess.SubprocessError):
            return subprocess.CompletedProcess([], 127, "", "")

    def proc(self, path):
        try:
            with self.path(path).open("r", encoding="utf-8") as stream:
                value = stream.read(1024 * 1024 + 1)
            return value if len(value) <= 1024 * 1024 else ""
        except (OSError, UnicodeError):
            return ""

    def sysctl(self, key):
        if key not in KEYS and key != "net.ipv4.tcp_available_congestion_control":
            raise OptError("系统参数不在允许范围。")
        value = self.proc("/proc/sys/" + key.replace(".", "/")).strip()
        if key.endswith("available_congestion_control"):
            words = value.split()
            return words if len(words) <= 64 and all(identifier(word) for word in words) else []
        return value if identifier(value) else None

    def check_bbr_persistence(self):
        """Read only the two keys that can override our drop-in at boot.

        sysctl.d(5): same basenames use directory precedence, then sort names.
        procps sysctl(8) also reads /etc/sysctl.conf last. Never load all sysctls.
        """
        own_name = Path(ASSETS["bbr"]).name
        selected = {}
        try:
            for logical in ("/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"):
                # Debian's merged-/usr alias is equivalent to the directory
                # already visited; no other directory symlinks are followed.
                if logical == "/lib/sysctl.d":
                    alias = self.path("/lib")
                    if alias.is_symlink() and os.readlink(alias) in ("usr/lib", "/usr/lib"):
                        continue
                directory = self.path(logical)
                try:
                    self.parents(directory)
                    info = directory.lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or stat.S_IMODE(info.st_mode) & 0o022:
                    raise OptError("系统 sysctl 目录不安全，无法确认启动配置，未修改。")
                for name in os.listdir(directory):
                    if name.endswith(".conf"):
                        selected.setdefault(name, logical + "/" + name)
                if len(selected) > 512:
                    raise OptError("系统 sysctl 配置过多，无法确认启动配置，未修改。")
            if own_name in selected and selected[own_name] != ASSETS["bbr"]:
                raise OptError("较低优先级已有同名 sysctl 配置，未创建文件遮蔽它。")
            files = [selected[name] for name in sorted(selected, key=os.fsencode) if os.fsencode(name) > os.fsencode(own_name)]
            files.append("/etc/sysctl.conf")
            values = {}
            keys = {key.replace(".", "/"): key for key in KEYS}
            for logical in files:
                path = self.path(logical)
                self.parents(path)
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    if logical == "/etc/sysctl.conf":
                        continue
                    raise OptError("系统 sysctl 配置刚发生变化，请重试。") from None
                if stat.S_ISLNK(info.st_mode):
                    if info.st_uid != self.owner:
                        raise OptError("系统 sysctl 配置链接归属异常，未修改。")
                    target = os.readlink(path)
                    target = os.path.normpath(target if target.startswith("/") else os.path.join(os.path.dirname(logical), target))
                    if target == "/dev/null":
                        continue
                    if target != "/etc/sysctl.conf" or logical == target:
                        raise OptError("存在无法确认的 sysctl 配置链接，未修改。")
                    path = self.path(target)
                    self.parents(path)
                    try:
                        info = path.lstat()
                    except FileNotFoundError:
                        # A dangling Debian 99-sysctl.conf compatibility link
                        # applies no values; procps also skips the absent file.
                        continue
                if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise OptError("系统 sysctl 配置类型或权限不安全，未修改。")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    actual = os.fstat(fd)
                    if (actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_nlink) != (info.st_dev, info.st_ino, info.st_mode, self.owner, 1):
                        raise OptError("系统 sysctl 配置刚发生变化，请重试。")
                    raw = os.read(fd, 1024 * 1024 + 1)
                finally:
                    os.close(fd)
                if len(raw) > 1024 * 1024:
                    raise OptError("系统 sysctl 配置过大，无法确认启动配置，未修改。")
                for line in raw.decode("utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", ";")):
                        continue
                    field, separator, value = line.partition("=")
                    field = field.strip().removeprefix("-").strip()
                    first_dot, first_slash = field.find("."), field.find("/")
                    if first_dot >= 0 and (first_slash < 0 or first_dot < first_slash):
                        field = field.translate(str.maketrans("./", "/."))
                    matching = [key for path_key, key in keys.items() if fnmatch.fnmatchcase(path_key, field)]
                    if not matching:
                        continue
                    if field not in keys or not separator or not identifier(value.strip()):
                        raise OptError("后序 sysctl 配置含无法确认的网络规则，未修改。")
                    values[keys[field]] = value.strip()
            if any(value != DESIRED[key] for key, value in values.items()):
                raise OptError("后序 sysctl 配置会覆盖 BBR 或 fq；请先手动处理冲突，原文件未修改。")
        except (OSError, UnicodeError):
            raise OptError("无法完整读取后序 sysctl 配置，未承诺持久生效，也未修改。") from None

    def swaps(self):
        raw = self.proc("/proc/swaps")
        if not raw.startswith("Filename"):
            raise OptError("无法读取当前 Swap，未推测其状态。")
        result = []
        for line in raw.splitlines()[1:]:
            values = line.split()
            if len(values) != 5 or not values[2].isdigit() or not values[3].isdigit():
                raise OptError("当前 Swap 列表格式异常。")
            path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), values[0])
            result.append({"path": path, "size": int(values[2]) * 1024, "used": int(values[3]) * 1024})
        return result

    def facts(self):
        memory = {match[1]: int(match[2]) * 1024 for match in re.finditer(r"^(MemTotal|MemAvailable):\s+(\d+) kB$", self.proc("/proc/meminfo"), re.M)}
        if not memory.get("MemTotal") or "MemAvailable" not in memory:
            raise OptError("无法读取内存容量与可用内存。")
        target = self.path(BASE)
        while not target.exists() and target != self.root:
            target = target.parent
        if self.disk:
            total, free = self.disk(target)
        else:
            disk = os.statvfs(target)
            total, free = disk.f_blocks * disk.f_frsize, disk.f_bavail * disk.f_frsize
        fs = self.call("findmnt", "-n", "-o", "FSTYPE", "--target", target)
        fs = fs.stdout.strip() if fs.returncode == 0 else "unknown"
        options = self.call("findmnt", "-n", "-o", "OPTIONS", "--target", target)
        options = options.stdout.strip().split(",") if options.returncode == 0 else []
        virtual = self.call("virt", "--container")
        container = virtual.stdout.strip() if virtual.returncode == 0 else "none" if virtual.returncode == 1 else "unknown"
        if self.path("/.dockerenv").exists() or self.path("/run/.containerenv").exists():
            container = "container"
        caps = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", self.proc("/proc/self/status"), re.M)
        qdiscs = []
        response = self.call("tc", "-j", "qdisc", "show")
        try:
            values = json.loads(response.stdout) if response.returncode == 0 and len(response.stdout) < 65536 else []
            if isinstance(values, list):
                for row in values[:100]:
                    if isinstance(row, dict) and isinstance(row.get("dev"), str) and re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,32}", row["dev"]) and identifier(row.get("kind")):
                        item = row["dev"] + ":" + row["kind"]
                        if item not in qdiscs:
                            qdiscs.append(item)
        except (ValueError, TypeError):
            pass
        available = self.sysctl("net.ipv4.tcp_available_congestion_control")
        module = "bbr" in available or self.call("modprobe", "--dry-run", "--quiet", "tcp_bbr").returncode == 0
        kernel = os.uname().release
        kernel = kernel if re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", kernel) else "未读取"
        return {"ram": memory["MemTotal"], "availableMemory": memory["MemAvailable"], "disk": total,
                "free": free, "fs": fs, "writable": "rw" in options, "container": container,
                "caps": int(caps[1], 16) if caps else 0, "swaps": self.swaps(), "availableCC": available,
                "bbrModule": module, "values": {key: self.sysctl(key) for key in KEYS}, "qdiscs": qdiscs[:8], "kernel": kernel}


class Optimizer:
    def __init__(self, host=None, *, output=None, confirm=None, privileged=None):
        self.host = host or Host()
        self.say = output or say
        self.confirm = confirm or self.terminal_confirm
        self.privileged = os.geteuid() == 0 if privileged is None else privileged

    @staticmethod
    def terminal_confirm():
        try:
            with open("/dev/tty", "r+", encoding="utf-8") as terminal:
                terminal.write("  确认执行以上变更？[y/N]：")
                terminal.flush()
                return terminal.readline().strip().lower() in ("y", "yes")
        except OSError:
            raise OptError("变更需要交互终端确认；自动化请显式提供 --yes。") from None

    def read_json(self, asset):
        try:
            raw = self.host.read(asset)
        except FileNotFoundError:
            return None
        if raw is None:
            return None
        try:
            result = json.loads(raw)
        except ValueError:
            raise OptError("本工具恢复记录损坏，未修改系统。") from None
        if not isinstance(result, dict):
            raise OptError("本工具恢复记录格式异常。")
        return result

    @staticmethod
    def validate_identity(value):
        if not isinstance(value, dict) or set(value) != {"dev", "ino"} or any(type(value[key]) is not int or value[key] < 0 for key in value):
            raise OptError("Swap 归属记录无效。")

    def validate_state(self, state):
        if state is None:
            return
        if not isinstance(state, dict) or set(state) != {"schema", "swap", "bbr"} or type(state["schema"]) is not int or state["schema"] != 1:
            raise OptError("优化记录版本或字段无效。")
        swap = state["swap"]
        if swap is not None:
            if not isinstance(swap, dict) or set(swap) != {"mib", "identity", "block"} or swap["block"] not in (BLOCK, "\n" + BLOCK):
                raise OptError("Swap 恢复记录无效。")
            size_mib(swap["mib"])
            self.validate_identity(swap["identity"])
        bbr = state["bbr"]
        if bbr is not None and (not isinstance(bbr, dict) or set(bbr) != set(KEYS) or not all(identifier(value) for value in bbr.values())):
            raise OptError("网络参数恢复记录无效。")

    def state(self):
        value = self.read_json("state")
        self.validate_state(value)
        return value

    def status(self, facts=None):
        facts = facts or self.host.facts()
        self.say("内核版本： " + facts["kernel"])
        self.say("物理内存： %.2f GiB · 当前可用 %.2f GiB" % (facts["ram"] / MIB / 1024, facts["availableMemory"] / MIB / 1024))
        self.say("交换空间： %.2f GiB · 已用 %.2f GiB" % (sum(row["size"] for row in facts["swaps"]) / MIB / 1024, sum(row["used"] for row in facts["swaps"]) / MIB / 1024))
        self.say("磁盘余量： %.2f GiB · Swap 目录文件系统 %s" % (facts["free"] / MIB / 1024, facts["fs"] if facts["fs"] in {"ext4", "xfs", "btrfs", "overlay", "tmpfs"} else "未确认"))
        self.say("拥塞算法： " + (facts["values"][KEYS[1]] or "未读取") + "（新 TCP 连接默认值）")
        self.say("可用算法： " + (" ".join(facts["availableCC"][:8]) or "未读取") + (" …" if len(facts["availableCC"]) > 8 else ""))
        self.say("默认队列： " + (facts["values"][KEYS[0]] or "未读取"))
        self.say("网卡队列： " + (" · ".join(facts["qdiscs"]) or "未读取；没有替换现有队列"))
        try:
            state = self.state()
            journal = self.read_json("journal")
            label = "存在待完成事务，请先选择恢复" if journal else "已记录本工具变更" if state and (state["swap"] or state["bbr"]) else "没有本工具变更记录"
        except PermissionError:
            label = "私有记录需管理员权限核对，未判定为未管理"
        except (OptError, OSError):
            label = "记录暂不可读取，变更前需检查"
        self.say("本机记录： " + label)
        return 0

    def recommendations(self, facts):
        swap = suggested_swap(facts)
        if facts["swaps"]:
            self.say("交换建议： 保留现有交换空间，不自动叠加或替换。")
            swap = 0
        elif facts["fs"] not in {"ext4", "xfs"} or not facts["writable"] or facts["container"] != "none":
            self.say("交换建议： 当前文件系统、挂载权限或容器环境不适合自动创建。")
            swap = 0
        elif swap < 256:
            self.say("交换建议： 磁盘余量不足，保留至少 2 GiB 或总容量 10% 后无法分配。")
            swap = 0
        else:
            self.say(f"交换建议： 创建 {swap} MiB 缓冲；分配后保留至少 {reserve_bytes(facts['disk']) / MIB / 1024:.2f} GiB 磁盘。")
        bbr = facts["bbrModule"] and all(facts["values"].values()) and facts["container"] == "none"
        if facts["values"] == DESIRED:
            self.say("网络建议： 当前已为 BBR + fq 默认值，保留现有设置。")
            bbr = False
        elif bbr:
            self.say("网络建议： 将新 TCP 连接默认算法设为 BBR，默认队列设为 fq；执行时再验证内核能力。")
        else:
            self.say("网络建议： 未确认内核 BBR 能力或可用权限，保持现状。")
        self.say("适用范围： Swap 是内存缓冲；BBR 不保证全链路加速，UDP/QUIC 不使用系统 TCP BBR。")
        self.say("队列说明： 不替换当前网卡的 mq、noqueue 或其它队列；默认队列和实际队列分别显示。")
        return swap, bool(bbr)

    def recommend(self):
        facts = self.host.facts()
        self.status(facts)
        self.say("")
        self.recommendations(facts)
        return 0

    def check_swap_identity(self, identity, *, allow_missing=False):
        self.validate_identity(identity)
        info = self.host.info("swap")
        if info is None and allow_missing:
            return None
        if info is None or (info.st_dev, info.st_ino) != (identity["dev"], identity["ino"]):
            raise OptError("Swap 文件已被替换或不属于本次记录，未操作。")
        return info

    @staticmethod
    def fstab_without_block(text, block):
        if text is None:
            raise OptError("/etc/fstab 不存在，未创建替代配置。")
        if text.count(block) == 1:
            start = text.index(block)
            prefix, suffix = text[:start], text[start + len(block):]
            # The block may include a newline we added to an unterminated file.
            # Later administrator entries still need a boundary when we remove it.
            separator = "\n" if prefix and suffix and not prefix.endswith("\n") and not suffix.startswith("\n") else ""
            rest = prefix + separator + suffix
        else:
            rest = text
        if "# BEGIN InstaBox Tool swap" in rest or "# END InstaBox Tool swap" in rest:
            raise OptError("本工具 fstab 条目被修改或重复，需先处理冲突。")
        for line in rest.splitlines():
            fields = line.split()
            if fields and not fields[0].startswith("#") and fields[0] == SWAP:
                raise OptError("fstab 存在非本工具拥有的同路径条目，未修改。")
        return rest

    def verify_managed(self, state, facts):
        if state and state["swap"]:
            swap = state["swap"]
            info = self.check_swap_identity(swap["identity"])
            if info.st_size != swap["mib"] * MIB:
                raise OptError("受管 Swap 文件大小改变，未修改。")
            text = self.host.read("fstab")
            self.fstab_without_block(text, swap["block"])
            if swap["block"] not in text:
                raise OptError("本工具 fstab 条目已被外部移除，需先处理冲突。")
        if state and state["bbr"]:
            if self.host.read("bbr") != BBR_TEXT:
                raise OptError("本工具网络配置已被外部修改，未覆盖。")
            for key in KEYS:
                if facts["values"][key] not in (DESIRED[key], state["bbr"][key]):
                    raise OptError("系统网络参数出现后续外部修改，未覆盖。")

    def plan(self, command, requested, facts, state):
        self.validate_state(state)
        self.verify_managed(state, facts)
        before = state or {"schema": 1, "swap": None, "bbr": None}
        after = json.loads(canonical(before))
        ops, cleanup = [], None
        add_swap = command in {"apply", "swap-on"}
        add_bbr = command in {"apply", "bbr-on"}
        if command == "apply":
            planned_size = suggested_swap(facts)
            add_swap = not facts["swaps"] and facts["fs"] in {"ext4", "xfs"} and facts["writable"] and facts["container"] == "none" and planned_size >= 256
            add_bbr = facts["bbrModule"] and all(facts["values"].values()) and facts["container"] == "none"
        else:
            planned_size = requested if requested is not None else suggested_swap(facts)
        if add_bbr and (before["bbr"] or facts["values"] != DESIRED):
            self.host.check_bbr_persistence()
        if add_swap and not before["swap"] and not facts["swaps"]:
            size_mib(planned_size)
            if facts["container"] != "none" or facts["fs"] not in {"ext4", "xfs"} or not facts["writable"]:
                raise OptError("只在可写 ext4/xfs 的非容器机器创建 Swap。")
            if not facts["caps"] & (1 << 21):
                raise OptError("缺少 CAP_SYS_ADMIN，无法管理 Swap。")
            if facts["free"] - planned_size * MIB < reserve_bytes(facts["disk"]):
                raise OptError("磁盘不足：创建后须保留至少 2 GiB 或总容量 10%。")
            if self.host.info("swap") is not None:
                raise OptError("固定 Swap 路径已有未登记文件，未接管或覆盖。")
            text = self.host.read("fstab")
            self.fstab_without_block(text, BLOCK)
            if BLOCK in text:
                raise OptError("已有无归属记录的 Swap 条目，未接管。")
            block = ("\n" if text and not text.endswith("\n") else "") + BLOCK
            ops += [{"kind": "create", "mib": planned_size, "identity": None},
                    {"kind": "active", "before": False, "after": True},
                    {"kind": "fstab", "add": True, "block": block}]
            after["swap"] = {"mib": planned_size, "identity": None, "block": block}
        elif command == "swap-on" and facts["swaps"]:
            self.say("已有 Swap，保持现有文件和设备；未额外分配。")
        if add_swap and before["swap"]:
            if requested is not None and requested != before["swap"]["mib"]:
                raise OptError("本工具已有不同大小的 Swap；请先停用，再重新创建。")
            if not any(row["path"] == SWAP for row in facts["swaps"]):
                if facts["container"] != "none" or not facts["caps"] & (1 << 21):
                    raise OptError("当前权限或容器环境不允许启用 Swap。")
                ops.append({"kind": "active", "before": False, "after": True})
        if command in {"swap-off", "restore"} and before["swap"]:
            managed = next((row for row in facts["swaps"] if row["path"] == SWAP), None)
            if managed and managed["used"] and facts["availableMemory"] < managed["used"] + 256 * MIB:
                raise OptError("可用内存不足以安全移回本工具 Swap；请先释放内存。")
            ops += [{"kind": "active", "before": managed is not None, "after": False},
                    {"kind": "fstab", "add": False, "block": before["swap"]["block"]}]
            cleanup = before["swap"]["identity"]
            after["swap"] = None
        if add_bbr and not before["bbr"] and facts["values"] != DESIRED:
            if facts["container"] != "none" or not facts["caps"] & (1 << 12):
                raise OptError("需要非容器环境及 CAP_NET_ADMIN 才能调整网络默认值。")
            if not facts["bbrModule"] or not all(facts["values"].values()):
                raise OptError("当前内核未确认 BBR 支持；未安装或替换内核。")
            if self.host.read("bbr") is not None:
                raise OptError("专属 sysctl 文件已存在但没有本工具记录，未覆盖。")
            self.host.parents(self.host.asset("bbr"))
            ops.append({"kind": "file", "before": None, "after": BBR_TEXT})
            for key in KEYS:
                ops.append({"kind": "sysctl", "key": key, "before": facts["values"][key], "after": DESIRED[key]})
            after["bbr"] = dict(facts["values"])
        elif add_bbr and before["bbr"] and facts["values"] != DESIRED:
            if facts["container"] != "none" or not facts["caps"] & (1 << 12) or not facts["bbrModule"]:
                raise OptError("当前权限或内核能力不允许重新启用 BBR。")
            # Preserve the original baseline, even when re-enabling after a
            # reboot or an administrator restoring exactly those original values.
            for key in KEYS:
                if facts["values"][key] != DESIRED[key]:
                    ops.append({"kind": "sysctl", "key": key, "before": facts["values"][key], "after": DESIRED[key]})
        if command in {"bbr-off", "restore"} and before["bbr"]:
            for key in reversed(KEYS):
                ops.append({"kind": "sysctl", "key": key, "before": facts["values"][key], "after": before["bbr"][key]})
            ops.append({"kind": "file", "before": BBR_TEXT, "after": None})
            after["bbr"] = None
        return {"schema": 1, "phase": "prepared", "before": state, "after": after,
                "ops": ops, "cleanup": cleanup}

    def save_journal(self, journal):
        self.host.write("journal", canonical(journal))

    def validate_journal(self, journal):
        if not isinstance(journal, dict) or set(journal) != {"schema", "phase", "before", "after", "ops", "cleanup"} or type(journal["schema"]) is not int or journal["schema"] != 1 or journal["phase"] not in ("prepared", "committed"):
            raise OptError("事务记录无效，保留现场。")
        self.validate_state(journal["before"])
        # A prepared create records its inode before allocation finishes.
        after = json.loads(canonical(journal["after"]))
        if not isinstance(after, dict) or after.get("swap") is not None and not isinstance(after["swap"], dict):
            raise OptError("事务目标记录无效。")
        if after.get("swap") and after["swap"].get("identity") is None and journal["phase"] == "prepared":
            after["swap"]["identity"] = {"dev": 0, "ino": 0}
        self.validate_state(after)
        if journal["cleanup"] is not None:
            self.validate_identity(journal["cleanup"])
        if not isinstance(journal["ops"], list) or len(journal["ops"]) > 8:
            raise OptError("事务操作列表无效。")
        for op in journal["ops"]:
            if not isinstance(op, dict):
                raise OptError("事务操作格式无效。")
            kind = op.get("kind")
            if kind == "create" and set(op) == {"kind", "mib", "identity"}:
                size_mib(op["mib"])
                if op["identity"] is not None:
                    self.validate_identity(op["identity"])
            elif kind == "active" and set(op) == {"kind", "before", "after"} and type(op["before"]) is bool and type(op["after"]) is bool:
                pass
            elif kind == "fstab" and set(op) == {"kind", "add", "block"} and type(op["add"]) is bool and op["block"] in (BLOCK, "\n" + BLOCK):
                pass
            elif kind == "file" and set(op) == {"kind", "before", "after"} and op["before"] in (None, BBR_TEXT) and op["after"] in (None, BBR_TEXT):
                pass
            elif kind == "sysctl" and set(op) == {"kind", "key", "before", "after"} and op["key"] in KEYS and identifier(op["before"]) and identifier(op["after"]):
                pass
            else:
                raise OptError("事务包含非允许操作，保留现场。")

    def swap_identity(self, journal):
        for op in journal["ops"]:
            if op["kind"] == "create":
                return op["identity"]
        state = journal["before"]
        return state["swap"]["identity"] if state and state["swap"] else None

    def execute_op(self, journal, op, reverse=False):
        kind = op["kind"]
        if kind == "create":
            if reverse:
                if self.host.info("swap") is not None:
                    self.remove_swap(op["identity"])
                return
            try:
                fd = os.open(self.host.path(BASE), os.O_RDWR | os.O_TMPFILE | os.O_NOFOLLOW, 0o600)
            except OSError:
                raise OptError("当前文件系统不支持安全创建匿名 Swap 文件，未启用。") from None
            try:
                os.fchmod(fd, 0o600)
                info = os.fstat(fd)
                op["identity"] = {"dev": info.st_dev, "ino": info.st_ino}
                journal["after"]["swap"]["identity"] = op["identity"]
                self.save_journal(journal)
                self.host.publish_swap(fd)
                self.check_swap_identity(op["identity"])
                self.host.allocator(fd, op["mib"] * MIB)
                if os.fstat(fd).st_size != op["mib"] * MIB:
                    raise OptError("Swap 文件大小未读回一致。")
                os.fsync(fd)
            finally:
                os.close(fd)
            if self.host.call("mkswap", "--", self.host.asset("swap"), timeout=60).returncode:
                raise OptError("Swap 初始化失败，正在回退。")
            return
        if kind == "active":
            identity = self.swap_identity(journal)
            if reverse and any(item["kind"] == "create" for item in journal["ops"]) and self.host.info("swap") is None:
                if any(row["path"] == SWAP for row in self.host.swaps()):
                    raise OptError("已无可见文件的 Swap 仍在活动，保留事务供检查。")
                return
            self.check_swap_identity(identity)
            desired = op["before"] if reverse else op["after"]
            active = next((row for row in self.host.swaps() if row["path"] == SWAP), None)
            if bool(active) == desired:
                return
            if not desired and active["used"]:
                if self.host.facts()["availableMemory"] < active["used"] + 256 * MIB:
                    raise OptError("Swap 仍在使用且可用内存不足，保留文件与记录。")
            command = "swapon" if desired else "swapoff"
            result = self.host.call(command, "--", self.host.asset("swap"), timeout=120)
            actual = any(row["path"] == SWAP for row in self.host.swaps())
            if result.returncode or actual != desired:
                raise OptError("Swap 启停未确认成功，保留可恢复记录；没有删除活动文件。")
            return
        if kind == "fstab":
            current = self.host.read("fstab")
            rest = self.fstab_without_block(current, op["block"])
            add = op["add"] != reverse
            desired = current if op["block"] in current else current + op["block"]
            if not add:
                desired = rest
            self.host.write("fstab", desired, expected=current)
            return
        if kind == "file":
            old, new = (op["after"], op["before"]) if reverse else (op["before"], op["after"])
            current = self.host.read("bbr")
            if current == new:
                return
            if current != old:
                raise OptError("网络配置文件被外部修改，保留事务记录。")
            self.host.write("bbr", new, expected=current)
            return
        if kind == "sysctl":
            old, new = (op["after"], op["before"]) if reverse else (op["before"], op["after"])
            current = self.host.sysctl(op["key"])
            if current == new:
                return
            if current != old:
                raise OptError("系统参数被外部修改，未强行覆盖。")
            result = self.host.call("sysctl", "-w", op["key"] + "=" + new)
            if result.returncode or self.host.sysctl(op["key"]) != new:
                raise OptError("系统参数未读回期望值，正在回退。")

    def remove_swap(self, identity):
        self.check_swap_identity(identity, allow_missing=True)
        if any(row["path"] == SWAP for row in self.host.swaps()):
            raise OptError("本工具 Swap 仍在活动，禁止删除。")
        if self.host.info("swap") is not None:
            self.check_swap_identity(identity)
            self.host.asset("swap").unlink()
            self.host.sync_directory(self.host.asset("swap").parent)

    def recover(self, journal):
        self.validate_journal(journal)
        current = self.state()
        if current not in (journal["before"], journal["after"]):
            raise OptError("优化记录出现并发修改，保留事务供检查。")
        if journal["phase"] == "committed":
            if current != journal["after"]:
                raise OptError("已提交事务的状态不一致，未回滚。")
            if journal["cleanup"] is not None:
                self.remove_swap(journal["cleanup"])
        else:
            for op in reversed(journal["ops"]):
                self.execute_op(journal, op, reverse=True)
            self.host.write("state", canonical(journal["before"]) if journal["before"] is not None else None)
        self.host.write("journal", None)

    def transaction(self, journal):
        self.save_journal(journal)
        try:
            if any(op["kind"] == "sysctl" and op["key"] == KEYS[1] and op["after"] == "bbr" for op in journal["ops"]):
                if "bbr" not in self.host.sysctl("net.ipv4.tcp_available_congestion_control"):
                    self.host.call("modprobe", "tcp_bbr")
                if "bbr" not in self.host.sysctl("net.ipv4.tcp_available_congestion_control"):
                    raise OptError("内核未注册 BBR；未替换内核，正在回退。")
            for op in journal["ops"]:
                self.execute_op(journal, op)
            if journal["after"]["bbr"] and any(op["kind"] == "sysctl" and op["after"] == DESIRED[op["key"]] for op in journal["ops"]):
                self.host.check_bbr_persistence()
            self.host.write("state", canonical(journal["after"]))
            journal["phase"] = "committed"
            self.save_journal(journal)
        except BaseException as error:
            # A write may have reached disk before fsync reported an error. The
            # on-disk commit decision, not the in-memory phase, controls recovery.
            try:
                recorded = self.read_json("journal")
                if recorded is None:
                    raise OptError("事务决策记录缺失，保留现场，未猜测回滚。")
                self.recover(recorded)
            except Exception:
                raise OptError("操作未完成且自动恢复受阻；现场已保留，请检查冲突后选择恢复。") from None
            if isinstance(error, KeyboardInterrupt):
                raise
            if recorded["phase"] == "committed":
                self.say("变更已提交并读回；已完成后续清理。")
                return
            reason = str(error) if isinstance(error, OptError) else "本地系统操作失败，未显示底层输出。"
            raise OptError(reason + " 本次新设置已撤回。") from None
        self.recover(journal)

    def change(self, command, requested=None, *, yes=False):
        if not self.privileged:
            raise OptError("系统变更需要管理员授权。")
        if requested is not None:
            size_mib(requested)
        pending = self.read_json("journal")
        if pending:
            if command != "restore":
                raise OptError("有未完成事务；请先选择恢复，避免叠加变更。")
            self.say("将核对并恢复上次未完成事务；外部修改会阻止覆盖。")
            if not yes and not self.confirm():
                self.say("已取消，未修改系统。")
                return 3
            with self.host.lock():
                pending = self.read_json("journal")
                if pending:
                    self.recover(pending)
            remaining = self.state()
            if remaining and (remaining["swap"] or remaining["bbr"]):
                self.say("上次事务已处理；仍有已提交设置，请再次选择恢复并确认具体计划。")
                return 2
            self.say("上次事务已处理，没有其它本工具设置需要恢复。")
            return 0
        facts, before = self.host.facts(), self.state()
        if command == "apply":
            self.recommendations(facts)
        # Missing /var/lib/insta-box-tool is normal before the first change.
        journal = self.plan(command, requested, facts, before)
        if not journal["ops"]:
            self.say("没有可执行的新增设置；保留现有配置。" if command == "apply" else "无需变更；已有系统设置与其它工具资源保持原样。")
            return 0
        self.say("计划变更：")
        for op in journal["ops"]:
            if op["kind"] == "create":
                self.say(f"创建本工具专属 {op['mib']} MiB Swap，启用并加入标记启动条目。")
            elif op["kind"] == "active" and not op["after"]:
                self.say("停用并移除本工具专属 Swap，保留其它交换空间。")
            elif op["kind"] == "sysctl":
                self.say(op["key"] + ": " + op["before"] + " → " + op["after"])
        self.say("已有网卡队列不替换；原值保存在管理员私有记录中，可从本菜单恢复。")
        if not yes and not self.confirm():
            self.say("已取消，未修改系统。")
            return 3
        with self.host.lock():
            if self.read_json("journal"):
                raise OptError("等待确认期间已有其它事务，请先恢复。")
            # Rebuild under the lock. Compare the exact approved operations and
            # prior state, while allowing harmless disk/memory fluctuations.
            fresh = self.plan(command, requested, self.host.facts(), self.state())
            if fresh != journal:
                raise OptError("等待确认期间环境已变化，请重新查看计划。")
            self.transaction(fresh)
        self.say("本次设置已读回确认，恢复记录已保存。")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="InstaBox Tool：只读检查与可恢复的机器优化")
    parser.add_argument("command", nargs="?", choices=COMMANDS, default="status")
    parser.add_argument("mib", nargs="?", type=int)
    parser.add_argument("--yes", action="store_true", help="明确批准所显示的变更，供自动化使用")
    parser.add_argument("--privileged", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.mib is not None and args.command != "swap-on":
        parser.error("大小参数仅用于 swap-on")
    try:
        if args.command in {"status", "recommend"}:
            return getattr(Optimizer(), args.command)()
        if args.mib is not None:
            size_mib(args.mib)
        if os.geteuid() != 0:
            if args.privileged:
                raise OptError("管理员授权未生效，未修改。")
            if any(os.environ.get(name) == "1" for name in ("IBT_NO_SUDO", "IB_NO_SUDO", "SB_NO_SUDO")):
                raise OptError("已按设置禁止 sudo，未修改；清除此设置后在菜单确认或以授权方式执行。")
            command = ["/usr/bin/sudo", "--", "/usr/bin/python3", "-I", str(Path(__file__).resolve()), args.command]
            if args.mib is not None:
                command += [str(args.mib)]
            command += ["--privileged"]
            if args.yes:
                command += ["--yes"]
            return subprocess.run(command, env={**ENV, "TERM": os.environ.get("TERM", "dumb")}, check=False).returncode
        os.umask(0o077)
        return Optimizer().change(args.command, args.mib, yes=args.yes)
    except KeyboardInterrupt:
        say("已中断；如存在未完成事务，请选择恢复后再操作。")
        return 130
    except (OptError, OSError, ValueError):
        # Unexpected OS errors never reveal raw command output or environment.
        error = sys.exc_info()[1]
        say("[失败] " + (str(error) if isinstance(error, OptError) else "本地系统操作失败；未显示底层路径或输出。"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
