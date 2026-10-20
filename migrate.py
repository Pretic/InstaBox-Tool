#!/usr/bin/env python3
# Author: Pre
"""Transactional InstaBox Tool installation and owned v2 migration, stdlib only.

The shell bootstrap verifies the bundle first. This module verifies it again,
moves private state instead of reconstructing it, and journals reversible local
changes before applying them. It never calls a cloud API or prints file contents.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid


VERSION = "0.0.1"
FILES = ("setup.sh", "ibt.sh", "install.sh", "keepalive.sh", "platform.mjs", "cf_route.py", "cf_select.py",
         "heartbeat.py", "cloud.py", "ssh_tokens.py", "machine_opt.py", "node_probe.py", "system_info.py", "ui_time.py", "migrate.py")
OLD_MARKER = "# Managed-by: Insta-Sing-box"
V3_MARKER = "# Managed-by: Insta Box"
NEW_MARKER = "# Managed-by: InstaBox Tool"
BRIDGE_MARKER = NEW_MARKER + " migration bridge"
UNIT_MAP = {
    "insta-sing-box.service": "insta-box-node.service",
    "insta-cloudflared.service": "insta-box-tunnel.service",
    "insta-singbox-quick.service": "insta-box-quick.service",
    "insta-singbox-heartbeat.service": "insta-box-heartbeat.service",
    "insta-singbox-heartbeat.timer": "insta-box-heartbeat.timer",
}
OLD_APP = ".local/share/insta-sing-box"
NEW_APP = ".local/share/insta-box"
OLD_CFG = ".config/insta-sing-box"
NEW_CFG = ".config/insta-box"
OLD_PATH_LINE = b'export PATH="$HOME/.local/bin:$PATH" # Insta-Sing-box CLI'
V3_PATH_LINE = b'export PATH="$HOME/.local/bin:$PATH" # Insta Box CLI'
NEW_PATH_LINE = b'export PATH="$HOME/.local/bin:$PATH" # InstaBox Tool CLI'
OLD_QUICK = b'''#!/usr/bin/env bash
set -Eeuo pipefail
base="${HOME}/.local/share/insta-sing-box"
port="$(awk -F= '$1=="port" {print substr($0,6); exit}' "${base}/state.conf")"
[[ "$port" =~ ^[1-9][0-9]{3,4}$ ]] || exit 2
: > "${base}/quick.log"
exec "${base}/bin/cloudflared" tunnel --url "http://127.0.0.1:${port}" >> "${base}/quick.log" 2>&1
'''
V3_QUICK = OLD_QUICK.replace(OLD_APP.encode(), NEW_APP.encode())
PREVIOUS_QUICK = V3_QUICK.replace(b"set -Eeuo pipefail\n", b"set -Eeuo pipefail\numask 077\n", 1)
QUICK = b'''#!/usr/bin/env bash
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
  printf 'auto\\n' > "${base}/quick-protocol"
  chmod 600 "${base}/quick-protocol"
fi
[[ "$protocol" == auto || "$protocol" == http2 ]] || exit 2
# An explicit empty config prevents unrelated named-tunnel ingress from winning
# over --url. It does not change the user's ~/.cloudflared configuration.
if [[ -f "${base}/quick-config.yml" && "$(< "${base}/quick-config.yml")" != '{}' ]]; then
  exit 2
fi
printf '{}\\n' > "${base}/quick-config.yml"
chmod 600 "${base}/quick-config.yml"
: > "${base}/quick.log"
chmod 600 "${base}/quick.log"
invocation="${INVOCATION_ID:-}"
[[ "$invocation" =~ ^[0-9a-f]{32}$ ]] || invocation=unknown
printf 'IBT_QUICK_INVOCATION=%s\\n' "$invocation" >> "${base}/quick.log"
# Do not inherit named-tunnel or demo-origin settings from the user manager.
unset TUNNEL_NAME TUNNEL_HELLO_WORLD
exec "${base}/bin/cloudflared" tunnel --config "${base}/quick-config.yml" --protocol "$protocol" --no-autoupdate --url "http://127.0.0.1:${port}" >> "${base}/quick.log" 2>&1
'''
PYTHON_MODULES = frozenset(Path(name).stem for name in FILES if name.endswith(".py"))


class MigrationError(Exception):
    """Only locally composed, credential-free diagnostics are exposed."""


def safe_path(path):
    value = str(path)
    prefix = str(Path.home()) + os.sep
    if value.startswith(prefix):
        value = "~/" + value[len(prefix):]
    value = re.sub(r"ib(?:k|ssh)_[A-Za-z0-9._~+/=%-]+", "[已隐藏]", value)
    return "".join(character if character.isprintable() else "?" for character in value)[:240]


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def owned(path, *, directory=False, private=False, allow_link=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if info.st_uid != os.getuid():
        raise MigrationError("安装路径中存在不属于当前用户的文件，未迁移。")
    if stat.S_ISLNK(info.st_mode):
        if allow_link:
            return True
        raise MigrationError("安装路径包含不允许的符号链接，未迁移。")
    if directory != stat.S_ISDIR(info.st_mode) or not directory and not stat.S_ISREG(info.st_mode):
        raise MigrationError("安装路径类型异常，未迁移。")
    if not directory and info.st_nlink != 1:
        raise MigrationError("安装文件存在额外硬链接，未迁移。")
    if info.st_mode & (0o077 if private else 0o022):
        raise MigrationError("安装路径权限不安全：" + safe_path(path) + "（当前 " + format(stat.S_IMODE(info.st_mode), "04o") + "），未迁移。")
    return True


def atomic_write(path, data, mode=0o600, *, temporary=None):
    if temporary is None:
        fd, temporary = tempfile.mkstemp(prefix=".ib-write-", dir=path.parent)
    else:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def fingerprint(path):
    if not os.path.lexists(path):
        return {"kind": "missing"}
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return {"kind": "symlink", "target": os.readlink(path)}
    if stat.S_ISREG(info.st_mode):
        return {"kind": "file", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": stat.S_IMODE(info.st_mode)}
    raise MigrationError("待替换的安装文件不是普通文件或已验证的链接。")


class Installer:
    def __init__(self, home=None, *, runner=None, output=None, checkpoint=None):
        self.home = Path(home) if home is not None else Path.home()
        self.home = self.home.absolute()
        self.runner = runner or subprocess.run
        self.output = output or print
        self.checkpoint = checkpoint or (lambda _name: None)
        self.old_app, self.app = self.home / OLD_APP, self.home / NEW_APP
        self.old_cfg, self.cfg = self.home / OLD_CFG, self.home / NEW_CFG
        self.unit_dir = self.home / ".config/systemd/user"
        self.local = self.home / ".local/bin"
        self.work = self.home / ".local/share/.insta-box-migration"
        self.journal_path = self.work / "journal.json"
        self.journal = None
        self.lock_fds = []
        self.heartbeat_fd = None

    def say(self, message):
        self.output("  " + message)

    def relative(self, path):
        return str(path.relative_to(self.home))

    def path(self, relative):
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            raise MigrationError("迁移记录中的路径无效，已保留现场。")
        return self.home / relative

    def check_parents(self, path):
        if not owned(self.home, directory=True):
            raise MigrationError("用户目录不存在。")
        for parent in reversed(path.parents):
            if parent == self.home or self.home not in parent.parents:
                continue
            if not owned(parent, directory=True):
                break

    def ensure_parent(self, path):
        self.check_parents(path)
        if os.path.lexists(path):
            owned(path, directory=True)
        missing = []
        parent = path
        while parent != self.home and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        return missing

    def check_tree(self, root, *, private=False):
        if not owned(root, directory=True, private=private):
            return []
        links = []
        for current, directories, filenames in os.walk(root, followlinks=False):
            for name in directories + filenames:
                path = Path(current) / name
                if path.is_symlink():
                    owned(path, allow_link=True)
                    if private:
                        raise MigrationError("私有配置中存在符号链接，未迁移。")
                    try:
                        path.resolve(strict=True).relative_to(root.resolve())
                    except (ValueError, OSError, RuntimeError):
                        raise MigrationError("旧程序目录存在外部或失效链接，未迁移。") from None
                    links.append((path.relative_to(root), os.readlink(path)))
                else:
                    owned(path, directory=path.is_dir(), private=private)
        return links

    @staticmethod
    def runtime_file(path):
        """Open only a current-user, single-link regular runtime artifact."""
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
            raise MigrationError("旧运行文件不是当前用户的独立普通文件：" + safe_path(path))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or current.st_nlink != 1:
            os.close(fd)
            raise MigrationError("旧运行文件在检查时发生变化，未修改：" + safe_path(path))
        return fd

    def repair_quick_log(self, root):
        log = root / "quick.log"
        if not os.path.lexists(log) or not stat.S_IMODE(log.lstat().st_mode) & 0o077:
            return
        self.check_parents(log)
        owned(root, directory=True)
        launcher = root / "bin/start-quick-tunnel"
        self.check_parents(launcher)
        if not owned(launcher):
            raise MigrationError("旧日志权限过宽，但无法确认对应启动器，未自动修改：" + safe_path(log))
        old = root == self.old_app
        body = OLD_QUICK if old else V3_QUICK
        accepted = (body.rstrip(b"\n"), body.replace(b"set -Eeuo pipefail\n", b"set -Eeuo pipefail\numask 077\n", 1).rstrip(b"\n"))
        if not old:
            accepted += (QUICK.rstrip(b"\n"),)
        if launcher.read_bytes().rstrip(b"\n") not in accepted:
            raise MigrationError("旧日志权限过宽，但启动器包含自定义内容，未自动修改：" + safe_path(log))
        unit = self.unit_dir / ("insta-singbox-quick.service" if old else "insta-box-quick.service")
        self.check_parents(unit)
        if not self.check_marked(unit, [OLD_MARKER] if old else [V3_MARKER, NEW_MARKER]):
            raise MigrationError("旧日志权限过宽，但对应服务归属未确认，未自动修改：" + safe_path(log))
        fd = self.runtime_file(log)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.say("已收紧旧版运行日志权限，日志内容保持不变。")

    def repair_python_caches(self, root):
        releases = root / "tool-releases"
        if not os.path.lexists(releases):
            return
        self.check_parents(releases)
        owned(releases, directory=True)
        for release in releases.iterdir():
            if not stat.S_ISDIR(release.lstat().st_mode):
                continue
            cache = release / "__pycache__"
            if not os.path.lexists(cache):
                continue
            self.check_parents(cache)
            entries = (("ibt.sh", [NEW_MARKER + " CLI"]), ("ib.sh", [V3_MARKER + " CLI"]), ("isb.sh", [OLD_MARKER + " CLI"]))
            if not any(self.check_marked(release / name, markers) for name, markers in entries):
                raise MigrationError("无法确认旧 Python 缓存所属版本，未清理：" + safe_path(cache))
            info = cache.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise MigrationError("旧 Python 缓存不是当前用户的普通目录，未清理：" + safe_path(cache))
            fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                current = os.fstat(fd)
                if current.st_uid != os.getuid() or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise MigrationError("旧 Python 缓存目录在检查时发生变化，未清理。")
                files = {}
                for name in os.listdir(fd):
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)\.[A-Za-z0-9_-]+(?:\.opt-[0-9]+)?\.pyc", name)
                    if not match or match.group(1) not in PYTHON_MODULES or not owned(release / (match.group(1) + ".py")):
                        raise MigrationError("旧 Python 缓存包含未知项目，未清理：" + safe_path(cache / name))
                    child = self.runtime_file(cache / name)
                    try:
                        item = os.fstat(child)
                        files[name] = (item.st_dev, item.st_ino)
                    finally:
                        os.close(child)
                # Block other users from adding entries between validation and
                # removal. Only this verified disposable cache is changed.
                os.fchmod(fd, 0o700)
                if set(os.listdir(fd)) != set(files):
                    raise MigrationError("旧 Python 缓存内容在检查时发生变化，未继续清理。")
                for name, identity in files.items():
                    item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or item.st_nlink != 1 or (item.st_dev, item.st_ino) != identity:
                        raise MigrationError("旧 Python 缓存文件在检查时发生变化，未继续清理。")
                    os.unlink(name, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
            cache.rmdir()
            fsync_dir(release)
            self.say("已清理旧版生成的 Python 缓存。")

    def sdk_is_managed(self, root):
        """Recognize menu installations and the earliest service-only install."""
        old = root == self.old_app
        markers = [OLD_MARKER] if old else [V3_MARKER, NEW_MARKER]

        def marked(path, expected):
            try:
                return self.check_marked(path, expected)
            except MigrationError:
                return False

        names = ("isb",) if old else ("ib", "ibt")
        for name in names:
            if marked(self.local / name, [marker + " CLI" for marker in markers]):
                return True
        try:
            cli = (root / "cli").resolve(strict=True)
            cli.relative_to(root)
            self.check_parents(cli / "probe")
        except (ValueError, OSError, RuntimeError, MigrationError):
            cli = None
        if cli is not None:
            for name in names:
                if marked(cli / (name + ".sh"), [marker + " CLI" for marker in markers]):
                    return True
        # The initial SDK helper predated the menu and installed no platform.mjs.
        # Its already-managed node/tunnel services are sufficient provenance.
        binaries = {"insta-sing-box.service": "sing-box", "insta-cloudflared.service": "cloudflared",
                    "insta-singbox-quick.service": "start-quick-tunnel"}
        for old_name, binary in binaries.items():
            name = old_name if old else UNIT_MAP[old_name]
            unit = self.unit_dir / name
            if not marked(unit, markers):
                continue
            commands = ("ExecStart=%h/" + self.relative(root) + "/bin/" + binary,
                        "ExecStart=" + str(root) + "/bin/" + binary)
            if any(line == command or line.startswith((command + " ", command + "\t"))
                   for line in unit.read_text().splitlines() for command in commands):
                self.unit_identity(name)
                return True
        return False

    def repair_sdk_permissions(self, root):
        """Tighten an identified, private SDK tree without running or replacing it."""
        management = root / "management"
        modules = management / "node_modules"
        # Safe/incomplete SDK installs retain the existing preflight behavior.
        # Do not follow a replaced management or node_modules root to inspect it.
        if not management.is_dir() or management.is_symlink() or not modules.is_dir() or modules.is_symlink():
            return
        needs_repair = bool(management.lstat().st_mode & 0o022 or modules.lstat().st_mode & 0o022)
        if not needs_repair:
            def walk_error(error):
                raise error
            for current, directories, filenames in os.walk(modules, followlinks=False, onerror=walk_error):
                if any(not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022
                       for info in ((Path(current) / name).lstat() for name in directories + filenames)):
                    needs_repair = True
                    break
        if not needs_repair:
            return
        self.check_parents(management)
        owned(root, directory=True, private=True)
        if not self.sdk_is_managed(root):
            raise MigrationError("无法确认旧 SDK 所属工具，未自动修改权限：" + safe_path(modules))

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)

        def validate(info, path):
            if info.st_uid != os.getuid() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise MigrationError("旧 SDK 包含非当前用户的文件或异常类型，未修改权限：" + safe_path(path))
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise MigrationError("旧 SDK 文件存在额外硬链接，未修改权限：" + safe_path(path))

        snapshots, children = {}, {}
        manifest = None

        def visit(parent_fd, name, relative, *, repair=False):
            nonlocal manifest
            path = modules / relative
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            validate(info, path)
            if repair:
                if identity(info) != snapshots.get(relative):
                    raise MigrationError("旧 SDK 在检查时发生变化，未继续修改权限。")
            else:
                snapshots[relative] = identity(info)
            if stat.S_ISLNK(info.st_mode):
                try:
                    path.resolve(strict=True).relative_to(modules)
                except (ValueError, OSError, RuntimeError):
                    raise MigrationError("旧 SDK 存在外部或失效链接，未修改权限：" + safe_path(path)) from None
                return
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(info.st_mode):
                flags |= os.O_DIRECTORY
            fd = os.open(name, flags, dir_fd=parent_fd)
            try:
                if identity(os.fstat(fd)) != identity(info):
                    raise MigrationError("旧 SDK 在打开时发生变化，未继续修改权限。")
                if stat.S_ISDIR(info.st_mode):
                    entries = sorted(os.listdir(fd))
                    if repair and entries != children[relative]:
                        raise MigrationError("旧 SDK 目录内容在检查时发生变化，未继续修改权限。")
                    if not repair:
                        children[relative] = entries
                    for entry in entries:
                        visit(fd, entry, relative / entry, repair=repair)
                elif not repair and relative == Path("@insforge/instabox-sdk/package.json"):
                    try:
                        manifest = json.loads(os.read(fd, 131073))
                    except (ValueError, UnicodeError):
                        raise MigrationError("旧 SDK 包信息无效，未修改权限。") from None
                if repair and info.st_mode & 0o022:
                    os.fchmod(fd, stat.S_IMODE(info.st_mode) & ~0o022)
                    os.fsync(fd)
            finally:
                os.close(fd)

        before = management.lstat()
        validate(before, management)
        fd = os.open(management, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if identity(os.fstat(fd)) != identity(before):
                raise MigrationError("旧 SDK 管理目录在检查时发生变化，未修改权限。")
            visit(fd, "node_modules", Path("."))
            if (not isinstance(manifest, dict) or manifest.get("name") != "@insforge/instabox-sdk"
                    or not isinstance(manifest.get("version"), str)
                    or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", manifest["version"])):
                raise MigrationError("无法确认旧 InstaBox SDK 包信息，未修改权限。")
            if identity(management.lstat()) != identity(before):
                raise MigrationError("旧 SDK 管理目录在检查时发生变化，未修改权限。")
            # Complete validation precedes any chmod. All later opens remain
            # relative to verified descriptors and never follow symlinks.
            visit(fd, "node_modules", Path("."), repair=True)
            os.fchmod(fd, 0o700)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.say("已修正旧版 SDK 依赖目录权限，文件内容和原配置保持不变。")

    def check_marked(self, path, markers):
        if not owned(path):
            return False
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeError, OSError):
            raise MigrationError("安装入口或服务文件无法安全读取，未覆盖。") from None
        if not any(marker in lines for marker in markers):
            raise MigrationError("同名入口或服务不属于本工具，不会覆盖。")
        return True

    @staticmethod
    def legacy_wrapper_markers(name):
        return [(OLD_MARKER if name == "isb" else V3_MARKER) + " CLI",
                V3_MARKER + " migration bridge", BRIDGE_MARKER]

    def legacy_wrapper_owned(self, name):
        path = self.local / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            return False
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return False
        if not any(marker in lines for marker in self.legacy_wrapper_markers(name)):
            return False
        owned(path)
        return True

    def command(self, args, *, timeout=45):
        try:
            return self.runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise MigrationError("本地安装命令不可用或超时，未确认成功。") from None

    def systemctl(self, *args):
        return self.command(["systemctl", "--user", *args])

    def unit_state(self, name, *, missing_ok=False):
        active = self.systemctl("is-active", name)
        enabled = self.systemctl("is-enabled", name)
        active_word = (active.stdout or "").strip()
        enabled_word = (enabled.stdout or "").strip()
        if missing_ok and active_word in ("inactive", "unknown", "failed") and not enabled_word and enabled.returncode != 0 and not os.path.lexists(self.unit_dir / name) and not self.unit_identity(name, missing_ok=True):
            return {"active": False, "enabled": "not-found"}
        if missing_ok and active_word in ("inactive", "unknown", "failed") and enabled_word in ("not-found", "disabled", "static"):
            return {"active": False, "enabled": enabled_word}
        if active_word not in ("active", "inactive", "failed") or enabled_word not in ("enabled", "disabled", "static"):
            raise MigrationError("无法确认服务的运行/自启状态，或存在特殊启用方式；请先检查用户级 systemd。")
        if active_word == "active" and active.returncode != 0 or enabled_word == "enabled" and enabled.returncode != 0:
            raise MigrationError("systemd 状态读回不一致，未迁移。")
        return {"active": active_word == "active", "enabled": enabled_word}

    def unit_identity(self, name, *, missing_ok=False):
        result = self.systemctl("show", name, "--property=LoadState", "--property=FragmentPath", "--property=DropInPaths")
        fields = {}
        for line in (result.stdout or "").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("LoadState", "FragmentPath", "DropInPaths"):
                fields[key] = value
        if missing_ok and fields == {"LoadState": "not-found", "FragmentPath": "", "DropInPaths": ""}:
            return False
        if result.returncode or fields.get("LoadState") != "loaded" or fields.get("FragmentPath") != str(self.unit_dir / name) or fields.get("DropInPaths") != "":
            raise MigrationError("同名服务实际来自其他位置或带有自定义覆盖，未停止或替换。")
        return True

    def preflight(self, bundle, ref):
        if not re.fullmatch(r"[a-f0-9]{40}", ref or ""):
            raise MigrationError("安装版本标识无效。")
        self.verify_bundle(bundle)
        for path in (self.old_app, self.app, self.old_cfg, self.cfg, self.local / "ibt", self.unit_dir / "probe", self.home / ".bashrc"):
            self.check_parents(path)
        if self.old_app.exists() and self.app.exists() or self.old_cfg.exists() and self.cfg.exists():
            raise MigrationError("新旧程序或配置目录同时存在，未选择覆盖任何一份；请先核对两份数据。")
        for root in (self.old_app, self.app):
            if os.path.lexists(root):
                owned(root, directory=True)
                self.repair_quick_log(root)
                self.repair_python_caches(root)
                self.repair_sdk_permissions(root)
        old_links = self.check_tree(self.old_app)
        self.check_tree(self.app)
        self.check_tree(self.old_cfg, private=True)
        self.check_tree(self.cfg, private=True)
        for path in (self.old_app / "cli", self.app / "cli"):
            if path.is_symlink():
                target = path.resolve(strict=True)
                try:
                    target.relative_to(path.parent / "tool-releases")
                except ValueError:
                    raise MigrationError("管理入口链接未指向本工具的版本目录，未替换。") from None
            elif path.exists() and not path.is_dir():
                raise MigrationError("管理入口路径冲突，未覆盖。")
        self.check_marked(self.local / "ibt", [NEW_MARKER + " CLI"])
        old_wrappers = [name for name in ("isb", "ib") if self.legacy_wrapper_owned(name)]
        units = []
        for old, new in UNIT_MAP.items():
            for name in (old, new):
                if os.path.lexists(self.unit_dir / (name + ".d")):
                    raise MigrationError("发现服务自定义覆盖目录；为保留其行为，未自动改名。")
            old_marker = OLD_MARKER + (" Heartbeat" if "heartbeat" in old else "")
            new_markers = [marker + (" Heartbeat" if "heartbeat" in new else "") for marker in (V3_MARKER, NEW_MARKER)]
            old_exists = self.check_marked(self.unit_dir / old, [old_marker])
            new_exists = self.check_marked(self.unit_dir / new, new_markers)
            if old_exists and new_exists:
                raise MigrationError("新旧同类服务同时存在，未开启重复服务；请先核对。")
            if old_exists:
                self.unit_identity(old)
                if self.unit_identity(new, missing_ok=True):
                    raise MigrationError("新服务名称已被加载，未覆盖同名服务。")
                units.append({"old": old, "new": new, **self.unit_state(old)})
        quick = self.old_app / "bin/start-quick-tunnel"
        if quick.exists() and quick.read_bytes().rstrip(b"\n") not in (OLD_QUICK.rstrip(b"\n"), OLD_QUICK.replace(b"set -Eeuo pipefail\n", b"set -Eeuo pipefail\numask 077\n", 1).rstrip(b"\n")):
            raise MigrationError("旧快捷隧道启动器有自定义内容，未自动改写。")
        for rc in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc"):
            owned(self.home / rc)
        return {"units": units, "oldApp": self.old_app.exists(), "oldCfg": self.old_cfg.exists(),
                "oldLinks": [(str(path), target) for path, target in old_links], "ownedLegacyWrappers": old_wrappers, "ref": ref}

    def verify_bundle(self, bundle):
        if not owned(bundle, directory=True):
            raise MigrationError("安装包目录不存在。")
        if not owned(bundle / "SHA256SUMS"):
            raise MigrationError("安装包缺少校验清单。")
        digests = {}
        for line in (bundle / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] in FILES:
                if parts[1] in digests or not re.fullmatch(r"[a-f0-9]{64}", parts[0]):
                    raise MigrationError("安装校验清单无效。")
                digests[parts[1]] = parts[0]
        for name in FILES:
            path = bundle / name
            if not owned(path) or digests.get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
                raise MigrationError("安装包校验未通过，现有数据未修改。")

    @contextlib.contextmanager
    def installation_lock(self):
        self.ensure_parent(self.work.parent)
        path = self.work.parent / ".insta-box-migration.lock"
        owned(path, private=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("另一次安装或迁移正在运行，请稍后重试。") from None
            yield
        finally:
            os.close(fd)

    def lock_file(self, path, *, heartbeat=False):
        owned(path, private=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise MigrationError("保活或云端管理操作仍在运行，未搬动配置；请稍后重试更新。") from None
        self.lock_fds.append(fd)
        if heartbeat:
            self.heartbeat_fd = fd

    def acquire_data_locks(self):
        cfg = self.old_cfg if self.old_cfg.exists() else self.cfg
        if not cfg.exists():
            return
        if self.heartbeat_fd is None:
            self.lock_file(cfg / "heartbeat.lock", heartbeat=True)
        requests = cfg / "cloud-requests"
        if requests.exists():
            names = {path.with_suffix(".lock") for path in requests.iterdir() if path.suffix in (".lock", ".json")}
            for path in sorted(names):
                self.lock_file(path)

    def release_heartbeat_lock(self):
        if self.heartbeat_fd is not None:
            self.lock_fds.remove(self.heartbeat_fd)
            os.close(self.heartbeat_fd)
            self.heartbeat_fd = None

    def release_locks(self):
        for fd in self.lock_fds:
            os.close(fd)
        self.lock_fds = []
        self.heartbeat_fd = None

    def save_journal(self):
        atomic_write(self.journal_path, (json.dumps(self.journal, sort_keys=True) + "\n").encode())

    def operation(self, entry):
        self.journal["ops"].append(entry)
        self.save_journal()
        return entry

    def mkdir(self, path):
        if path.exists():
            owned(path, directory=True)
            return
        self.mkdir(path.parent)
        self.operation({"kind": "mkdir", "path": self.relative(path)})
        path.mkdir(mode=0o700)
        fsync_dir(path.parent)

    def move(self, source, destination):
        self.operation({"kind": "move", "source": self.relative(source), "destination": self.relative(destination)})
        os.rename(source, destination)
        fsync_dir(source.parent)
        fsync_dir(destination.parent)
        self.checkpoint("move:" + self.relative(source))

    def replace(self, path, *, data=None, target=None, mode=0o600, preserve_live=False):
        before = fingerprint(path)
        temporary = path.parent / ((".ib-link-" if target is not None else ".ib-write-") + uuid.uuid4().hex)
        entry = {"kind": "replace", "path": self.relative(path), "before": before, "preserveLive": preserve_live,
                 "temporary": self.relative(temporary)}
        if before["kind"] == "file":
            backup = "backup-" + str(len(self.journal["ops"]))
            atomic_write(self.work / backup, path.read_bytes())
            entry["backup"] = backup
        if data is not None:
            after = {"kind": "file", "sha256": hashlib.sha256(data).hexdigest(), "mode": mode}
        elif target is not None:
            after = {"kind": "symlink", "target": target}
        else:
            after = {"kind": "missing"}
        entry["after"] = after
        self.operation(entry)
        if data is not None:
            atomic_write(path, data, mode, temporary=temporary)
        elif target is not None:
            try:
                os.symlink(target, temporary)
                os.replace(temporary, path)
                fsync_dir(path.parent)
            finally:
                if os.path.lexists(temporary):
                    temporary.unlink()
        elif os.path.lexists(path):
            path.unlink()
            fsync_dir(path.parent)
        self.checkpoint("replace:" + self.relative(path))

    def stop_unit(self, name, *, disable=False):
        markers = (OLD_MARKER,) if name in UNIT_MAP else (V3_MARKER, NEW_MARKER)
        self.check_marked(self.unit_dir / name, [marker + (" Heartbeat" if "heartbeat" in name else "") for marker in markers])
        self.unit_identity(name, missing_ok=True)
        self.systemctl("stop", name)
        if disable:
            self.systemctl("disable", name)
        current = self.unit_state(name, missing_ok=True)
        if current["active"] or disable and current["enabled"] == "enabled":
            raise MigrationError("未确认旧服务已停止或自启已解除，未搬动数据。")

    @staticmethod
    def stop_order(units, key):
        return sorted(units, key=lambda item: (0 if item[key].endswith("heartbeat.timer") else 1 if "heartbeat" in item[key] else 2, item[key]))

    def restore_units(self, units, key):
        # Restore enablement separately; an inactive enabled service stays inactive.
        for item in units:
            if item["enabled"] == "enabled" and self.systemctl("enable", item[key]).returncode:
                raise MigrationError("恢复服务自启状态失败，正在保留或恢复原安装。")
        ordered = sorted(units, key=lambda item: ("heartbeat" in item[key], item[key].endswith(".timer"), item[key]))
        for item in ordered:
            if "heartbeat" in item[key]:
                self.release_heartbeat_lock()
            if item["active"] and self.systemctl("start", item[key]).returncode:
                raise MigrationError("恢复服务运行状态失败，正在保留或恢复原安装。")
            current = self.unit_state(item[key])
            completed_oneshot = item["active"] and item[key].endswith("heartbeat.service") and not current["active"] and "Type=oneshot" in (self.unit_dir / item[key]).read_text().splitlines()
            if current["enabled"] != item["enabled"] or current["active"] != item["active"] and not completed_oneshot:
                raise MigrationError("服务状态未按原设置恢复，正在保留或恢复原安装。")
            self.checkpoint("restored:" + item[key])

    def install_files(self, bundle, plan):
        self.mkdir(self.local)
        if plan["oldApp"]:
            self.move(self.old_app, self.app)
        else:
            self.mkdir(self.app)
        if plan["oldCfg"]:
            self.move(self.old_cfg, self.cfg)
        for relative, target in plan["oldLinks"]:
            if relative != "cli" and target.startswith(str(self.old_app) + "/"):
                self.replace(self.app / relative, target=str(self.app) + target[len(str(self.old_app)):])
        quick = self.app / "bin/start-quick-tunnel"
        if quick.exists():
            original = quick.read_bytes()
            updated = original.replace(OLD_APP.encode(), NEW_APP.encode()) if plan["oldApp"] else original
            if updated.rstrip(b"\n") in (V3_QUICK.rstrip(b"\n"), PREVIOUS_QUICK.rstrip(b"\n")):
                updated = QUICK
            if updated != original:
                self.replace(quick, data=updated, mode=stat.S_IMODE(quick.stat().st_mode))
        heartbeat = self.cfg / "heartbeat.json"
        if plan["oldCfg"] and heartbeat.exists():
            try:
                value = json.loads(heartbeat.read_bytes())
                if not isinstance(value, dict) or value.get("leasePrefix", "isb") not in ("ib", "isb"):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise MigrationError("旧保活配置格式异常，未重建或丢弃现有授权记录。") from None
            if "leasePrefix" not in value:
                value["leasePrefix"] = "isb"
                self.replace(heartbeat, data=(json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(), preserve_live=True)
        releases = self.app / "tool-releases"
        self.mkdir(releases)
        release = releases / (plan["ref"] + "-" + uuid.uuid4().hex[:12])
        self.operation({"kind": "tree", "path": self.relative(release)})
        release.mkdir(mode=0o700)
        for name in (*FILES, "SHA256SUMS"):
            atomic_write(release / name, (bundle / name).read_bytes(), 0o600 if name == "SHA256SUMS" else 0o700)
        cli = self.app / "cli"
        if cli.is_dir() and not cli.is_symlink():
            self.move(cli, self.app / ("cli-before-3.0-" + uuid.uuid4().hex[:12]))
        self.replace(cli, target=str(release))
        for item in plan["units"]:
            old, new = self.unit_dir / item["old"], self.unit_dir / item["new"]
            data = old.read_bytes().replace(OLD_MARKER.encode(), NEW_MARKER.encode())
            data = data.replace(b"Description=Insta-Sing-box", b"Description=InstaBox Tool")
            data = data.replace(OLD_APP.encode(), NEW_APP.encode()).replace(OLD_CFG.encode(), NEW_CFG.encode())
            for old_name, new_name in UNIT_MAP.items():
                data = data.replace(old_name.encode(), new_name.encode())
            self.replace(new, data=data, mode=stat.S_IMODE(old.stat().st_mode))
            self.replace(old)
        wrapper = '''#!/usr/bin/env bash
# Managed-by: InstaBox Tool CLI
if [[ -e "$HOME/.local/share/.insta-box-migration/busy" && "${1:-}" != --version ]]; then
  printf '%s\\n' 'InstaBox Tool 正在迁移，请稍后再打开菜单。' >&2
  exit 75
fi
exec bash "$HOME/.local/share/insta-box/cli/ibt.sh" "$@"
'''
        self.replace(self.local / "ibt", data=wrapper.encode(), mode=0o700)
        version = self.command(["bash", str(self.local / "ibt"), "--version"], timeout=20)
        if version.returncode or (version.stdout or "").strip() != VERSION:
            raise MigrationError("新 ibt 入口验证失败，正在恢复原安装。")
        login = next((name for name in (".bash_profile", ".bash_login", ".profile") if (self.home / name).exists()), ".profile")
        for name in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc"):
            path = self.home / name
            if not path.exists() and name not in (".bashrc", login):
                continue
            original = path.read_bytes() if path.exists() else b""
            updated = original.replace(OLD_PATH_LINE, NEW_PATH_LINE).replace(V3_PATH_LINE, NEW_PATH_LINE)
            if name in (".bashrc", login) and NEW_PATH_LINE not in updated.splitlines():
                updated += b"\n" + NEW_PATH_LINE + b"\n"
            if updated != original:
                self.replace(path, data=updated, mode=stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600)
        for name in plan["ownedLegacyWrappers"]:
            old_wrapper = self.local / name
            bridge = '''#!/usr/bin/env bash
# Managed-by: InstaBox Tool migration bridge
old="$HOME/.local/bin/LEGACY_COMMAND"
if [[ -f "$old" && ! -L "$old" && -O "$old" ]] && grep -Fqx '# Managed-by: InstaBox Tool migration bridge' "$old"; then
  rm -f -- "$old" || exit 1
fi
exec "$HOME/.local/bin/ibt" "$@"
'''.replace("LEGACY_COMMAND", name)
            self.replace(old_wrapper, data=bridge.encode(), mode=0o700)

    def rollback_replace(self, entry):
        path = self.path(entry["path"])
        self.check_parents(path)
        temporary = self.path(entry["temporary"])
        if os.path.lexists(temporary):
            owned(temporary, allow_link=True)
            if temporary.is_symlink() and os.readlink(temporary) != entry["after"].get("target"):
                raise MigrationError("迁移临时链接已被更改，未自动删除。")
            temporary.unlink()
        owned(path, allow_link=True)
        current, before, after = fingerprint(path), entry["before"], entry["after"]
        if current == before:
            return
        if current != after and current["kind"] != "missing":
            if entry.get("preserveLive") and current["kind"] == "file":
                # A new heartbeat may have durably recorded a non-idempotent token
                # intent. Keep its current bytes and move them back with the CFG.
                return
            raise MigrationError("迁移后文件出现额外修改，未覆盖；已保留恢复记录。")
        if before["kind"] == "missing":
            if os.path.lexists(path):
                path.unlink()
        elif before["kind"] == "file":
            backup = self.work / entry["backup"]
            owned(backup, private=True)
            original = backup.read_bytes()
            if hashlib.sha256(original).hexdigest() != before["sha256"]:
                raise MigrationError("迁移备份校验失败，未用损坏备份覆盖当前文件。")
            atomic_write(path, original, before["mode"], temporary=temporary)
        elif before["kind"] == "symlink":
            if os.path.lexists(path):
                path.unlink()
            os.symlink(before["target"], path)
        fsync_dir(path.parent)

    def rollback(self):
        self.check_recovery_paths()
        units = self.journal.get("units", [])
        for item in self.stop_order(units, "new"):
            self.stop_unit(item["new"], disable=item["enabled"] == "enabled")
        if self.heartbeat_fd is None:
            cfg = self.cfg if self.cfg.exists() else self.old_cfg
            if cfg.exists():
                self.lock_file(cfg / "heartbeat.lock", heartbeat=True)
        while self.journal["ops"]:
            entry = self.journal["ops"][-1]
            kind = entry["kind"]
            if kind == "replace":
                self.rollback_replace(entry)
            elif kind == "move":
                source, destination = self.path(entry["source"]), self.path(entry["destination"])
                for path in (source, destination):
                    if os.path.lexists(path):
                        owned(path, directory=True)
                if source.exists() and destination.exists():
                    raise MigrationError("迁移两侧目录都有数据，未自动覆盖；请保留恢复记录。")
                if destination.exists():
                    os.rename(destination, source)
                    fsync_dir(source.parent)
            elif kind == "tree":
                path = self.path(entry["path"])
                if path.exists():
                    self.check_tree(path)
                    shutil.rmtree(path)
            elif kind == "mkdir":
                path = self.path(entry["path"])
                if path.exists():
                    try:
                        path.rmdir()
                    except OSError:
                        raise MigrationError("新建目录出现额外文件，已保留现场供恢复。") from None
            self.journal["ops"].pop()
            self.save_journal()
        if units:
            if self.systemctl("daemon-reload").returncode:
                raise MigrationError("恢复旧服务定义后重新加载失败，已保留恢复记录。")
            self.restore_units(units, "old")
        self.journal["phase"] = "rolled_back"
        self.save_journal()
        self.cleanup_work()

    def cleanup_work(self):
        """Delete the durable decision last so interrupted cleanup stays resumable."""
        for path in self.work.iterdir():
            if path.name == "journal.json":
                continue
            if path.name != "busy" and not re.fullmatch(r"backup-[0-9]+|\.ib-write-[A-Za-z0-9_-]+", path.name):
                raise MigrationError("迁移目录出现未知文件，未清理该文件。")
            owned(path, private=True)
            path.unlink()
        fsync_dir(self.work)
        self.journal_path.unlink()
        self.work.rmdir()
        fsync_dir(self.work.parent)

    def validate_operation(self, entry):
        kind = entry.get("kind")
        for key in ("path", "source", "destination"):
            if key in entry:
                self.path(entry[key])
        if kind == "tree":
            allowed = re.fullmatch(re.escape(NEW_APP) + r"/tool-releases/[a-f0-9]{40}-[a-f0-9]{12}", entry.get("path", ""))
        elif kind == "move":
            pair = (entry.get("source"), entry.get("destination"))
            allowed = pair in ((OLD_APP, NEW_APP), (OLD_CFG, NEW_CFG)) or pair[0] == NEW_APP + "/cli" and re.fullmatch(re.escape(NEW_APP) + r"/cli-before-3\.0-[a-f0-9]{12}", pair[1] or "")
        elif kind == "mkdir":
            allowed = entry.get("path") in (".local", ".local/bin", ".local/share", NEW_APP, NEW_APP + "/tool-releases")
        elif kind == "replace":
            temporary = entry.get("temporary")
            if not isinstance(temporary, str) or Path(temporary).parent != Path(entry.get("path", "")).parent or not re.fullmatch(r"\.ib-(?:write|link)-[a-f0-9]{32}", Path(temporary).name):
                raise ValueError()
            self.path(temporary)
            allowed_paths = {".local/bin/ibt", ".local/bin/ib", ".local/bin/isb", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc",
                             NEW_APP + "/cli", NEW_APP + "/bin/start-quick-tunnel", NEW_CFG + "/heartbeat.json"}
            allowed_paths.update(".config/systemd/user/" + name for name in (*UNIT_MAP, *UNIT_MAP.values()))
            before, after = entry.get("before", {}), entry.get("after", {})
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise ValueError()
            allowed = entry.get("path") in allowed_paths
            if not allowed and str(entry.get("path", "")).startswith(NEW_APP + "/") and before.get("kind") == after.get("kind") == "symlink":
                original = before.get("target", "")
                allowed = isinstance(original, str) and original.startswith(str(self.old_app) + "/") and after.get("target") == str(self.app) + original[len(str(self.old_app)):]
            for item in (before, after):
                if item.get("kind") not in ("missing", "file", "symlink"):
                    raise ValueError()
                if item["kind"] == "file" and (not isinstance(item.get("mode"), int) or not 0 <= item["mode"] <= 0o777 or not re.fullmatch(r"[a-f0-9]{64}", str(item.get("sha256", "")))):
                    raise ValueError()
                if item["kind"] == "symlink" and not isinstance(item.get("target"), str):
                    raise ValueError()
            if before["kind"] == "file" and not re.fullmatch(r"backup-[0-9]+", str(entry.get("backup", ""))):
                raise ValueError()
            if entry.get("preserveLive") and entry.get("path") != NEW_CFG + "/heartbeat.json":
                raise ValueError()
        else:
            allowed = False
        if not allowed:
            raise ValueError()

    def check_recovery_paths(self):
        for path in (self.old_app, self.app, self.old_cfg, self.cfg):
            self.check_parents(path)
            if os.path.lexists(path):
                owned(path, directory=True)
        for entry in self.journal["ops"]:
            for key in ("path", "source", "destination", "temporary"):
                if key in entry:
                    self.check_parents(self.path(entry[key]))
        self.check_parents(self.unit_dir / "placeholder")

    def recover(self):
        if not os.path.lexists(self.work):
            return
        self.check_tree(self.work, private=True)
        if not owned(self.journal_path, private=True):
            if not any(self.work.iterdir()):
                self.work.rmdir()
                return
            raise MigrationError("发现不完整迁移目录，已保留现场；请检查后重试。")
        try:
            self.journal = json.loads(self.journal_path.read_bytes())
            if self.journal.get("schema") != 1 or not isinstance(self.journal.get("ops"), list) or not isinstance(self.journal.get("units"), list):
                raise ValueError()
            for entry in self.journal["ops"]:
                self.validate_operation(entry)
            for item in self.journal["units"]:
                if UNIT_MAP.get(item.get("old")) != item.get("new") or item.get("enabled") not in ("enabled", "disabled", "static") or not isinstance(item.get("active"), bool):
                    raise ValueError()
        except (ValueError, UnicodeError, AttributeError, TypeError):
            raise MigrationError("迁移恢复记录格式异常，未继续修改。") from None
        self.check_recovery_paths()
        if self.journal.get("phase") in ("committed", "rolled_back"):
            self.cleanup_work()
            return
        self.say("发现上次未完成的安装，先恢复原入口和服务状态。")
        self.acquire_data_locks()
        self.rollback()
        self.release_locks()

    def install(self, bundle, ref):
        bundle = Path(bundle).absolute()
        with self.installation_lock():
            try:
                self.recover()
                plan = self.preflight(bundle, ref)
                self.acquire_data_locks()
                self.work.mkdir(mode=0o700)
                fsync_dir(self.work.parent)
                self.journal = {"schema": 1, "phase": "prepared", "units": plan["units"], "ops": []}
                self.save_journal()
                atomic_write(self.work / "busy", b"in-progress\n")
                commit_attempted = False
                committed_durable = False
                try:
                    for name in plan["ownedLegacyWrappers"]:
                        old_wrapper = self.local / name
                        self.check_marked(old_wrapper, self.legacy_wrapper_markers(name))
                        busy = "#!/usr/bin/env bash\n# Managed-by: InstaBox Tool migration lock\nprintf '%s\\n' 'InstaBox Tool 正在迁移，请稍后重试。' >&2\nexit 75\n".encode()
                        self.replace(old_wrapper, data=busy, mode=0o700)
                    for item in self.stop_order(plan["units"], "old"):
                        self.stop_unit(item["old"], disable=item["enabled"] == "enabled")
                    self.install_files(bundle, plan)
                    self.journal["phase"] = "files_ready"
                    self.save_journal()
                    if plan["units"]:
                        if self.systemctl("daemon-reload").returncode:
                            raise MigrationError("新服务定义加载失败，正在恢复原安装。")
                        self.restore_units(plan["units"], "new")
                    commit_attempted = True
                    self.journal["phase"] = "committed"
                    self.save_journal()
                    committed_durable = True
                    (self.work / "busy").unlink()
                    fsync_dir(self.work)
                    self.checkpoint("committed")
                    self.cleanup_work()
                except (Exception, KeyboardInterrupt):
                    if commit_attempted and not committed_durable:
                        # atomic_write can fail before or after replacing the
                        # journal. The in-memory phase cannot decide recovery.
                        try:
                            owned(self.journal_path, private=True)
                            recorded = json.loads(self.journal_path.read_bytes())
                            if isinstance(recorded, dict) and recorded.get("phase") == "committed" and recorded == self.journal:
                                committed_durable = True
                            elif recorded == {**self.journal, "phase": "files_ready"}:
                                self.journal = recorded
                            else:
                                raise ValueError()
                        except (OSError, ValueError, UnicodeError, MigrationError):
                            raise MigrationError("安装提交状态未确认；未报告成功或回退，数据和私有恢复记录已保留，请重新运行同一安装命令检查。") from None
                    if committed_durable:
                        busy = self.work / "busy"
                        if os.path.lexists(busy):
                            try:
                                owned(busy, private=True)
                                busy.unlink()
                                fsync_dir(self.work)
                            except (OSError, MigrationError):
                                raise MigrationError("安装已提交，但入口尚未解除迁移锁；请重新运行同一安装命令完成清理。") from None
                        self.say("安装已完成；迁移备份尚未清理，下次更新会继续清理。")
                        return 0
                    try:
                        self.rollback()
                    except Exception:
                        raise MigrationError("迁移未完成，自动恢复也尚未确认；数据和私有恢复记录已保留，请重新运行同一安装命令继续恢复。") from None
                    raise
            finally:
                self.release_locks()
        self.say("管理工具已准备。")
        return 0


def main(args=None):
    parser = argparse.ArgumentParser(description="Verified InstaBox Tool installer migration")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--ref", required=True)
    options = parser.parse_args(args)
    if os.geteuid() == 0:
        print("  [失败] 请使用普通用户，不要加 sudo。", file=sys.stderr)
        return 1
    try:
        return Installer().install(options.bundle, options.ref)
    except KeyboardInterrupt:
        print("  [失败] 安装已中断；请重新运行同一命令检查恢复状态。", file=sys.stderr)
        return 130
    except MigrationError as error:
        print("  [失败] " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("  [失败] 本地安装未完成；未输出私有数据，请重新运行同一命令检查恢复状态。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
