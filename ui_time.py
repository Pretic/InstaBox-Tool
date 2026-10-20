#!/usr/bin/env python3
# Author: Pre
"""A private, user-scoped display timezone; never changes the system timezone.

``env`` emits only a validated IANA name, for the parent CLI to export as TZ.
An explicit valid TZ environment value wins over the stored preference. The
parent must retain its original environment when refreshing after set/reset.
"""

import argparse
import datetime as dt
import io
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


FILENAME = "display-timezone"
MAX_BYTES = 256
NAME = re.compile(r"(?:UTC|[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+)\Z")


class TimezoneError(Exception):
    """Only fixed, locally composed messages are displayed."""


def valid_timezone(value):
    if not isinstance(value, str) or len(value) > 128 or not NAME.fullmatch(value):
        return False
    try:
        ZoneInfo(value)
        return True
    except (ValueError, ZoneInfoNotFoundError, OSError):
        return False


class TimezoneConfig:
    def __init__(self, home=None):
        self.home = Path(home) if home is not None else Path.home()

    @staticmethod
    def check_directory(fd, *, private=False):
        info = os.fstat(fd)
        prohibited = 0o077 if private else 0o022
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & prohibited:
            raise TimezoneError("时区配置目录的归属或权限异常，未修改。")

    def directory(self, create=False):
        """Return an owned directory fd; traverse children without symlinks."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors = []
        try:
            descriptors.append(os.open(self.home, flags))
            self.check_directory(descriptors[-1])
            for name, private in ((".config", False), ("insta-box", True)):
                try:
                    child = os.open(name, flags, dir_fd=descriptors[-1])
                except FileNotFoundError:
                    if not create:
                        return None
                    try:
                        os.mkdir(name, 0o700, dir_fd=descriptors[-1])
                    except FileExistsError:
                        pass
                    child = os.open(name, flags, dir_fd=descriptors[-1])
                descriptors.append(child)
                self.check_directory(child, private=private)
            return descriptors.pop()
        except TimezoneError:
            raise
        except OSError:
            raise TimezoneError("时区配置目录无法安全读取，未修改。") from None
        finally:
            for fd in descriptors:
                os.close(fd)

    @staticmethod
    def existing(directory):
        try:
            info = os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise TimezoneError("时区配置必须是当前用户的独立私有文件，未修改。")
        return info

    def read(self):
        directory = self.directory()
        if directory is None:
            return None
        try:
            before = self.existing(directory)
            if before is None:
                return None
            fd = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                after = os.fstat(fd)
                if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                        or not stat.S_ISREG(after.st_mode) or after.st_uid != os.getuid()
                        or after.st_nlink != 1 or stat.S_IMODE(after.st_mode) & 0o077):
                    raise TimezoneError("时区配置在读取时发生变化，请重试。")
                if after.st_size > MAX_BYTES:
                    raise TimezoneError("时区配置内容无效，请重新设置显示时区。")
                raw = os.read(fd, MAX_BYTES + 1)
            finally:
                os.close(fd)
            if len(raw) > MAX_BYTES:
                raise TimezoneError("时区配置内容无效，请重新设置显示时区。")
            try:
                value = raw.decode("ascii")
            except UnicodeDecodeError:
                raise TimezoneError("时区配置内容无效，请重新设置显示时区。") from None
            if value.endswith("\n"):
                value = value[:-1]
            if not valid_timezone(value):
                raise TimezoneError("时区配置内容无效，请重新设置显示时区。")
            return value
        except TimezoneError:
            raise
        except OSError:
            raise TimezoneError("时区配置无法安全读取，未显示原始内容。") from None
        finally:
            os.close(directory)

    def set(self, value):
        if not valid_timezone(value):
            raise TimezoneError("请输入有效 IANA 时区，例如 Asia/Shanghai、America/New_York 或 UTC。")
        directory = self.directory(create=True)
        temporary = ".display-timezone-" + secrets.token_hex(12)
        created = False
        try:
            before = self.existing(directory)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            created = True
            try:
                os.fchmod(fd, 0o600)
                payload = (value + "\n").encode("ascii")
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            current = self.existing(directory)
            identity = lambda item: None if item is None else (item.st_dev, item.st_ino, item.st_mtime_ns, item.st_size)
            if identity(before) != identity(current):
                raise TimezoneError("时区配置被另一操作更改，请重试。")
            os.replace(temporary, FILENAME, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
            os.fsync(directory)
        except TimezoneError:
            raise
        except OSError:
            raise TimezoneError("显示时区保存未完成，请重新查看设置后重试。") from None
        finally:
            if created:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except OSError:
                    pass
            os.close(directory)

    def reset(self):
        directory = self.directory()
        if directory is None:
            return False
        try:
            if self.existing(directory) is None:
                return False
            os.unlink(FILENAME, dir_fd=directory)
            os.fsync(directory)
            return True
        except TimezoneError:
            raise
        except OSError:
            raise TimezoneError("显示时区重置未完成，请重新查看设置后重试。") from None
        finally:
            os.close(directory)


def environment_timezone(environment, error):
    value = environment.get("TZ")
    if value in (None, ""):
        return None, False
    if valid_timezone(value):
        return value, False
    error("  [提示] 环境 TZ 不是有效 IANA 时区，已忽略该值。")
    return None, True


def emit_environment(config, environment, output, error):
    selected, invalid = environment_timezone(environment, error)
    if selected is not None:
        output(selected)
        return 0
    saved = config.read()
    if saved is not None:
        output(saved)
        return 0
    return 2 if invalid else 0


def system_timezone():
    """Read the OS zone independently of an inherited TZ override."""
    try:
        with open("/etc/localtime", "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                return None
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            return None
        return ZoneInfo.from_file(io.BytesIO(raw))
    except (OSError, ValueError):
        return None


def utc_offset(moment):
    value = moment.utcoffset()
    if value is None:
        return "UTC 偏移未读取"
    seconds = int(value.total_seconds())
    sign = "+" if seconds >= 0 else "-"
    minutes, extra = divmod(abs(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return "UTC" + sign + f"{hours:02d}:{minutes:02d}" + (f":{extra:02d}" if extra else "")


def zone_description(zone, now):
    if zone is None:
        return "未读取"
    moment = now.astimezone(zone)
    abbreviation = moment.tzname() or ""
    abbreviation = re.sub(r"[^A-Za-z0-9_+-]", "", abbreviation)[:24]
    return utc_offset(moment) + ("（" + abbreviation + "）" if abbreviation else "")


def show_status(config, environment, output, error, now, system_zone):
    selected, invalid_environment = environment_timezone(environment, error)
    failed = False
    try:
        saved = config.read()
        stored_label = saved or "跟随系统时区"
    except TimezoneError as problem:
        saved = None
        stored_label = "配置无法读取"
        error("  [提示] " + str(problem))
        failed = True
    source = "环境指定" if selected else "工具设置" if saved else "系统默认"
    effective = selected or saved
    zone = ZoneInfo(effective) if effective else system_zone
    output("  工具设置： " + stored_label)
    output("  环境覆盖： " + (selected + " · " + zone_description(ZoneInfo(selected), now) if selected else "无效，已忽略" if invalid_environment else "未设置"))
    output("  系统时区： " + zone_description(system_zone, now))
    output("  生效来源： " + source)
    output("  显示时区： " + ((effective + " · ") if effective else "") + zone_description(zone, now))
    output("  当前时间： " + (now.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S") + " " + utc_offset(now.astimezone(zone)) if zone is not None else "未读取"))
    output("  此设置只影响本工具显示，系统时区与任务执行时刻保持不变。")
    return 2 if failed or invalid_environment and effective is None else 0


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise TimezoneError("用法：ibt timezone status | set IANA时区 | reset。")


def main(args=None, *, home=None, environment=None, output=print, error=None, now=None, system_zone=None):
    error = error or (lambda message: print(message, file=sys.stderr))
    environment = os.environ if environment is None else environment
    try:
        parser = SafeParser(description="InstaBox Tool 显示时区设置；不修改系统时区。")
        commands = parser.add_subparsers(dest="command")
        commands.add_parser("env")
        commands.add_parser("status")
        commands.add_parser("reset")
        setting = commands.add_parser("set")
        setting.add_argument("timezone")
        arguments = list(sys.argv[1:] if args is None else args)
        try:
            parsed = parser.parse_args(arguments or ["status"])
        except SystemExit as problem:
            return problem.code
        config = TimezoneConfig(home)
        if parsed.command == "env":
            return emit_environment(config, environment, output, error)
        if parsed.command == "set":
            config.set(parsed.timezone)
            output("  已保存显示时区：" + parsed.timezone + "；系统时区未修改。")
            override, _ = environment_timezone(environment, error)
            if override is not None and override != parsed.timezone:
                output("  当前显式 TZ 环境仍优先；清除环境覆盖后使用工具设置。")
            return 0
        if parsed.command == "reset":
            config.reset()
            output("  已清除工具显示时区，恢复跟随系统；显式 TZ 环境仍优先。")
            return 0
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise TimezoneError("无法确定当前时刻，显示时区未确认。")
        if system_zone is None:
            system_zone = system_timezone()
        return show_status(config, environment, output, error, now, system_zone)
    except KeyboardInterrupt:
        error("  时区操作已中断，请重新查看设置。")
        return 130
    except TimezoneError as problem:
        error("  [提示] " + str(problem))
        return 2
    except Exception:
        error("  显示时区操作未完成，未显示配置内容或原始错误。")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
