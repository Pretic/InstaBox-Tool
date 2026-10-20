"""Offline timezone preference tests; no host timezone or privileges changed."""

import datetime as dt
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ui_time as ui


class TimezoneTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ibt-time-", dir=ROOT.parent)
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir(mode=0o700)
        self.folder = self.home / ".config/insta-box"
        self.record = self.folder / ui.FILENAME
        self.config = ui.TimezoneConfig(self.home)
        self.now = dt.datetime(2026, 10, 20, 11, 30, tzinfo=dt.timezone.utc)

    def command(self, *args, environment=None, **kwargs):
        output, errors = [], []
        result = ui.main(args, home=self.home, environment={} if environment is None else environment,
                         output=output.append, error=errors.append, now=kwargs.pop("now", self.now),
                         system_zone=kwargs.pop("system_zone", dt.timezone.utc), **kwargs)
        return result, "\n".join(output), "\n".join(errors)

    def private(self, value, mode=0o600):
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.record.write_bytes(value.encode() if isinstance(value, str) else value)
        self.record.chmod(mode)

    def test_valid_iana_names_and_invalid_path_or_shell_content(self):
        for value in ("UTC", "Asia/Shanghai", "America/New_York", "Europe/London", "Etc/GMT+8"):
            with self.subTest(value=value):
                self.assertTrue(ui.valid_timezone(value))
        for value in ("", "localtime", "CST-8", "EST5EDT", "No/Such_Zone", "/etc/localtime", "../UTC",
                      "America/../New_York", "Asia//Shanghai", "Asia/Shanghai\n", "Asia/Shanghai\r",
                      "Asia/Shanghai\x1b[31m", " Asia/Shanghai", "UTC; touch sentinel", "$(id)",
                      "`id`", ":Asia/Shanghai", "界/面", "A/" + "x" * 129, None, 4):
            with self.subTest(value=value):
                self.assertFalse(ui.valid_timezone(value))

    def test_env_and_status_without_preference_do_not_create_files(self):
        self.assertEqual(self.command("env"), (0, "", ""))
        result, output, error = self.command("status")
        self.assertEqual(result, 0)
        self.assertEqual(error, "")
        self.assertIn("工具设置： 跟随系统时区", output)
        self.assertIn("生效来源： 系统默认", output)
        self.assertIn("2026-10-20 11:30:00 UTC+00:00", output)
        self.assertFalse((self.home / ".config").exists())

    def test_set_stores_one_private_iana_value_and_env_reads_it(self):
        result, output, error = self.command("set", "Asia/Shanghai")
        self.assertEqual(result, 0, error)
        self.assertIn("系统时区未修改", output)
        self.assertEqual(self.record.read_bytes(), b"Asia/Shanghai\n")
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.record.stat().st_mode), 0o600)
        self.assertEqual(self.command("env"), (0, "Asia/Shanghai", ""))
        self.assertEqual(self.command("env", environment={"TZ": ""}), (0, "Asia/Shanghai", ""))

    def test_explicit_timezone_overrides_saved_and_does_not_need_to_read_it(self):
        self.private("malformed\n")
        self.assertEqual(self.command("env", environment={"TZ": "America/New_York"}), (0, "America/New_York", ""))
        self.assertEqual(self.record.read_bytes(), b"malformed\n")

    def test_invalid_environment_falls_back_without_echoing_payload(self):
        value = "$(touch /tmp/PRIVATE_SENTINEL)\x1b[31m"
        result, output, error = self.command("env", environment={"TZ": value})
        self.assertEqual(result, 2)
        self.assertEqual(output, "")
        self.assertIn("已忽略", error)
        self.assertNotIn(value, error)
        self.assertNotIn("PRIVATE_SENTINEL", error)
        self.assertFalse((self.home / ".config").exists())
        self.config.set("Asia/Shanghai")
        result, output, error = self.command("env", environment={"TZ": value})
        self.assertEqual((result, output), (0, "Asia/Shanghai"))
        self.assertIn("已忽略", error)

    def test_saved_display_time_and_os_time_are_separate(self):
        self.config.set("Asia/Shanghai")
        result, output, error = self.command("status")
        self.assertEqual(result, 0, error)
        self.assertIn("工具设置： Asia/Shanghai", output)
        self.assertIn("环境覆盖： 未设置", output)
        self.assertIn("系统时区： UTC+00:00", output)
        self.assertIn("生效来源： 工具设置", output)
        self.assertIn("显示时区： Asia/Shanghai · UTC+08:00", output)
        self.assertIn("2026-10-20 19:30:00 UTC+08:00", output)
        for line in output.splitlines()[:-1]:
            self.assertEqual(line.index("："), 6)

    def test_explicit_override_is_identified_even_when_preference_differs(self):
        self.config.set("Asia/Shanghai")
        result, output, error = self.command("status", environment={"TZ": "America/New_York"})
        self.assertEqual(result, 0, error)
        self.assertIn("工具设置： Asia/Shanghai", output)
        self.assertIn("环境覆盖： America/New_York · UTC-04:00", output)
        self.assertIn("生效来源： 环境指定", output)
        self.assertIn("2026-10-20 07:30:00 UTC-04:00", output)

    def test_dst_is_computed_at_the_requested_instant(self):
        self.config.set("America/New_York")
        winter = self.command("status", now=dt.datetime(2026, 1, 20, 12, tzinfo=dt.timezone.utc))
        summer = self.command("status", now=dt.datetime(2026, 7, 20, 12, tzinfo=dt.timezone.utc))
        self.assertIn("2026-01-20 07:00:00 UTC-05:00", winter[1])
        self.assertIn("2026-07-20 08:00:00 UTC-04:00", summer[1])
        first = self.command("status", now=dt.datetime(2026, 11, 1, 5, 30, tzinfo=dt.timezone.utc))
        second = self.command("status", now=dt.datetime(2026, 11, 1, 6, 30, tzinfo=dt.timezone.utc))
        self.assertIn("2026-11-01 01:30:00 UTC-04:00", first[1])
        self.assertIn("2026-11-01 01:30:00 UTC-05:00", second[1])

    def test_reset_removes_only_timezone_and_keeps_environment_precedence(self):
        self.config.set("Asia/Shanghai")
        unrelated = self.folder / "api-key"
        unrelated.write_text("fixture-only")
        self.assertEqual(self.command("reset")[0], 0)
        self.assertFalse(self.record.exists())
        self.assertEqual(unrelated.read_text(), "fixture-only")
        self.assertTrue(self.folder.is_dir())
        self.assertEqual(self.command("env"), (0, "", ""))
        self.assertEqual(self.command("env", environment={"TZ": "UTC"}), (0, "UTC", ""))

    def test_reset_without_record_does_not_create_directories(self):
        self.assertEqual(self.command("reset")[0], 0)
        self.assertFalse((self.home / ".config").exists())

    def test_invalid_set_is_rejected_before_creating_directories(self):
        result, output, error = self.command("set", "Asia/../Shanghai")
        self.assertEqual(result, 2)
        self.assertEqual(output, "")
        self.assertIn("IANA", error)
        self.assertFalse((self.home / ".config").exists())

    def test_invalid_file_contents_are_not_interpreted_or_echoed(self):
        for value in (b"UTC\nUTC\n", b"", b"UTC\r\n", b" UTC\n", b"Asia/Shanghai\n\n",
                      b"X" * 257, b"\xff", b"TZ=Asia/Shanghai", b"$(touch PRIVATE_SENTINEL)\n"):
            with self.subTest(value=value):
                self.private(value)
                result, output, error = self.command("env")
                self.assertEqual(result, 2)
                self.assertEqual(output, "")
                self.assertNotIn("PRIVATE_SENTINEL", error)
                self.assertEqual(self.record.read_bytes(), value)
        self.assertEqual(self.command("set", "UTC")[0], 0)
        self.assertEqual(self.config.read(), "UTC")

    def test_file_links_and_public_permissions_are_rejected_for_every_operation(self):
        outside = self.home / "outside"
        outside.write_text("UTC\n")
        outside.chmod(0o600)
        self.folder.mkdir(parents=True, mode=0o700)
        for kind in ("symlink", "hardlink", "public", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.record.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, self.record)
                elif kind == "public":
                    self.private("UTC\n", 0o644)
                else:
                    self.record.mkdir()
                for arguments in (("env",), ("set", "Asia/Shanghai"), ("reset",)):
                    self.assertEqual(self.command(*arguments)[0], 2)
                self.assertEqual(outside.read_text(), "UTC\n")
                if self.record.is_dir() and not self.record.is_symlink():
                    self.record.rmdir()
                else:
                    self.record.unlink()

    def test_unsafe_ancestors_do_not_allow_reads_or_mutations(self):
        self.config.set("UTC")
        for path, mode in ((self.home, 0o777), (self.home / ".config", 0o775), (self.folder, 0o755)):
            with self.subTest(path=path):
                original = stat.S_IMODE(path.stat().st_mode)
                path.chmod(mode)
                try:
                    for arguments in (("env",), ("set", "Asia/Shanghai"), ("reset",)):
                        self.assertEqual(self.command(*arguments)[0], 2)
                    self.assertEqual(self.record.read_bytes(), b"UTC\n")
                finally:
                    path.chmod(original)

    def test_symlinked_directory_and_wrong_owner_are_rejected(self):
        outside = self.home / "outside-config"
        outside.mkdir(mode=0o700)
        (self.home / ".config").symlink_to(outside, target_is_directory=True)
        for arguments in (("env",), ("set", "UTC"), ("reset",)):
            self.assertEqual(self.command(*arguments)[0], 2)
        self.assertEqual(list(outside.iterdir()), [])
        (self.home / ".config").unlink()
        with mock.patch.object(ui.os, "getuid", return_value=os.getuid() + 1):
            self.assertEqual(self.command("set", "UTC")[0], 2)

    def test_failed_publish_keeps_previous_value_and_cleans_temporary_file(self):
        self.config.set("UTC")
        with mock.patch.object(ui.os, "replace", side_effect=OSError("private raw error")):
            result, output, error = self.command("set", "Asia/Shanghai")
        self.assertEqual(result, 2)
        self.assertEqual(self.config.read(), "UTC")
        self.assertNotIn("private raw error", error)
        self.assertEqual({path.name for path in self.folder.iterdir()}, {ui.FILENAME})

    def test_environment_and_system_settings_are_never_modified(self):
        environment = {"TZ": "America/New_York", "PATH": "private-placeholder"}
        original = dict(environment)
        with mock.patch.dict(os.environ, {"TZ": "Etc/GMT+8"}):
            parent = dict(os.environ)
            self.assertEqual(self.command("set", "Asia/Shanghai", environment=environment)[0], 0)
            self.assertEqual(self.command("status", environment=environment)[0], 0)
            self.assertEqual(self.command("reset", environment=environment)[0], 0)
            self.assertEqual(dict(os.environ), parent)
        self.assertEqual(environment, original)

    def test_status_with_invalid_preference_reports_unknown_without_raw_contents(self):
        self.private("PRIVATE_SENTINEL\x1b[31m\n")
        result, output, error = self.command("status")
        self.assertEqual(result, 2)
        self.assertIn("工具设置： 配置无法读取", output)
        self.assertIn("生效来源： 系统默认", output)
        self.assertNotIn("PRIVATE_SENTINEL", output + error)
        self.assertNotIn("\x1b", output + error)

    def test_naive_time_and_invalid_arguments_have_safe_errors(self):
        self.assertEqual(self.command("status", now=dt.datetime(2026, 1, 1))[0], 2)
        result, output, error = self.command("--PRIVATE_SENTINEL\x1b[31m")
        self.assertEqual(result, 2)
        self.assertEqual(output, "")
        self.assertNotIn("PRIVATE_SENTINEL", error)
        self.assertNotIn("\x1b", error)


if __name__ == "__main__":
    unittest.main()
