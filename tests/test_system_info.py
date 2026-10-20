"""Read-only host reports from isolated fixtures; no real system changes."""

import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import system_info as info


GIB = 1024 ** 3


def service(unit, load="loaded", active="active", sub="running", enabled="enabled"):
    return f"Id={unit}\nLoadState={load}\nActiveState={active}\nSubState={sub}\nUnitFileState={enabled}\n"


class SystemInfoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibt-info-", dir=ROOT.parent)
        self.root = Path(self.temp.name)
        self.calls = []
        self.addresses = [
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
            {"ifname": "eth0", "addr_info": [
                {"family": "inet", "local": "192.0.2.5", "prefixlen": 24},
                {"family": "inet6", "local": "2001:db8::5", "prefixlen": 64},
            ]},
        ]
        self.units = "\n".join([
            service(info.UNITS["node"]), service(info.UNITS["quick"], active="failed", sub="failed"),
            service(info.UNITS["fixed"], load="not-found", active="inactive", sub="dead", enabled=""),
            service(info.UNITS["keepalive"], sub="waiting"),
        ])
        self.code = 0
        self.file("/etc/os-release", 'NAME="Debian GNU/Linux"\nVERSION="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n')
        self.file("/etc/timezone", "Etc/UTC\n")
        self.tzfile("Etc/UTC", 0)
        self.tzfile("Asia/Shanghai", 8 * 3600)
        self.host_localtime = self.root / "etc/localtime"
        self.host_localtime.symlink_to("../usr/share/zoneinfo/Etc/UTC")
        self.file("/proc/cpuinfo", "processor : 0\nmodel name : Test CPU 4 Core\n")
        self.file("/proc/uptime", "90061.25 2.0\n")
        self.file("/proc/loadavg", "0.15 0.20 0.25 1/99 500\n")
        self.file("/proc/meminfo", "MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
        self.file("/proc/self/mountinfo", "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /data rw - ext4 /dev/vdb rw\n")
        self.file("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n")
        self.file("/proc/sys/net/core/default_qdisc", "fq\n")
        (self.root / "data").mkdir()
        self.uname = SimpleNamespace(nodename="instabox-test", release="6.18.54-instabox", machine="x86_64")
        self.now = dt.datetime(2026, 10, 20, 19, 30, tzinfo=dt.timezone(dt.timedelta(hours=8)))
        self.host = info.Host(self.root, runner=self.run_command, disk=self.disk, uname=lambda: self.uname,
                              cores=lambda: 4, now=lambda: self.now, finder=lambda name: "/usr/bin/" + name)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, value):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def tzfile(self, name, offset):
        path = self.root / "usr/share/zoneinfo" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"TZif\0" + b"\0" * 15 + struct.pack(">6I", 0, 0, 0, 0, 1, 4) + struct.pack(">lbb", offset, 0, 0) + b"UTC\0")
        return path

    def disk(self, path):
        total = 16 if Path(path) == self.root else 20
        return SimpleNamespace(f_frsize=4096, f_blocks=total * GIB // 4096,
                               f_bfree=(total - 4) * GIB // 4096, f_bavail=(total - 5) * GIB // 4096)

    def run_command(self, argv):
        self.calls.append(argv)
        if Path(argv[0]).name == "systemctl":
            return self.code, self.units
        if argv[1:] == ["-j", "address", "show"]:
            return 0, json.dumps(self.addresses)
        if argv[1:] == ["-j", "-4", "route", "show", "default"]:
            return 0, json.dumps([{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"}])
        if argv[1:] == ["-j", "-6", "route", "show", "default"]:
            return 0, "[]"
        raise AssertionError("Unexpected command: " + repr(argv))

    def test_complete_current_report(self):
        report = self.host.collect()
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["collected_at"], "2026-10-20T19:30:00+08:00")
        self.assertEqual(report["system"]["os"], "Debian GNU/Linux 13 (trixie)")
        self.assertEqual(report["system"]["uptime_seconds"], 90061)
        self.assertEqual(report["cpu"]["logical_cores"], 4)
        self.assertEqual(report["cpu"]["load"], [0.15, 0.2, 0.25])
        self.assertEqual(report["memory"], {"total_bytes": 8 * GIB, "available_bytes": 6 * GIB, "used_bytes": 2 * GIB})
        self.assertEqual(report["swap"], {"total_bytes": 0, "free_bytes": 0, "used_bytes": 0})
        self.assertEqual(report["disks"][0]["available_bytes"], 11 * GIB)
        self.assertEqual(report["disks"][0]["used_bytes"], 4 * GIB)
        self.assertEqual([v["mount"] for v in report["disks"]], ["/", "/data"])
        self.assertEqual(report["services"]["node"]["state"], "running")
        self.assertEqual(report["services"]["quick"]["state"], "failed")
        self.assertEqual(report["services"]["fixed"]["state"], "not_installed")
        self.assertEqual(report["warnings"], [])

    def test_unknown_memory_and_swap_are_not_zero(self):
        self.host.path("/proc/meminfo").unlink()
        report = self.host.collect()
        self.assertTrue(all(v is None for v in report["memory"].values()))
        self.assertTrue(all(v is None for v in report["swap"].values()))
        self.assertIn("内存用量： 未读取 / 未读取", info.render(report))
        self.assertNotIn("未启用（0 B）", info.render(report))

    def test_memory_inconsistency_and_oversized_numbers(self):
        memory, swap = info.memory_values("MemTotal: 2 kB\nMemAvailable: 3 kB\nSwapTotal: 4 kB\nSwapFree: 5 kB\n")
        self.assertEqual(memory["total_bytes"], 2048)
        self.assertIsNone(memory["available_bytes"])
        self.assertIsNone(memory["used_bytes"])
        self.assertIsNone(swap["free_bytes"])
        self.assertIsNone(swap["used_bytes"])
        self.assertIsNone(info.memory_values("MemTotal: " + "9" * 5000 + " kB")[0]["total_bytes"])

    def test_swap_usage_is_reported(self):
        self.file("/proc/meminfo", "MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\nSwapTotal: 2097152 kB\nSwapFree: 1048576 kB\n")
        report = self.host.collect()
        self.assertEqual(report["swap"]["used_bytes"], GIB)
        self.assertIn("交换空间： 1.0 GiB / 2.0 GiB", info.render(report))

    def test_data_directory_is_not_double_counted_without_its_mount(self):
        self.file("/proc/self/mountinfo", "1 0 8:1 / / rw - ext4 /dev/root rw\n")
        self.assertEqual(len(self.host.collect()["disks"]), 1)

    def test_failed_disk_read_does_not_erase_other_fields(self):
        self.host.disk = mock.Mock(side_effect=PermissionError())
        report = self.host.collect()
        self.assertTrue(all(d["state"] == "unavailable" for d in report["disks"]))
        self.assertEqual(report["cpu"]["logical_cores"], 4)
        self.assertIsNone(report["disks"][0]["used_bytes"])

    def test_invalid_disk_counters_are_unknown(self):
        self.host.disk = lambda _: SimpleNamespace(f_frsize=4096, f_blocks=20, f_bfree=30, f_bavail=25)
        self.assertEqual(self.host.disk_info("/")["state"], "unavailable")

    def test_network_contains_valid_local_addresses_only(self):
        self.addresses[1]["addr_info"].extend([
            {"family": "inet", "local": "https://credential.invalid", "prefixlen": 24},
            {"family": "inet", "local": "192.0.2.9", "prefixlen": 129},
            {"family": "inet", "local": "0.0.0.0", "prefixlen": 0},
        ])
        self.addresses.append({"ifname": "bad\nIFACE", "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24}]})
        report = self.host.collect()
        self.assertEqual([v["address"] for v in report["network"]["addresses"]], ["192.0.2.5", "2001:db8::5"])
        self.assertEqual(report["network"]["default_ipv4"], [{"family": 4, "interface": "eth0"}])
        self.assertEqual(report["network"]["default_ipv6"], [])
        self.assertIn("未查询公网出口", info.render(report))

    def test_invalid_json_and_network_shapes_remain_unknown(self):
        for value in (None, "", "{}", "[42]", "[", "[[[[]]]]", "[" + "{}," * 256 + "{}]"):
            with self.subTest(value=str(value)[:30]):
                self.assertIsNone(info.parse_interfaces(value))
                self.assertIsNone(info.parse_routes(value, 4))
        self.assertEqual(info.parse_routes('[{"dst":"192.0.2.0/24","dev":"eth0"}]', 4), [])

    def test_malformed_addresses_do_not_claim_none_and_multipath_routes_are_supported(self):
        text = '[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"fe80::1%bad\\nvalue","prefixlen":64}]}]'
        self.assertIsNone(info.parse_interfaces(text))
        self.assertIsNone(info.parse_routes('[{"dst":"default","dev":"bad\\nvalue"}]', 4))
        self.assertEqual(info.parse_routes('[{"dst":"default","nexthops":[{"dev":"eth0"},{"dev":"eth1"}]}]', 4),
                         [{"family": 4, "interface": "eth0"}, {"family": 4, "interface": "eth1"}])

    def test_command_failure_is_unknown_not_unconfigured(self):
        self.host.runner = lambda _: (1, "unexpected raw error and ibssh_DO_NOT_REPORT")
        report = self.host.collect()
        self.assertIsNone(report["network"]["addresses"])
        self.assertIsNone(report["network"]["default_ipv4"])
        self.assertTrue(all(v["state"] == "unavailable" for v in report["services"].values()))
        self.assertNotIn("ibssh_", info.render(report))
        self.assertNotIn("ibssh_", json.dumps(report))

    def test_service_missing_inactive_and_failed_are_distinct(self):
        self.units = "\n".join([
            service(info.UNITS["node"], active="inactive", sub="dead", enabled="disabled"),
            service(info.UNITS["quick"], active="failed", sub="failed"),
            service(info.UNITS["fixed"], load="not-found"),
        ])
        self.code = 1  # systemctl can return nonzero for one missing unit.
        report = self.host.collect()
        self.assertEqual([report["services"][name]["state"] for name in info.UNITS], ["inactive", "failed", "not_installed", "unavailable"])
        text = info.render(report)
        self.assertIn("节点服务： 未运行 · 自启关闭", text)
        self.assertIn("快捷隧道： 运行失败", text)
        self.assertIn("固定隧道： 尚未配置", text)
        self.assertIn("自动保活： 未读取", text)

    def test_service_duplicates_malformed_and_unrecognized_states_fail_closed(self):
        for text in (
            service(info.UNITS["node"]) + "ActiveState=inactive\n",
            service(info.UNITS["node"]) + "\n" + service(info.UNITS["node"]),
            f"Id={info.UNITS['node']}\nActiveState=active\n",
            service(info.UNITS["node"], active="unknown-new-state"),
            service(info.UNITS["node"], load="error"),
        ):
            self.assertEqual(info.parse_services(text)["node"]["state"], "unavailable")

    def test_transitional_and_masked_service_states(self):
        self.assertEqual(info.parse_services(service(info.UNITS["node"], active="activating"))["node"]["state"], "starting")
        self.assertEqual(info.parse_services(service(info.UNITS["node"], load="masked"))["node"]["state"], "masked")
        self.assertEqual(info.parse_services(service(info.UNITS["node"], active="deactivating"))["node"]["state"], "stopping")
        for enabled in ("linked", "linked-runtime", "static", "alias"):
            self.assertIsNone(info.parse_services(service(info.UNITS["node"], enabled=enabled))["node"]["enabled"])

    def test_reads_do_not_write_and_commands_are_a_fixed_read_only_allowlist(self):
        secret = self.file("/home/user/.config/insta-box/api-key", "SECRET_NEVER_READ")
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with mock.patch.object(self.host, "read", wraps=self.host.read) as reader:
            report = self.host.collect()
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertNotIn(str(secret), repr(reader.call_args_list))
        self.assertNotIn("SECRET_NEVER_READ", json.dumps(report))
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.calls[-1], ["/usr/bin/systemctl", "--user", "show", "--no-pager",
                                         *("--property=" + field for field in info.PROPERTIES), *info.UNITS.values()])
        self.assertTrue(all(Path(argv[0]).name in {"ip", "systemctl"} for argv in self.calls))
        self.assertIsNone(info.Host.find_command("sudo"))
        self.assertIsNone(info.Host.find_command("curl"))

    def test_display_alignment_controls_and_width(self):
        self.uname.nodename = "中文机器" * 60 + "\x1b[31m\rINJECT"
        self.file("/proc/cpuinfo", "model name: CPU\x1b]0;TITLE\x07\n")
        report = self.host.collect()
        text = info.render(report)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("\x07", text)
        for line in text.splitlines():
            self.assertLessEqual(info.display_width(line), 102)
            if "： " in line:
                self.assertEqual(info.display_width(line.split("： ")[0]), 10, line)

    def test_os_release_is_parsed_as_data_without_shell_execution(self):
        marker = self.root / "unexpected"
        self.file("/etc/os-release", f'PRETTY_NAME="Debian $(touch {marker})"\n')
        report = self.host.collect()
        self.assertIn("$(touch", report["system"]["os"])
        self.assertFalse(marker.exists())
        self.assertEqual(info.read_os_release('PRETTY_NAME="unterminated\nNAME=Debian\nVERSION="13"'), "Debian 13")

    def test_file_size_limit_and_fifo_are_rejected(self):
        self.file("/oversize", "X" * 101)
        self.assertIsNone(self.host.read("/oversize", 100))
        os.mkfifo(self.host.path("/pipe"))
        started = time.monotonic()
        self.assertIsNone(self.host.read("/pipe"))
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNone(self.host.read("/missing"))

    def test_collect_is_fresh_each_time_and_invalid_load_is_not_json_nan(self):
        before = self.host.collect()
        self.file("/proc/meminfo", "MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
        self.file("/proc/loadavg", "nan inf -1\n")
        self.file("/proc/uptime", "nan\n")
        after = self.host.collect()
        self.assertEqual(before["memory"]["used_bytes"], 2 * GIB)
        self.assertEqual(after["memory"]["used_bytes"], 4 * GIB)
        self.assertIsNone(after["cpu"]["load"])
        self.assertIsNone(after["system"]["uptime_seconds"])
        json.dumps(after, allow_nan=False)

    def test_timezone_reports_system_and_display_separately(self):
        with mock.patch.dict(os.environ, {"TZ": "Asia/Shanghai"}):
            report = self.host.collect()
        self.assertEqual(report["system"]["system_timezone"], "Etc/UTC")
        self.assertEqual(report["system"]["display_timezone"], "Asia/Shanghai")
        self.assertTrue(report["collected_at"].endswith("+08:00"))
        self.assertIn("系统时区： Etc/UTC", info.render(report))
        self.assertIn("显示时区： Asia/Shanghai", info.render(report))
        self.host.path("/etc/timezone").unlink()
        self.host_localtime.unlink()
        self.host_localtime.symlink_to("../usr/share/zoneinfo/Asia/Shanghai")
        self.assertEqual(self.host.system_timezone(), "Asia/Shanghai")

    def test_actual_localtime_link_takes_precedence_over_stale_timezone_hint(self):
        self.host_localtime.unlink()
        self.host_localtime.symlink_to("../usr/share/zoneinfo/Asia/Shanghai")
        self.assertEqual(self.host.path("/etc/timezone").read_text(), "Etc/UTC\n")
        with mock.patch.dict(os.environ, {"TZ": "UTC"}):
            report = self.host.collect()
        self.assertEqual(report["system"]["system_timezone"], "Asia/Shanghai")
        self.assertNotIn("system_timezone_unconfirmed", report["warnings"])

    def test_copied_localtime_requires_exact_hint_content_match(self):
        actual = self.host_localtime.read_bytes()
        self.host_localtime.unlink()
        self.host_localtime.write_bytes(actual)
        self.assertEqual(self.host.system_timezone(), "Etc/UTC")
        self.file("/etc/timezone", "Asia/Shanghai\n")
        report = self.host.collect()
        self.assertIsNone(report["system"]["system_timezone"])
        self.assertIn("system_timezone_unconfirmed", report["warnings"])
        self.assertIn("系统时区： 未确认", info.render(report))

    def test_missing_zoneinfo_or_dangling_localtime_are_not_confirmed(self):
        actual = self.host_localtime.read_bytes()
        self.host_localtime.unlink()
        self.host_localtime.write_bytes(actual)
        self.file("/etc/timezone", "Missing/Unknown\n")
        self.assertIsNone(self.host.system_timezone())
        self.host_localtime.unlink()
        self.host_localtime.symlink_to("../usr/share/zoneinfo/Missing/Unknown")
        self.file("/etc/timezone", "Etc/UTC\n")
        self.assertIsNone(self.host.system_timezone())

    def test_non_tzif_localtime_does_not_validate_a_textual_hint(self):
        self.host_localtime.unlink()
        for data in (b"not a timezone", b"TZif", b"TZif\0" + b"\0" * 15):
            self.host_localtime.write_bytes(data)
            self.assertIsNone(self.host.system_timezone())

    def test_unknown_timezone_does_not_claim_to_match_display(self):
        actual = self.host_localtime.read_bytes()
        self.host_localtime.unlink()
        self.host_localtime.write_bytes(actual)
        self.file("/etc/timezone", "bad\x1btimezone\n")
        with mock.patch.dict(os.environ, {"TZ": "Etc/UTC"}):
            report = self.host.collect()
        self.assertIsNone(report["system"]["system_timezone"])
        self.assertNotEqual(report["system"]["display_timezone"], "Etc/UTC")
        with mock.patch.dict(os.environ, {"TZ": "Invalid/NoSuchZone"}):
            self.assertNotEqual(self.host.collect()["system"]["display_timezone"], "Invalid/NoSuchZone")

    def test_cli_json_has_only_report_and_unknown_data_is_a_completed_report(self):
        self.host.finder = lambda _: None
        output = io.StringIO()
        with mock.patch.object(info, "Host", return_value=self.host), contextlib.redirect_stdout(output):
            self.assertEqual(info.main(["--json"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["schema"], 1)
        self.assertIn("services_partial", report["warnings"])
        self.assertIn("system_timezone", report["system"])

    def test_huge_command_output_is_rejected_without_exposing_text(self):
        self.host.runner = lambda _: (0, "SENSITIVE" * info.MAX_COMMAND)
        report = self.host.collect()
        self.assertIsNone(report["network"]["addresses"])
        self.assertNotIn("SENSITIVE", info.render(report))

    def test_sysctl_value_is_validated_not_printed_raw(self):
        self.file("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\nSECRET")
        report = self.host.collect()
        self.assertIsNone(report["network"]["tcp_congestion_control"])
        self.assertNotIn("SECRET", json.dumps(report))


class BoundedCommandTests(unittest.TestCase):
    def test_output_is_bounded(self):
        self.assertEqual(info.run_bounded([sys.executable, "-c", "print('X'*1000)"], limit=64), (None, None))
        code, text = info.run_bounded([sys.executable, "-c", "print('ok')"], limit=64)
        self.assertEqual((code, text), (0, "ok\n"))

    def test_timeout_is_bounded(self):
        started = time.monotonic()
        result = info.run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)
        self.assertEqual(result, (None, None))
        self.assertLess(time.monotonic() - started, 2)

    def test_environment_does_not_inherit_remote_bus_or_proxy(self):
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "tcp:host=remote.invalid", "HTTP_PROXY": "http://secret.invalid"}):
            code, text = info.run_bounded([sys.executable, "-c", "import json,os; print(json.dumps(dict(os.environ)))"])
        self.assertEqual(code, 0)
        env = json.loads(text)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertTrue(env["DBUS_SESSION_BUS_ADDRESS"].startswith("unix:path=/run/user/"))
        self.assertEqual(env["LC_ALL"], "C")


if __name__ == "__main__":
    unittest.main()
