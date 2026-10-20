"""Host tuning transactions in a private fake root; never runs privileged tools."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import machine_opt as opt


SECRET = "ibssh_FAKE_MUST_NOT_BE_LOGGED"


class FakeSystem:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.swaps = []
        self.fail = {}
        self.after = None
        self.container = False
        self.module = True
        self.fs = "ext4"
        self.mount_options = "rw,relatime"
        self.allocations = []
        self.available_memory = 6 * 1024 * opt.MIB
        self.write_proc()

    def file(self, path, text):
        filename = self.root / path.lstrip("/")
        filename.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        filename.write_text(text)
        return filename

    def write_proc(self):
        self.file("/proc/meminfo", f"MemTotal: {8 * 1024 * 1024} kB\nMemAvailable: {self.available_memory // 1024} kB\n")
        self.file("/proc/self/status", "CapEff:\t0000003fffffffff\n")
        self.write_swaps()
        self.file("/proc/sys/net/core/default_qdisc", "fq_codel\n")
        self.file("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")
        self.file("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n")

    def write_swaps(self):
        self.file("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n" + "".join(
            f"{row['path']} file {row['size'] // 1024} {row['used'] // 1024} -2\n" for row in self.swaps))

    def allocate(self, fd, length):
        # Transaction tests need the right logical size, not gigabytes of I/O.
        # The production write-filled allocator has its own real allocation test.
        self.allocations.append(length)
        os.ftruncate(fd, length)

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        assert kwargs["env"] == opt.ENV
        assert kwargs["stdin"] == subprocess.DEVNULL
        tool = Path(args[0]).name
        code, stdout = 0, ""
        signature = " ".join([tool, *args[1:]])
        if self.fail.get(tool, 0):
            self.fail[tool] -= 1
            return subprocess.CompletedProcess(args, 1, SECRET, SECRET)
        if self.fail.get(signature, 0):
            self.fail[signature] -= 1
            return subprocess.CompletedProcess(args, 1, SECRET, SECRET)
        if tool == "findmnt":
            stdout = self.fs if "FSTYPE" in args else self.mount_options
        elif tool == "systemd-detect-virt":
            code, stdout = (0, "docker") if self.container else (1, "none")
        elif tool == "tc":
            assert args[1:] == ["-j", "qdisc", "show"]
            stdout = json.dumps([{"dev": "lo", "kind": "noqueue"}, {"dev": "eth0", "kind": "mq"}, {"dev": "eth0", "kind": "fq_codel"}])
        elif tool == "modprobe":
            code = 0 if self.module else 1
            if "--dry-run" not in args and self.module:
                self.file("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
        elif tool == "mkswap":
            assert args[1] == "--"
            info = Path(args[2]).stat()
            assert info.st_size >= 256 * opt.MIB and stat.S_IMODE(info.st_mode) == 0o600
        elif tool == "swapon":
            assert args[1] == "--" and Path(args[2]) == self.root / opt.SWAP.lstrip("/")
            self.swaps.append({"path": opt.SWAP, "size": Path(args[2]).stat().st_size - 4096, "used": 0})
            self.write_swaps()
        elif tool == "swapoff":
            assert args[1] == "--" and len(args) == 3
            self.swaps = [row for row in self.swaps if row["path"] != opt.SWAP]
            self.write_swaps()
        elif tool == "sysctl":
            assert args[1] == "-w" and len(args) == 3
            key, value = args[2].split("=", 1)
            assert key in opt.KEYS
            self.file("/proc/sys/" + key.replace(".", "/"), value + "\n")
        else:
            raise AssertionError("Unexpected OS command " + tool)
        if self.after:
            self.after(tool, args)
        return subprocess.CompletedProcess(args, code, stdout, "")


class MachineOptimizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibt-opt-", dir=ROOT.parent)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        for directory in ("var/lib", "etc/sysctl.d"):
            (self.root / directory).mkdir(parents=True, mode=0o755)
        self.system = FakeSystem(self.root)
        self.fstab = self.system.file("/etc/fstab", "# administrator entries\nUUID=keep / ext4 defaults 0 1\n")
        self.fstab.chmod(0o644)
        self.original_fstab = self.fstab.read_text()
        self.disk = [16 * 1024 * opt.MIB, 11 * 1024 * opt.MIB]
        self.host = opt.Host(self.root, owner=os.getuid(), runner=self.system,
                             allocator=self.system.allocate, disk=lambda _: self.disk)
        self.lines = []
        self.manager = opt.Optimizer(self.host, output=self.lines.append, confirm=lambda: True, privileged=True)

    def tearDown(self):
        self.temp.cleanup()

    def mutate_calls(self):
        return [call for call in self.system.calls if Path(call[0]).name in {"swapon", "swapoff", "mkswap", "sysctl"} or Path(call[0]).name == "modprobe" and "--dry-run" not in call]

    def run_change(self, command="apply", size=None):
        return self.manager.change(command, size, yes=True)

    def test_status_and_recommend_are_read_only_and_current_host_recommends_2g(self):
        files_before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        self.assertEqual(self.manager.status(), 0)
        self.assertEqual(self.manager.recommend(), 0)
        self.assertIn("2048 MiB", "\n".join(self.lines))
        self.assertIn("eth0:mq", "\n".join(self.lines))
        self.assertIn("UDP/QUIC", "\n".join(self.lines))
        self.assertIn("内核版本： ", "\n".join(self.lines))
        self.assertIn("可用算法： reno cubic", "\n".join(self.lines))
        self.assertIn("交换建议： 创建 2048 MiB", "\n".join(self.lines))
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())
        self.assertEqual(files_before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")))

    def test_apply_creates_only_owned_assets_and_restores_original_values(self):
        self.assertEqual(self.run_change(), 0)
        state = self.manager.state()
        self.assertEqual(state["swap"]["mib"], 2048)
        self.assertEqual(self.system.allocations, [2048 * opt.MIB])
        self.assertEqual(stat.S_IMODE(self.host.path(opt.BASE).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.host.asset("swap").stat().st_mode), 0o600)
        self.assertEqual(self.host.read("bbr"), opt.BBR_TEXT)
        self.assertEqual({key: self.host.sysctl(key) for key in opt.KEYS}, opt.DESIRED)
        self.assertIn(opt.BLOCK, self.fstab.read_text())
        self.assertIsNone(self.manager.read_json("journal"))
        self.assertEqual(self.run_change("restore"), 0)
        self.assertEqual(self.fstab.read_text(), self.original_fstab)
        self.assertFalse(self.host.asset("swap").exists())
        self.assertFalse(self.host.asset("bbr").exists())
        self.assertEqual(self.host.sysctl(opt.KEYS[0]), "fq_codel")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "cubic")
        self.assertEqual(self.manager.state(), {"schema": 1, "swap": None, "bbr": None})

    def test_disk_budget_is_adaptive_and_explicit_oversize_is_rejected(self):
        self.disk[1] = 3 * 1024 * opt.MIB
        self.assertEqual(opt.suggested_swap(self.host.facts()), 1024)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 2048)
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())
        self.disk[1] = 2 * 1024 * opt.MIB + 100 * opt.MIB
        self.assertEqual(opt.suggested_swap(self.host.facts()), 0)

    def test_existing_foreign_swap_is_kept_and_not_managed_by_off(self):
        self.system.swaps = [{"path": "/existing.swap", "size": 1024 * opt.MIB, "used": 8 * opt.MIB}]
        self.system.write_swaps()
        self.assertEqual(self.run_change("swap-on", 2048), 0)
        self.assertEqual(self.run_change("swap-off"), 0)
        self.assertEqual(self.mutate_calls(), [])
        self.assertEqual(self.system.swaps[0]["path"], "/existing.swap")
        self.assertEqual(self.fstab.read_text(), self.original_fstab)

    def test_foreign_same_path_file_and_config_are_not_adopted(self):
        self.host.ensure_base()
        self.host.asset("swap").write_text("foreign data")
        self.host.asset("swap").chmod(0o600)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.assertEqual(self.host.asset("swap").read_text(), "foreign data")
        self.host.asset("swap").unlink()
        self.host.write("bbr", opt.BBR_TEXT)
        with self.assertRaises(opt.OptError):
            self.run_change("bbr-on")
        self.assertEqual(self.host.read("bbr"), opt.BBR_TEXT)
        self.assertEqual(self.mutate_calls(), [])

    def test_foreign_fstab_same_path_entry_refused_without_rewrite(self):
        content = self.original_fstab + opt.SWAP + " none swap defaults 0 0\n"
        self.fstab.write_text(content)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.assertEqual(self.fstab.read_text(), content)
        self.assertEqual(self.mutate_calls(), [])

    def test_unsupported_filesystem_container_and_capability_are_refused(self):
        for setting, value in (("fs", "btrfs"), ("mount_options", "ro"), ("container", True)):
            original = getattr(self.system, setting)
            setattr(self.system, setting, value)
            with self.subTest(setting=setting), self.assertRaises(opt.OptError):
                self.run_change("swap-on", 256)
            setattr(self.system, setting, original)
        self.system.file("/proc/self/status", "CapEff:\t0000000000000000\n")
        for command in ("swap-on", "bbr-on"):
            with self.subTest(command=command), self.assertRaises(opt.OptError):
                self.run_change(command, 256 if command == "swap-on" else None)
        self.assertEqual(self.mutate_calls(), [])

    def test_unsupported_bbr_never_installs_kernel_or_changes_values(self):
        self.system.module = False
        with self.assertRaises(opt.OptError):
            self.run_change("bbr-on")
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())

    def test_apply_without_applicable_settings_explains_reasons(self):
        self.system.container = True
        self.system.module = False
        self.assertEqual(self.run_change(), 0)
        output = "\n".join(self.lines)
        self.assertIn("容器环境不适合", output)
        self.assertIn("未确认内核 BBR 能力", output)
        self.assertIn("没有可执行的新增设置", output)
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())

    def test_failed_swap_activation_rolls_back_new_resource(self):
        self.system.fail["swapon"] = 1
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.assertFalse(self.host.asset("swap").exists())
        self.assertIsNone(self.manager.state())
        self.assertIsNone(self.manager.read_json("journal"))
        self.assertEqual(self.fstab.read_text(), self.original_fstab)
        self.assertNotIn(SECRET, "\n".join(self.lines))

    def test_late_network_failure_rolls_back_swap_and_prior_network_write(self):
        self.system.fail["sysctl -w net.ipv4.tcp_congestion_control=bbr"] = 1
        with self.assertRaises(opt.OptError):
            self.run_change()
        self.assertEqual(self.system.swaps, [])
        self.assertFalse(self.host.asset("swap").exists())
        self.assertFalse(self.host.asset("bbr").exists())
        self.assertEqual(self.host.sysctl(opt.KEYS[0]), "fq_codel")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "cubic")
        self.assertEqual(self.fstab.read_text(), self.original_fstab)
        self.assertIsNone(self.manager.state())
        self.assertIsNone(self.manager.read_json("journal"))

    def test_failed_swapoff_keeps_active_file_fstab_and_state(self):
        self.run_change("swap-on", 256)
        before = self.manager.state()
        self.system.fail["swapoff"] = 1
        with self.assertRaises(opt.OptError):
            self.run_change("swap-off")
        self.assertTrue(self.host.asset("swap").exists())
        self.assertTrue(self.system.swaps)
        self.assertIn(opt.BLOCK, self.fstab.read_text())
        self.assertEqual(self.manager.state(), before)

    def test_swapoff_memory_check_prevents_dangerous_attempt(self):
        self.run_change("swap-on", 256)
        self.system.swaps[0]["used"] = 200 * opt.MIB
        self.system.write_swaps()
        self.system.file("/proc/meminfo", "MemTotal: 8388608 kB\nMemAvailable: 131072 kB\n")
        calls = list(self.mutate_calls())
        with self.assertRaises(opt.OptError):
            self.run_change("swap-off")
        self.assertEqual(self.mutate_calls(), calls)
        self.assertTrue(self.host.asset("swap").exists())

    def test_idempotent_repeat_preserves_saved_original_values(self):
        self.run_change()
        original_state = self.manager.state()
        inode = self.host.asset("swap").stat().st_ino
        self.system.calls.clear()
        self.run_change()
        self.assertEqual(self.mutate_calls(), [])
        self.assertEqual(self.manager.state(), original_state)
        self.assertEqual(self.host.asset("swap").stat().st_ino, inode)
        self.assertEqual(self.fstab.read_text().count(opt.BLOCK), 1)

    def test_restore_preserves_other_fstab_edits_but_rejects_owned_block_changes(self):
        self.run_change("swap-on", 256)
        self.fstab.write_text(self.fstab.read_text() + "UUID=elsewhere /data ext4 defaults 0 2\n")
        self.run_change("swap-off")
        self.assertEqual(self.fstab.read_text(), self.original_fstab + "UUID=elsewhere /data ext4 defaults 0 2\n")
        self.run_change("swap-on", 256)
        self.fstab.write_text(self.fstab.read_text().replace("sw,nofail", "sw,pri=100"))
        calls = list(self.mutate_calls())
        with self.assertRaises(opt.OptError):
            self.run_change("restore")
        self.assertEqual(self.mutate_calls(), calls)
        self.assertTrue(self.system.swaps)

    def test_fstab_without_final_newline_keeps_later_mount_separate(self):
        original = self.original_fstab.rstrip("\n")
        self.fstab.write_text(original)
        self.run_change("swap-on", 256)
        self.assertEqual(self.manager.state()["swap"]["block"], "\n" + opt.BLOCK)
        later = "UUID=elsewhere /data ext4 defaults 0 2\n"
        self.fstab.write_text(self.fstab.read_text() + later)
        self.run_change("swap-off")
        self.assertEqual(self.fstab.read_text(), original + "\n" + later)

    def test_bbr_reenable_preserves_first_baseline_and_reapplies_changed_value(self):
        self.run_change("bbr-on")
        baseline = self.manager.state()
        self.system.file("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")
        self.system.calls.clear()
        self.run_change("bbr-on")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "bbr")
        self.assertEqual(self.manager.state(), baseline)
        self.assertEqual(self.mutate_calls(), [[opt.TOOLS["sysctl"], "-w", "net.ipv4.tcp_congestion_control=bbr"]])
        self.run_change("bbr-off")
        self.assertEqual(self.host.sysctl(opt.KEYS[0]), "fq_codel")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "cubic")

    def test_restore_rejects_later_sysctl_or_dropin_edits(self):
        self.run_change("bbr-on")
        self.system.file("/proc/sys/net/ipv4/tcp_congestion_control", "reno\n")
        calls = list(self.mutate_calls())
        with self.assertRaises(opt.OptError):
            self.run_change("bbr-off")
        self.assertEqual(self.mutate_calls(), calls)
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "reno")
        self.system.file("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n")
        self.host.asset("bbr").write_text(opt.BBR_TEXT + "# external edit\n")
        with self.assertRaises(opt.OptError):
            self.run_change("restore")
        self.assertTrue(self.host.asset("bbr").read_text().endswith("# external edit\n"))

    def test_bbr_existing_external_settings_are_not_claimed(self):
        for key, value in opt.DESIRED.items():
            self.system.file("/proc/sys/" + key.replace(".", "/"), value + "\n")
        self.run_change("bbr-on")
        self.run_change("bbr-off")
        self.assertEqual(self.mutate_calls(), [])
        self.assertIsNone(self.manager.state())

    def test_allocation_failure_removes_partial_owned_file(self):
        def fail_allocation(fd, length):
            os.write(fd, b"partial")
            raise OSError("secret underlying error " + SECRET)
        self.host.allocator = fail_allocation
        with self.assertRaises(opt.OptError) as error:
            self.run_change("swap-on", 256)
        self.assertNotIn(SECRET, str(error.exception))
        self.assertFalse(self.host.asset("swap").exists())
        self.assertIsNone(self.manager.read_json("journal"))

    def test_anonymous_swap_identity_save_failure_never_publishes_file(self):
        save = self.manager.save_journal
        for after_write in (False, True):
            def failed_identity_save(value):
                has_identity = value["ops"][0]["identity"] is not None
                if not has_identity or after_write:
                    save(value)
                if has_identity:
                    raise OSError("identity write failure")
            with self.subTest(after_write=after_write), mock.patch.object(self.manager, "save_journal", failed_identity_save), self.assertRaises(opt.OptError):
                self.run_change("swap-on", 256)
            self.assertFalse(self.host.asset("swap").exists())
            self.assertIsNone(self.manager.read_json("journal"))
            self.assertIsNone(self.manager.state())
            self.assertEqual(self.mutate_calls(), [])

    def test_durable_identity_without_published_swap_can_recover(self):
        journal = self.manager.plan("swap-on", 256, self.host.facts(), None)
        with self.host.lock():
            self.manager.save_journal(journal)
            with mock.patch.object(self.host, "publish_swap", side_effect=OSError("interruption before link")), self.assertRaises(OSError):
                self.manager.execute_op(journal, journal["ops"][0])
        self.assertIsNotNone(self.manager.read_json("journal")["ops"][0]["identity"])
        self.assertFalse(self.host.asset("swap").exists())
        self.assertEqual(self.run_change("restore"), 0)
        self.assertIsNone(self.manager.read_json("journal"))
        self.assertEqual(self.fstab.read_text(), self.original_fstab)
        self.assertEqual(self.mutate_calls(), [])

    def test_publish_collision_preserves_unknown_file_and_recovery_record(self):
        publish = self.host.publish_swap
        def collision(fd):
            self.host.asset("swap").write_bytes(b"foreign")
            self.host.asset("swap").chmod(0o600)
            return publish(fd)
        with mock.patch.object(self.host, "publish_swap", collision), self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.assertEqual(self.host.asset("swap").read_bytes(), b"foreign")
        self.assertIsNotNone(self.manager.read_json("journal"))
        with self.assertRaises(opt.OptError):
            self.run_change("restore")
        self.assertEqual(self.host.asset("swap").read_bytes(), b"foreign")
        self.assertEqual(self.mutate_calls(), [])

    def test_own_descriptor_publish_fallback_uses_only_exact_swap_destination(self):
        libc = opt.ctypes.CDLL(None, use_errno=True)
        linkat = libc.linkat
        linkat.argtypes = [opt.ctypes.c_int, opt.ctypes.c_char_p, opt.ctypes.c_int, opt.ctypes.c_char_p, opt.ctypes.c_int]
        linkat.restype = opt.ctypes.c_int
        real_link = os.link
        rejected = mock.Mock()
        def deny_empty_path(*_):
            opt.ctypes.set_errno(opt.errno.EPERM)
            return -1
        rejected.linkat.side_effect = deny_empty_path
        calls = []
        def fallback(source, destination, *, dst_dir_fd, follow_symlinks):
            calls.append((source, destination, follow_symlinks))
            fd = int(source.rsplit("/", 1)[1])
            # This sandbox does not expose /proc/self/fd, so publish through the
            # captured real libc while verifying the documented fallback argv.
            if linkat(fd, b"", dst_dir_fd, destination.encode(), 0x1000) != 0:
                # An ordinary CI user lacks CAP_DAC_READ_SEARCH but can link
                # its own descriptor through the real procfs alternative.
                real_link(source, destination, dst_dir_fd=dst_dir_fd, follow_symlinks=True)
        with mock.patch.object(opt.ctypes, "CDLL", return_value=rejected), mock.patch.object(opt.os, "link", fallback):
            self.run_change("swap-on", 256)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].startswith("/proc/self/fd/"))
        self.assertEqual(calls[0][1:], ("swapfile", True))
        self.assertTrue(self.system.swaps)

    def test_missing_previously_managed_swap_is_not_a_prelink_recovery(self):
        self.run_change("swap-on", 256)
        self.system.swaps.clear()
        self.system.write_swaps()
        journal = self.manager.plan("swap-off", None, self.host.facts(), self.manager.state())
        self.manager.save_journal(journal)
        self.host.asset("swap").unlink()
        with self.assertRaises(opt.OptError):
            self.run_change("restore")
        self.assertIsNotNone(self.manager.read_json("journal"))
        self.assertIsNotNone(self.manager.state()["swap"])

    def test_real_allocator_writes_blocks_without_holes(self):
        path = self.root / "allocation-test"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            opt.allocate_filled(fd, 2 * opt.MIB)
        finally:
            os.close(fd)
        info = path.stat()
        self.assertEqual(info.st_size, 2 * opt.MIB)
        self.assertGreaterEqual(info.st_blocks * 512, info.st_size)

    def test_symlink_and_hardlink_assets_are_rejected(self):
        self.host.ensure_base()
        foreign = self.root / "foreign"
        foreign.write_text("do not alter")
        self.host.asset("swap").symlink_to(foreign)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.host.asset("swap").unlink()
        foreign.chmod(0o600)
        os.link(foreign, self.host.asset("swap"))
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        self.assertEqual(foreign.read_text(), "do not alter")
        self.assertEqual(self.mutate_calls(), [])

    def test_unsafe_parent_and_foreign_owner_are_rejected(self):
        (self.root / "var/lib").chmod(0o777)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-on", 256)
        (self.root / "var/lib").chmod(0o755)
        self.host.owner = os.getuid() + 1
        with self.assertRaises(opt.OptError):
            self.run_change("bbr-on")
        self.assertEqual(self.mutate_calls(), [])

    def test_concurrent_mutation_and_confirmation_changes_are_rejected(self):
        with self.host.lock():
            with self.assertRaises(opt.OptError):
                self.run_change("swap-on", 256)
        def changed():
            self.system.file("/proc/sys/net/core/default_qdisc", "pfifo_fast\n")
            return True
        self.manager.confirm = changed
        with self.assertRaises(opt.OptError):
            self.manager.change("bbr-on")
        self.assertEqual(self.mutate_calls(), [])

    def test_cancellation_returns_three_without_creating_state_directory(self):
        self.manager.confirm = lambda: False
        self.assertEqual(self.manager.change("apply"), 3)
        self.assertFalse(self.host.path(opt.BASE).exists())
        self.assertEqual(self.mutate_calls(), [])

    def test_journal_contains_no_foreign_fstab_credentials(self):
        content = self.original_fstab + "//server/share /mnt cifs password=" + SECRET + " 0 0\n"
        self.fstab.write_text(content)
        observed = []
        original = self.manager.save_journal
        def save(value):
            observed.append(opt.canonical(value))
            return original(value)
        with mock.patch.object(self.manager, "save_journal", save):
            self.run_change()
        self.assertTrue(observed)
        self.assertNotIn(SECRET, "".join(observed))
        self.run_change("restore")
        self.assertEqual(self.fstab.read_text(), content)

    def test_rollback_interruption_can_be_retried_without_overwriting_foreign_values(self):
        self.system.fail["sysctl -w net.ipv4.tcp_congestion_control=bbr"] = 1
        self.system.fail["swapoff"] = 1
        with self.assertRaises(opt.OptError):
            self.run_change()
        self.assertIsNotNone(self.manager.read_json("journal"))
        self.assertTrue(self.host.asset("swap").exists())
        self.assertEqual(self.run_change("restore"), 0)
        self.assertFalse(self.host.asset("swap").exists())
        self.assertEqual(self.fstab.read_text(), self.original_fstab)

    def test_commit_save_error_after_replace_does_not_rollback(self):
        save = self.manager.save_journal
        def fail_after(value):
            save(value)
            if value["phase"] == "committed":
                raise OSError("fsync failure")
        with mock.patch.object(self.manager, "save_journal", fail_after):
            self.assertEqual(self.run_change("bbr-on"), 0)
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "bbr")
        self.assertIsNotNone(self.manager.state()["bbr"])
        self.assertIsNone(self.manager.read_json("journal"))

    def test_commit_save_error_before_replace_rolls_back(self):
        save = self.manager.save_journal
        def fail_before(value):
            if value["phase"] == "committed":
                raise OSError("write failure")
            save(value)
        with mock.patch.object(self.manager, "save_journal", fail_before), self.assertRaises(opt.OptError):
            self.run_change("bbr-on")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "cubic")
        self.assertIsNone(self.manager.state())

    def test_managed_inode_replacement_is_never_removed(self):
        self.run_change("swap-on", 256)
        owned = self.host.asset("swap")
        old = owned.with_name("original")
        owned.rename(old)
        owned.write_bytes(b"foreign")
        owned.chmod(0o600)
        with self.assertRaises(opt.OptError):
            self.run_change("swap-off")
        self.assertEqual(owned.read_bytes(), b"foreign")

    def test_status_permission_failure_says_unknown_not_unmanaged(self):
        with mock.patch.object(self.manager, "state", side_effect=PermissionError()):
            self.assertEqual(self.manager.status(), 0)
        self.assertIn("需管理员权限核对", "\n".join(self.lines))
        self.assertNotIn("没有本工具变更记录", "\n".join(self.lines))

    def test_no_sudo_flags_and_nonroot_worker_never_escalate(self):
        for flag in ("IBT_NO_SUDO", "IB_NO_SUDO", "SB_NO_SUDO"):
            with self.subTest(flag=flag), mock.patch.object(opt.os, "geteuid", return_value=1000), mock.patch.dict(os.environ, {flag: "1"}), mock.patch.object(opt.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(opt.main(["apply"]), 2)
                run.assert_not_called()
                self.assertIn("禁止 sudo", out.getvalue())
        with mock.patch.object(opt.os, "geteuid", return_value=1000), mock.patch.object(opt.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(opt.main(["apply", "--privileged"]), 2)
            run.assert_not_called()

    def test_sudo_argv_contains_only_fixed_interpreter_script_and_validated_size(self):
        with mock.patch.object(opt.os, "geteuid", return_value=1000), mock.patch.dict(os.environ, {"INSTABOX_API_KEY": "ibk_FAKE_SECRET"}, clear=True), mock.patch.object(opt.subprocess, "run", return_value=subprocess.CompletedProcess([], 3)) as run:
            self.assertEqual(opt.main(["swap-on", "512"]), 3)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:4], ["/usr/bin/sudo", "--", "/usr/bin/python3", "-I"])
        self.assertEqual(args[0][-3:], ["swap-on", "512", "--privileged"])
        self.assertNotIn("INSTABOX_API_KEY", kwargs["env"])

    def test_recovery_rejects_unknown_resources_and_malformed_state(self):
        self.host.ensure_base()
        self.host.write("journal", opt.canonical({"schema": 1, "phase": "prepared", "before": None,
            "after": {"schema": 1, "swap": None, "bbr": None}, "cleanup": None,
            "ops": [{"kind": "file", "path": "/etc/shadow", "before": None, "after": "oops"}]}))
        with self.assertRaises(opt.OptError):
            self.run_change("restore")
        self.assertEqual(self.mutate_calls(), [])
        self.assertIsNotNone(self.manager.read_json("journal"))

    def test_later_sysctl_conflicts_are_refused_without_touching_foreign_config(self):
        filename = self.system.file("/etc/sysctl.d/99-existing.conf", "net/ipv4/tcp_congestion_control = cubic\n")
        before = filename.read_bytes()
        with self.assertRaisesRegex(opt.OptError, "后序 sysctl 配置会覆盖"):
            self.run_change("bbr-on")
        self.assertEqual(filename.read_bytes(), before)
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())

    def test_sysctl_directory_precedence_and_final_effective_values(self):
        self.system.file("/usr/lib/sysctl.d/99-example.conf", "net.ipv4.tcp_congestion_control = cubic\n")
        self.system.file("/etc/sysctl.d/99-example.conf", "net.ipv4.tcp_congestion_control = bbr\n")
        self.system.file("/etc/sysctl.d/95-old.conf", "net.core.default_qdisc = pfifo_fast\n")
        self.system.file("/etc/sysctl.d/99-new.conf", "net.core.default_qdisc = fq\n")
        self.system.file("/etc/sysctl.d/20-old.conf", "net.ipv4.tcp_congestion_control = reno\n")
        self.assertEqual(self.run_change("bbr-on"), 0)
        self.assertEqual({key: self.host.sysctl(key) for key in opt.KEYS}, opt.DESIRED)
        self.assertEqual((self.root / "usr/lib/sysctl.d/99-example.conf").read_text(), "net.ipv4.tcp_congestion_control = cubic\n")

    def test_debian_sysctl_compatibility_link_and_procps_last_file(self):
        legacy = self.system.file("/etc/sysctl.conf", "net.ipv4.tcp_congestion_control = cubic\n")
        link = self.root / "etc/sysctl.d/99-sysctl.conf"
        link.symlink_to("../sysctl.conf")
        with self.assertRaisesRegex(opt.OptError, "后序 sysctl 配置会覆盖"):
            self.run_change("bbr-on")
        legacy.write_text("# system defaults\n")
        self.assertEqual(self.run_change("bbr-on"), 0)
        self.assertTrue(link.is_symlink())
        self.run_change("bbr-off")
        link.unlink()
        legacy.write_text("net.core.default_qdisc = fq_codel\n")
        with self.assertRaisesRegex(opt.OptError, "后序 sysctl 配置会覆盖"):
            self.run_change("bbr-on")

    def test_sysctl_devnull_mask_and_merged_usr_alias(self):
        self.system.file("/usr/lib/sysctl.d/99-mask.conf", "net.core.default_qdisc = pfifo_fast\n")
        (self.root / "etc/sysctl.d/99-mask.conf").symlink_to("/dev/null")
        (self.root / "lib").symlink_to("usr/lib")
        self.assertEqual(self.run_change("bbr-on"), 0)

    def test_unknown_sysctl_link_or_matching_glob_does_not_claim_persistence(self):
        path = self.root / "etc/sysctl.d/99-unknown.conf"
        path.symlink_to("/run/unknown-config")
        with self.assertRaisesRegex(opt.OptError, "无法确认"):
            self.run_change("bbr-on")
        path.unlink()
        path.write_text("net.* = arbitrary\n")
        with self.assertRaisesRegex(opt.OptError, "无法确认"):
            self.run_change("bbr-on")
        self.assertEqual(self.mutate_calls(), [])
        self.assertFalse(self.host.path(opt.BASE).exists())

    def test_sysctl_conflict_added_during_transaction_rolls_back_only_owned_change(self):
        def external_change(tool, args):
            if tool == "sysctl" and args[-1] == "net.ipv4.tcp_congestion_control=bbr":
                self.system.file("/etc/sysctl.d/99-later.conf", "net.ipv4.tcp_congestion_control = cubic\n")
        self.system.after = external_change
        with self.assertRaises(opt.OptError):
            self.run_change("bbr-on")
        self.assertEqual(self.host.sysctl(opt.KEYS[1]), "cubic")
        self.assertFalse(self.host.asset("bbr").exists())
        self.assertTrue((self.root / "etc/sysctl.d/99-later.conf").exists())
        self.assertIsNone(self.manager.read_json("journal"))


if __name__ == "__main__":
    unittest.main()
