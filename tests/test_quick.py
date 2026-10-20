"""Exercise the actual Quick launcher and installer with offline child processes."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import migrate

SOURCE = (ROOT / "install.sh").read_text()
LIBRARY = SOURCE.rsplit('case "${1:-install}" in', 1)[0]
LAUNCHER = re.search(r"write_quick_launcher\(\) \{.*?<<'EOF'\n(.*?)\nEOF", SOURCE, re.S).group(1) + "\n"


class QuickLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibt-quick-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.app = self.home / ".local/share/insta-box"
        self.bin = self.app / "bin"
        self.bin.mkdir(parents=True, mode=0o700)
        self.home.chmod(0o700)
        self.launcher = self.bin / "start-quick-tunnel"
        self.launcher.write_text(LAUNCHER)
        self.launcher.chmod(0o700)
        self.state = self.app / "state.conf"
        self.state.write_text("mode=quick\ndomain=unchanged.example.com\nuuid=" + "1" * 36 + "\npath=/ws-" + "2" * 36 + "\nport=20000\n")
        self.state.chmod(0o600)
        self.config = self.app / "config.json"
        self.config.write_text('{"fixture": "unchanged"}\n')
        self.binary = self.bin / "cloudflared"
        self.binary.write_text("#!" + sys.executable + "\n" + '''import json, os, sys
from pathlib import Path
base = Path(os.environ['HOME']) / '.local/share/insta-box'
(base / 'captured-args.json').write_text(json.dumps(sys.argv[1:]))
(base / 'captured-env.json').write_text(json.dumps([key for key in ('TUNNEL_NAME', 'TUNNEL_HELLO_WORLD') if key in os.environ]))
print('https://fixture-current.trycloudflare.com')
print('Registered tunnel connection protocol=http2')
''')
        self.binary.chmod(0o700)
        self.env = {**os.environ, "HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1"}

    def launch(self):
        return subprocess.run(["bash", str(self.launcher)], env=self.env, capture_output=True, text=True, timeout=5)

    def core(self, action, *, probe=1):
        # The installer is real, but all service operations and downloaded
        # binaries are fixtures. No host systemd, network or sudo can be called.
        helper = Path(self.temp.name) / "node_probe.py"
        normal, quiet = (probe, probe) if isinstance(probe, int) else probe
        helper.write_text("import sys\nif '--quiet' not in sys.argv: print('  公网检查： 离线夹具')\nraise SystemExit(" + str(quiet) + " if '--quiet' in sys.argv else " + str(normal) + ")\n")
        script = Path(self.temp.name) / "core.sh"
        script.write_text(LIBRARY + '''
preflight() { :; }
ensure_cloudflared() { :; }
install_quick_unit() { :; }
systemctl() {
  if [[ "${2:-}" == restart ]]; then
    printf '%s\\n' "$*" >> "$HOME/service-actions"
    bash "$QUICK_LAUNCHER"
  elif [[ "${2:-}" == is-active ]]; then return 0
  else return 97; fi
}
''' + action + "\n")
        return subprocess.run(["bash", str(script)], env=self.env, capture_output=True, text=True, timeout=5)

    def test_fresh_and_migrated_launchers_are_identical(self):
        self.assertEqual(LAUNCHER.encode(), migrate.QUICK)

    def test_auto_fallback_and_private_config_do_not_load_named_tunnel_config(self):
        foreign = self.home / ".cloudflared/config.yml"
        foreign.parent.mkdir()
        foreign.write_text("ingress:\n  - service: http_status:404\n")
        original = foreign.read_bytes()
        self.env.update(TUNNEL_NAME="fixture-named", TUNNEL_HELLO_WORLD="true", INVOCATION_ID="a" * 32)
        (self.app / "quick.log").write_text("https://fixture-old.trycloudflare.com\n")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads((self.app / "captured-args.json").read_text())
        self.assertEqual(args, ["tunnel", "--config", str(self.app / "quick-config.yml"), "--protocol", "auto", "--no-autoupdate", "--url", "http://127.0.0.1:20000"])
        self.assertEqual(foreign.read_bytes(), original)
        self.assertEqual(json.loads((self.app / "captured-env.json").read_text()), [])
        self.assertEqual((self.app / "quick.log").read_text().splitlines()[0], "IBT_QUICK_INVOCATION=" + "a" * 32)
        self.assertEqual((self.app / "quick-config.yml").read_text(), "{}\n")
        for name in ("quick.log", "quick-config.yml", "quick-protocol"):
            self.assertEqual(stat.S_IMODE((self.app / name).stat().st_mode), 0o600)
        self.assertNotIn("fixture-old", (self.app / "quick.log").read_text())
        self.assertEqual((self.app / "quick-protocol").read_text(), "auto\n")

    def test_http2_selection_and_invalid_values_cannot_inject_options(self):
        selected = self.app / "quick-protocol"
        selected.write_text("http2\n")
        self.assertEqual(self.launch().returncode, 0)
        captured = self.app / "captured-args.json"
        self.assertEqual(json.loads(captured.read_text())[4], "http2")
        captured.unlink()
        selected.write_text("http2 --token BAD\n")
        self.assertNotEqual(self.launch().returncode, 0)
        self.assertFalse(captured.exists())

    def test_invalid_port_rejected_before_connector_starts(self):
        self.state.write_text("port=99999\n")
        self.assertEqual(self.launch().returncode, 2)
        self.assertFalse((self.app / "captured-args.json").exists())

    def test_linked_private_files_and_foreign_quick_config_are_not_truncated(self):
        outside = self.home / "unrelated"
        outside.write_text("preserve this content\n")
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                target = self.app / "quick.log"
                if kind == "symlink":
                    target.symlink_to(outside)
                else:
                    os.link(outside, target)
                self.assertEqual(self.launch().returncode, 2)
                self.assertEqual(outside.read_text(), "preserve this content\n")
                target.unlink()
        config = self.app / "quick-config.yml"
        config.write_text("ingress: []\n")
        self.assertEqual(self.launch().returncode, 2)
        self.assertEqual(config.read_text(), "ingress: []\n")

    def test_launcher_replacement_rejects_linked_or_writable_parents(self):
        outside = self.home / "unrelated"
        outside.write_text("unchanged\n")
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                self.launcher.unlink()
                if kind == "symlink":
                    self.launcher.symlink_to(outside)
                else:
                    os.link(outside, self.launcher)
                result = self.core("write_quick_launcher")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outside.read_text(), "unchanged\n")
        self.launcher.unlink()
        self.bin.chmod(0o777)
        self.assertNotEqual(self.core("write_quick_launcher").returncode, 0)
        self.assertFalse(self.launcher.exists())
        self.assertNotEqual(self.core("quick_protocol_main http2").returncode, 0)
        self.assertFalse((self.app / "quick-protocol").exists())

    def test_refresh_propagates_probe_failure_even_with_registration_in_log(self):
        before = {path: path.read_bytes() for path in (self.state, self.config)}
        result = self.core("refresh_quick_main", probe=1)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("Registered tunnel connection", (self.app / "quick.log").read_text())
        self.assertIn("链路检查： 尚未通过", result.stdout)
        self.assertNotIn("WebSocket 握手通过", result.stdout)
        self.assertIn("ibt diagnose", result.stderr)
        self.assertEqual((self.home / "service-actions").read_text().splitlines(), ["--user restart insta-box-quick.service"])
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_protocol_switch_only_restarts_quick_and_preserves_node(self):
        before = {path: path.read_bytes() for path in (self.state, self.config)}
        result = self.core("quick_protocol_main http2", probe=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WebSocket 握手通过", result.stdout)
        self.assertEqual((self.app / "quick-protocol").read_text(), "http2\n")
        self.assertEqual(stat.S_IMODE((self.app / "quick-protocol").stat().st_mode), 0o600)
        self.assertEqual((self.home / "service-actions").read_text().splitlines(), ["--user restart insta-box-quick.service"])
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_refresh_uses_last_host_bound_result_when_health_changes(self):
        failed = self.core("refresh_quick_main", probe=(0, 1))
        self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
        self.assertIn("链路检查： 尚未通过", failed.stdout)
        recovered = self.core("refresh_quick_main", probe=(1, 0))
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertIn("WebSocket 握手通过", recovered.stdout)

    def repair(self, *, probe=0, active=True, enabled=True, start_ok=True, unit=True, installed=False,
               show_status=0, helper_fails=False):
        helper = Path(self.temp.name) / "node_probe.py"
        helper.write_text("import sys\nfrom pathlib import Path\nimport os\n"
                          "p=Path(os.environ['HOME'])/'probe-actions'\n"
                          "p.write_text(' '.join(sys.argv[1:]))\n"
                          "print('  本机握手： 测试结果')\nraise SystemExit(" + str(probe) + ")\n")
        sb = self.bin / "sing-box"
        sb.write_text("#!/usr/bin/env bash\nexit 0\n")
        sb.chmod(0o700)
        units = self.home / ".config/systemd/user"
        units.mkdir(parents=True, exist_ok=True)
        if unit:
            (units / "insta-box-quick.service").write_text("# Managed-by: InstaBox Tool\n")
        script = Path(self.temp.name) / "install.sh"
        script.write_text(LIBRARY + '''
preflight() { :; }
install_singbox_unit() { :; }
ensure_linger() { :; }
ensure_cloudflared() { ''' + ("false; printf 'UNSAFE_CONTINUED\\n';" if helper_fails else ":;") + ''' }
install_named_tunnel_unit() { :; }
show_main() { SHOW_QUICK_STATUS=''' + str(show_status) + '''; printf 'SHOW_LINKS\\n'; }
systemctl() {
  case "${2:-}" in
    is-active) return ''' + str(0 if active else 1) + ''';;
    is-enabled) return ''' + str(0 if enabled else 1) + ''';;
    start) printf '%s\\n' "$*" >> "$HOME/service-actions"; return ''' + str(0 if start_ok else 1) + ''';;
    *) printf 'Unexpected service mutation\\n' >&2; return 97;;
  esac
}
''' + ('if [[ "${1:-}" == repair ]]; then repair_main; else install_main; fi' if installed else "repair_main") + "\n")
        return subprocess.run(["bash", str(script)], env=self.env, capture_output=True, text=True, timeout=5)

    def test_repair_checks_connectivity_and_returns_failure_without_restarting_active_quick(self):
        before = {path: path.read_bytes() for path in (self.state, self.config)}
        result = self.repair(probe=1)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertEqual((self.home / "probe-actions").read_text(), "status")
        self.assertIn("连接检查尚未通过", result.stderr)
        self.assertNotIn("本次已检查的 WebSocket 链路通过", result.stdout)
        self.assertEqual((self.home / "service-actions").read_text().splitlines(), ["--user start insta-box-quick.service"])
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_repair_does_not_reenable_disabled_quick_or_create_missing_service(self):
        result = self.repair(probe=0, active=False, enabled=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("快捷隧道已停用", result.stdout)
        self.assertFalse((self.home / "service-actions").exists())
        (self.home / ".config/systemd/user/insta-box-quick.service").unlink()
        result = self.repair(probe=1, unit=False, active=False, enabled=False)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("未找到可管理的快捷服务", result.stderr)
        self.assertFalse((self.home / ".config/systemd/user/insta-box-quick.service").exists())

    def test_repair_reports_service_start_failure_even_if_probe_recovers(self):
        result = self.repair(start_ok=False, probe=0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("仍有服务操作失败", result.stderr)

    def test_existing_install_does_not_hide_repair_failure_with_link_display(self):
        result = self.repair(probe=2, installed=True)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn("SHOW_LINKS", result.stdout)

    def test_existing_install_preserves_errexit_inside_nested_repair(self):
        result = self.repair(installed=True, helper_fails=True)
        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("UNSAFE_CONTINUED", result.stdout)
        self.assertFalse((self.home / "probe-actions").exists())

    def test_repair_does_not_report_success_if_current_displayed_host_check_fails(self):
        result = self.repair(probe=0, show_status=1)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("本次已检查的 WebSocket 链路通过", result.stdout)
        self.assertIn("SHOW_LINKS", result.stdout)

    def autostart(self, action, *, readback=None, linger="yes", node="enabled", foreign=False):
        units = self.home / ".config/systemd/user"
        units.mkdir(parents=True, exist_ok=True)
        (units / "insta-box-quick.service").write_text("# Other owner\n" if foreign else "# Managed-by: InstaBox Tool\n")
        script = Path(self.temp.name) / "autostart.sh"
        script.write_text(LIBRARY + '''
preflight() { :; }
ensure_linger() { :; }
loginctl() { printf '%s\\n' "''' + linger + '''"; }
fixture_boot_state=disabled
systemctl() {
  case "${2:-}" in
    enable|disable)
      printf '%s\\n' "$*" >> "$HOME/boot-actions"
      if [[ "$2" == enable ]]; then fixture_boot_state=enabled; else fixture_boot_state=disabled; fi;;
    is-enabled)
      if [[ "${3:-}" == "$SB_SERVICE" ]]; then printf '%s\\n' "''' + node + '''"
      else printf '%s\\n' "''' + (readback if readback else "$fixture_boot_state") + '''"; fi;;
    is-active) printf 'active\\n';;
    *) printf 'Unexpected mutation\\n' >&2; exit 97;;
  esac
}
quick_autostart_main ''' + action + "\n")
        return subprocess.run(["bash", str(script)], env=self.env, capture_output=True, text=True, timeout=5)

    def test_autostart_enable_disable_only_changes_next_boot(self):
        before = {path: path.read_bytes() for path in (self.state, self.config, self.launcher)}
        for action in ("enable", "disable"):
            with self.subTest(action=action):
                result = self.autostart(action)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.home / "boot-actions").read_text().splitlines(), [
            "--user enable insta-box-quick.service", "--user disable insta-box-quick.service"])
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse((self.app / "captured-args.json").exists())

    def test_autostart_rejects_unconfirmed_persistence_linger_and_dependency(self):
        for options in ({"readback": "enabled-runtime"}, {"linger": "no"}, {"node": "disabled"}):
            with self.subTest(options=options):
                result = self.autostart("enable", **options)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("[OK] 已开启开机重建", result.stdout)
        result = self.autostart("disable", readback="enabled")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_autostart_status_and_foreign_units_do_not_change_services(self):
        result = self.autostart("status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.home / "boot-actions").exists())
        result = self.autostart("enable", foreign=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.home / "boot-actions").exists())


if __name__ == "__main__":
    unittest.main()
