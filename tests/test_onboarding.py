"""Offline first-install authorization and installer side-effect boundaries."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import warnings


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("onboarding_cloud", ROOT / "cloud.py")
cloud = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud)
KEY = "ibk_FAKE_ONBOARDING_VALID_KEY"
OLD_KEY = "ibk_FAKE_ONBOARDING_PREVIOUS_KEY"
INSTALLER = (ROOT / "install.sh").read_text()
LIBRARY, DISPATCH = INSTALLER.rsplit('case "${1:-install}" in', 1)


class Response(io.BytesIO):
    def __init__(self, status, payload):
        super().__init__(json.dumps(payload).encode() if not isinstance(payload, bytes) else payload)
        self.status = status


class HTTP:
    """Queued read-only replies; no network or real credentials are used."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def open(self, request, timeout):
        url = urllib.parse.urlsplit(request.full_url)
        assert (url.scheme, url.netloc) == ("https", "api.instabox.sh")
        assert request.get_method() == "GET" and request.data is None
        assert url.path in ("/v1/me", "/v1/machines") and not url.fragment
        self.calls.append({"path": url.path, "query": urllib.parse.parse_qs(url.query),
                           "headers": {key.lower(): value for key, value in request.header_items()}})
        if not self.steps:
            raise AssertionError("Unexpected authorization request")
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        status, payload = step
        if status >= 300:
            raise urllib.error.HTTPError(request.full_url, status, "fixture", {}, Response(status, payload))
        return Response(status, payload)


def authorized_http():
    return HTTP((200, {"inviteRequired": False, "activated": True}),
                (200, {"machines": [{"id": "m_fixture", "name": "fixture"}]}))


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibt-onboarding-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.config = self.home / ".config/insta-box"
        self.key_path = self.config / "api-key"
        env = mock.patch.dict(os.environ, {"HOME": str(self.home), "INSTABOX_API_KEY": ""})
        env.start()
        self.addCleanup(env.stop)
        self.output = io.StringIO()

    def save(self, value=OLD_KEY):
        self.config.mkdir(parents=True, mode=0o700)
        self.config.chmod(0o700)
        self.key_path.write_text(value + "\n")
        self.key_path.chmod(0o600)

    def ensure(self, http, value=KEY):
        with mock.patch.dict(os.environ, {"INSTABOX_API_KEY": value}), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output):
            return cloud.ensure_api(self.config)

    def assert_no_install(self):
        self.assertFalse(self.config.exists(), "failed authorization created a private credential directory")
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse((self.home / ".config/systemd").exists())

    def test_environment_key_is_persisted_only_after_account_and_list_access(self):
        http = authorized_http()
        api = self.ensure(http)
        self.assertIsInstance(api, cloud.API)
        self.assertEqual(api.key, KEY)
        self.assertEqual([call["path"] for call in http.calls], ["/v1/me", "/v1/machines"])
        self.assertTrue(all(call["headers"]["x-api-key"] == KEY for call in http.calls))
        self.assertEqual(self.key_path.read_text(), KEY + "\n")
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o700)
        self.assertEqual(self.key_path.stat().st_uid, os.getuid())
        self.assertNotIn(KEY, self.output.getvalue())
        self.assertFalse((self.home / ".config/systemd").exists())

    def test_saved_key_is_revalidated_without_prompt_or_rewriting_cache(self):
        self.save(KEY)
        original = (self.key_path.read_bytes(), self.key_path.stat().st_ino, self.key_path.stat().st_mtime_ns)
        http = authorized_http()
        with mock.patch.object(cloud.getpass, "getpass", side_effect=AssertionError("cached key prompted")):
            self.assertEqual(self.ensure(http, "").key, KEY)
        self.assertEqual([call["path"] for call in http.calls], ["/v1/me", "/v1/machines"])
        self.assertEqual((self.key_path.read_bytes(), self.key_path.stat().st_ino, self.key_path.stat().st_mtime_ns), original)

    def test_rejected_environment_key_never_overwrites_saved_working_key(self):
        self.save()
        original = (self.key_path.read_bytes(), self.key_path.stat().st_ino)
        http = HTTP((401, {"error": {"code": "api_key_revoked", "message": KEY}}))
        with self.assertRaises(cloud.CloudError) as caught:
            self.ensure(http)
        self.assertNotIn(KEY, str(caught.exception) + self.output.getvalue())
        self.assertEqual((self.key_path.read_bytes(), self.key_path.stat().st_ino), original)
        self.assertEqual(len(http.calls), 1)

    def test_valid_replacement_key_is_saved_after_both_read_permissions(self):
        self.save()
        self.ensure(authorized_http())
        self.assertEqual(self.key_path.read_text(), KEY + "\n")
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        self.assertEqual(list(self.config.iterdir()), [self.key_path], "atomic save left a temporary secret file")

    def test_machine_read_permission_is_required_before_persisting_key(self):
        http = HTTP((200, {"activated": True}),
                    (403, {"error": {"code": "insufficient_scope", "message": KEY}}))
        with self.assertRaises(cloud.CloudError) as caught:
            self.ensure(http)
        self.assertNotIn(KEY, str(caught.exception) + self.output.getvalue())
        self.assertEqual(len(http.calls), 2)
        self.assert_no_install()

    def test_all_machine_pages_must_validate_before_persisting_key(self):
        http = HTTP((200, {}), (200, {"machines": [{"id": "m_first"}], "nextCursor": "second"}),
                    (200, {"machines": "malformed " + KEY}))
        with self.assertRaises(cloud.CloudError):
            self.ensure(http)
        self.assertEqual(http.calls[-1]["query"], {"cursor": ["second"]})
        self.assert_no_install()

    def test_empty_machine_list_is_valid_account_read_access(self):
        self.ensure(HTTP((200, {}), (200, {"machines": []})))
        self.assertTrue(self.key_path.is_file())

    def test_pending_invitation_is_rejected_before_machine_reads_or_saving(self):
        for me in ({"inviteRequired": True}, {"inviteRequired": True, "activated": False}):
            with self.subTest(me=me):
                http = HTTP((200, me))
                with self.assertRaises(cloud.CloudError):
                    self.ensure(http)
                self.assertEqual(len(http.calls), 1)
                self.assert_no_install()

    def test_activated_invitation_and_optional_gate_fields_are_supported(self):
        for me in ({"inviteRequired": True, "activated": True},
                   {"inviteRequired": False, "activated": False}, {}):
            with self.subTest(me=me):
                self.ensure(HTTP((200, me), (200, {"machines": []})))
                self.assertEqual(self.key_path.read_text(), KEY + "\n")

    def test_malformed_gate_flags_never_become_truthy_authorization(self):
        for field in ("inviteRequired", "activated"):
            for value in ("true", "false", 0, 1, None, [], {}):
                with self.subTest(field=field, value=value):
                    http = HTTP((200, {field: value}))
                    with self.assertRaises(cloud.CloudError):
                        self.ensure(http)
                    self.assertEqual(len(http.calls), 1)
                    self.assert_no_install()

    def test_transport_redirect_and_malformed_account_fail_closed(self):
        cases = [(302, {"message": KEY}), (200, b"not JSON " + KEY.encode()),
                 (200, [KEY]), urllib.error.URLError(KEY), TimeoutError(KEY)]
        for step in cases:
            with self.subTest(step=type(step).__name__):
                with self.assertRaises(cloud.CloudError) as caught:
                    self.ensure(HTTP(step))
                self.assertNotIn(KEY, str(caught.exception) + self.output.getvalue())
                self.assert_no_install()

    def test_invalid_key_format_is_rejected_before_http_or_persistence(self):
        for value in ("arbitrary", "ibk_", "ibk_bad value", "ibk_a\nb", "ibk_$(echo unsafe)", "ibk_" + "a" * 4093):
            with self.subTest(length=len(value)):
                http = HTTP()
                with self.assertRaises(cloud.CloudError):
                    self.ensure(http, value)
                self.assertEqual(http.calls, [])
                self.assert_no_install()

    def test_pipe_stdin_does_not_prevent_getpass_from_using_controlling_terminal(self):
        redirected = io.StringIO("do not read a secret from this pipe\n")
        with mock.patch.object(cloud.sys, "stdin", redirected), \
             mock.patch.object(cloud.getpass, "getpass", return_value=KEY) as secret_input:
            self.ensure(authorized_http(), "")
        self.assertFalse(redirected.isatty())
        self.assertEqual(redirected.tell(), 0, "authorization consumed the install script's standard input")
        secret_input.assert_called_once()
        self.assertNotIn("stream", secret_input.call_args.kwargs, "getpass must select the controlling TTY itself")
        self.assertEqual(self.key_path.read_text(), KEY + "\n")
        self.assertNotIn(KEY, self.output.getvalue())

    def test_missing_terminal_or_input_cancels_without_request_or_persistence(self):
        for failure in (EOFError(), OSError("no controlling TTY")):
            with self.subTest(failure=type(failure).__name__):
                http = HTTP()
                with mock.patch.object(cloud.getpass, "getpass", side_effect=failure), \
                     self.assertRaises(cloud.CloudError):
                    self.ensure(http, "")
                self.assertEqual(http.calls, [])
                self.assert_no_install()

    def test_echo_fallback_is_rejected_before_secret_input(self):
        def echo_fallback(*args, **kwargs):
            warnings.warn("cannot disable echo", cloud.getpass.GetPassWarning)
            self.fail("unsafe echoed input was allowed to continue")

        http = HTTP()
        with mock.patch.object(cloud.getpass, "getpass", side_effect=echo_fallback), \
             self.assertRaises(cloud.CloudError):
            self.ensure(http, "")
        self.assertEqual(http.calls, [])
        self.assert_no_install()

    def test_symlinked_or_shared_key_is_rejected_even_with_environment_authorization(self):
        self.save()
        original = self.key_path.read_bytes()
        outside = self.home / "outside-key"
        self.key_path.rename(outside)
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.key_path.symlink_to(outside)
                else:
                    os.link(outside, self.key_path)
                http = HTTP()
                try:
                    with self.assertRaises(cloud.CloudError):
                        self.ensure(http)
                    self.assertEqual(http.calls, [])
                    self.assertEqual(outside.read_bytes(), original)
                finally:
                    self.key_path.unlink()

    def test_nonprivate_existing_directory_is_not_silently_repaired(self):
        self.save()
        self.config.chmod(0o775)
        http = HTTP()
        with self.assertRaises(cloud.CloudError):
            self.ensure(http)
        self.assertEqual(http.calls, [])
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o775)
        self.assertEqual(self.key_path.read_text(), OLD_KEY + "\n")

    def test_cli_ensure_uses_validation_entry_point(self):
        with mock.patch.object(cloud, "ensure_api", return_value=object()) as ensure, \
             mock.patch.object(cloud, "load_api", side_effect=AssertionError("generic API loading bypassed the gate")):
            self.assertEqual(cloud.main(["key", "ensure"]), 0)
        ensure.assert_called_once_with(self.config)


INSTALL_FIXTURES = r'''
record() { printf '%s\n' "$*" >> "$HOME/install-actions"; }
preflight() { record preflight; }
validate_port() { record validate-port; PORT=20000; }
install_singbox() {
  record install-singbox
  mkdir -p "$BIN_DIR"
  printf '{"fixture":"preserve"}\n' > "$CONFIG"
  UUID='11111111-1111-4111-8111-111111111111'
  WS_PATH='/ws-11111111-1111-4111-8111-111111111111'
}
install_singbox_unit() {
  record node-service
  mkdir -p "$UNIT_DIR"
  printf '%s\n' "$MARKER" > "$SB_UNIT"
}
ensure_linger() { record linger; }
ensure_cloudflared() { record cloudflared; }
install_named_tunnel_unit() { record named-service; }
write_quick_launcher() { record quick-launcher; }
install_quick_unit() {
  record quick-service
  printf '%s\n' "$MARKER" > "$QUICK_UNIT"
}
report_quick_connection() { record quick-probe; return "${FIXTURE_PROBE_RC:-0}"; }
repair_main() { record repair; return "${FIXTURE_REPAIR_RC:-0}"; }
'''


class DirectInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibt-first-node-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.app = self.home / ".local/share/insta-box"
        self.events = self.home / "install-actions"
        self.installer = self.root / "install.sh"
        # Keep the real install_main and every real CLI route. Only external
        # actions have fixture implementations, so no root/network/systemd is
        # needed to exercise the ordering and return status of the gate.
        self.installer.write_text(LIBRARY + INSTALL_FIXTURES + 'case "${1:-install}" in' + DISPATCH)
        (self.root / "ibt.sh").write_text((ROOT / "ibt.sh").read_text())
        (self.root / "cloud.py").write_text('''import os
from pathlib import Path
import sys
assert sys.argv[1:] == ["key", "ensure"], "API Key must never be passed as an argument"
with (Path.home() / "install-actions").open("a") as log:
    log.write("authorize:key ensure\\n")
raise SystemExit(int(os.environ.get("FIXTURE_AUTH_RC", "0")))
''')
        (self.root / "heartbeat.py").write_text('''import os
from pathlib import Path
import sys
assert sys.argv[1:] == ["auto-local"], "Unexpected automatic heartbeat command"
with (Path.home() / "install-actions").open("a") as log:
    log.write("heartbeat:auto-local\\n")
raise SystemExit(int(os.environ.get("FIXTURE_AUTO_RC", "0")))
''')
        self.env = {**os.environ, "HOME": str(self.home), "INSTABOX_API_KEY": KEY,
                    "PYTHONDONTWRITEBYTECODE": "1", "IBT_NO_SUDO": "1"}
        for name in ("IBT_DOMAIN", "IB_DOMAIN", "SB_DOMAIN", "IBT_PORT", "IB_PORT", "SB_PORT"):
            self.env.pop(name, None)

    def run_core(self, args=("install",), *, menu=False, trace=False, **extra):
        script = self.root / "ibt.sh" if menu else self.installer
        command = ["bash", *(["-x"] if trace else []), str(script), *args]
        return subprocess.run(command, env={**self.env, **extra}, capture_output=True, text=True, timeout=10)

    def actions(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_default_install_and_ibt_install_cannot_bypass_rejected_key(self):
        for args, menu in (((), False), (("install",), False), (("install",), True)):
            with self.subTest(args=args, menu=menu):
                self.events.unlink(missing_ok=True)
                result = self.run_core(args, menu=menu, FIXTURE_AUTH_RC="1")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.actions(), ["preflight", "authorize:key ensure"])
                self.assertFalse(self.app.exists())
                self.assertFalse((self.home / ".config/systemd").exists())
                self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_incomplete_single_file_installer_has_no_ungated_fallback(self):
        for name in ("cloud.py", "heartbeat.py"):
            with self.subTest(name=name):
                helper = self.root / name
                original = helper.read_bytes()
                helper.unlink()
                self.events.unlink(missing_ok=True)
                try:
                    result = self.run_core()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.actions(), ["preflight"])
                    self.assertFalse(self.app.exists())
                finally:
                    helper.write_bytes(original)

    def test_existing_node_repair_keeps_configuration_and_requires_no_key(self):
        self.app.mkdir(parents=True, mode=0o700)
        state, config = self.app / "state.conf", self.app / "config.json"
        state.write_text("existing state is preserved\n")
        config.write_text('{"existing":"configuration"}\n')
        before = [(path.read_bytes(), path.stat().st_ino) for path in (state, config)]
        result = self.run_core(FIXTURE_AUTH_RC="1", FIXTURE_REPAIR_RC="7", INSTABOX_API_KEY="")
        self.assertEqual(result.returncode, 7, result.stderr + result.stdout)
        self.assertEqual(self.actions(), ["preflight", "repair"])
        self.assertEqual([(path.read_bytes(), path.stat().st_ino) for path in (state, config)], before)

    def test_authorization_precedes_node_changes_and_automatic_local_keepalive(self):
        result = self.run_core()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        actions = self.actions()
        self.assertLess(actions.index("authorize:key ensure"), actions.index("install-singbox"))
        self.assertLess(actions.index("quick-service"), actions.index("heartbeat:auto-local"))
        self.assertEqual(actions.count("heartbeat:auto-local"), 1)
        self.assertTrue((self.app / "state.conf").is_file())
        self.assertTrue((self.home / ".config/systemd/user/insta-box-quick.service").is_file())

    def test_automatic_keepalive_failure_is_nonzero_and_keeps_node_for_retry(self):
        result = self.run_core(FIXTURE_AUTO_RC="2")
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertTrue((self.app / "state.conf").is_file())
        self.assertTrue((self.app / "config.json").is_file())
        self.assertEqual(self.actions()[-1], "heartbeat:auto-local")
        self.assertIn("ibt keepalive auto-local", result.stderr)
        self.assertNotIn("本机自动保活已启用", result.stdout)

    def test_unsuccessful_quick_probe_still_attempts_automatic_keepalive(self):
        result = self.run_core(FIXTURE_PROBE_RC="1")
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertEqual(self.actions()[-1], "heartbeat:auto-local")
        self.assertIn("网络连接仍需排查", result.stderr)
        self.assertIn("ibt diagnose", result.stderr)

    def test_shell_trace_and_helper_arguments_do_not_include_key(self):
        result = self.run_core(trace=True, FIXTURE_AUTH_RC="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(KEY, result.stdout + result.stderr + self.events.read_text())
        self.assertIn("authorize:key ensure", self.actions())

    def test_tunnel_management_cannot_create_node_services_on_an_uninstalled_machine(self):
        result = self.run_core(("tunnel",))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.actions(), ["preflight"])
        self.assertFalse(self.app.exists())
        self.assertFalse((self.home / ".config/systemd").exists())


if __name__ == "__main__":
    unittest.main()
