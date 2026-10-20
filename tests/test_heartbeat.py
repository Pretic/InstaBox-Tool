"""Offline behavior/security regressions. Never contacts InstaBox or real SSH."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import heartbeat as hb

NOW = 1800000000.0
SECRET = "ibssh_FAKE_ONLY_TEST_SECRET_123"
KEY = "ibk_FAKE_ONLY_TEST_KEY_123"


def ssh_target(name="one", token=SECRET):
    return {"id": "ssh_" + name, "kind": "ssh", "label": "SSH " + name,
            "revision": "b" * 32, "ssh": {"user": token, "host": hb.GATEWAY, "port": 2222, "family": None},
            "tokenExpiry": {"kind": "unknown"}}


def api_target(name="one"):
    return {"id": "api_" + name, "kind": "api", "label": "Machine " + name,
            "revision": "c" * 32, "machineId": "m_" + name}


class Client:
    def __init__(self):
        self.calls = []
        self.failures = {}
        self.pages = {"/v1/machines": {"machines": [{"id": "m_one", "name": "One", "state": "running"},
                                                                  {"id": "m_two", "name": "Two", "state": "suspended"}]}}

    def request(self, method, route, key, body=None):
        self.calls.append((method, route, key, body))
        for pattern, error in self.failures.items():
            if pattern in route:
                raise error
        if method == "GET":
            if route == "/v1/me":
                return {"manualLifecycle": False, "fixedAutoSuspendSeconds": 1800,
                        "inviteRequired": False, "activated": True}
            if route.startswith("/v1/machines/"):
                for page in self.pages.values():
                    for machine in page.get("machines", []):
                        if machine["id"] == route.rsplit("/", 1)[-1]:
                            return dict(machine)
                raise hb.HeartbeatError("目标机器不存在。", "not_found")
            return self.pages[route]
        if method == "DELETE":
            return None
        if method == "PUT":
            return {"id": route.split("/")[-1], "machineId": route.split("/")[3], "expiresAt": hb.iso_time(NOW + body["ttlSeconds"])}
        raise AssertionError("Unexpected HTTP operation")


class Runner:
    def __init__(self):
        self.calls = []
        self.ssh_configs = []
        self.active = False
        self.enabled = False
        self.service_active = False
        self.service_properties = None
        self.show_returncode = 0
        self.timer_rows = [{"unit": hb.TIMER, "activates": hb.SERVICE,
                            "next": int((NOW + 317) * 1000000), "last": int((NOW - 29) * 1000000)}]
        self.timer_stdout = None
        self.timers_returncode = 0
        self.linger = True
        self.fail_enable = False
        self.fail_stop = False
        self.ssh_returncode = 0
        self.ssh_stdout = hb.SSH_MARKER + "\n"
        self.ssh_stderr = ""
        self.ssh_timeout = False
        self.guard = threading.Lock()
        self.running_ssh = 0
        self.max_ssh = 0
        self.delay = 0

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        code, stdout, stderr = 0, "", ""
        if args[0] == "ssh":
            self.assert_safe(args, kwargs)
            filename = Path(args[args.index("-F") + 1])
            self.ssh_configs.append((filename, filename.read_text(), stat.S_IMODE(filename.stat().st_mode)))
            with self.guard:
                self.running_ssh += 1
                self.max_ssh = max(self.max_ssh, self.running_ssh)
            try:
                if self.delay:
                    time.sleep(self.delay)
                if self.ssh_timeout:
                    raise subprocess.TimeoutExpired(args, kwargs["timeout"], output=SECRET, stderr=SECRET)
                code, stdout, stderr = self.ssh_returncode, self.ssh_stdout, self.ssh_stderr
            finally:
                with self.guard:
                    self.running_ssh -= 1
        elif args[0] == "systemctl":
            command = args[2]
            if command == "enable":
                if self.fail_enable:
                    code = 1
                else:
                    self.active = self.enabled = True
            elif command == "disable":
                if self.fail_stop:
                    code = 1
                else:
                    self.active = self.enabled = False
            elif command == "stop":
                if self.fail_stop:
                    code = 1
                else:
                    self.service_active = False
            elif command == "is-active":
                active = self.service_active if args[-1] == hb.SERVICE else self.active
                code, stdout = (0, "active\n") if active else (3, "inactive\n")
            elif command == "is-enabled":
                code, stdout = (0, "enabled\n") if self.enabled else (1, "disabled\n")
            elif command == "show":
                code = self.show_returncode
                stdout = self.service_properties if self.service_properties is not None else (
                    "Id=" + hb.SERVICE + "\nLoadState=loaded\nActiveState=" + ("activating" if self.service_active else "inactive") +
                    "\nSubState=" + ("start" if self.service_active else "dead") + "\n")
            elif command == "list-timers":
                code = self.timers_returncode
                stdout = self.timer_stdout if self.timer_stdout is not None else json.dumps(self.timer_rows)
        elif args[0] == "loginctl":
            stdout = "yes\n" if self.linger else "no\n"
        elif args[0] == "journalctl":
            stdout = "probe " + SECRET + " API " + KEY + "\n"
        return subprocess.CompletedProcess(args, code, stdout, stderr)

    @staticmethod
    def assert_safe(args, kwargs):
        if SECRET in " ".join(args):
            raise AssertionError("SSH token leaked in argv")
        if kwargs.get("shell"):
            raise AssertionError("Shell execution is forbidden")
        if kwargs["timeout"] != 45:
            raise AssertionError("Missing overall SSH timeout")


class Fixture(unittest.TestCase):
    def setUp(self):
        # This location also works in restricted workspaces without a /tmp mount.
        self.temp = tempfile.TemporaryDirectory(prefix="ib-heartbeat-test-", dir=ROOT.parent)
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir(mode=0o700)
        self.client, self.runner, self.lines = Client(), Runner(), []
        self.now = NOW
        self.manager = hb.Manager(home=self.home, client=self.client, runner=self.runner, clock=lambda: self.now,
                                  output=self.lines.append, env={"IBT_NO_SUDO": "1"})

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, targets, interval=300):
        config = {"schema": 1, "controllerId": "a" * 32, "leasePrefix": "ib", "intervalSeconds": interval, "targets": targets}
        self.manager.ensure_cfg(create=True)
        hb.atomic_json(self.manager.config_file, config)
        return config

    def add_key(self):
        self.manager.ensure_cfg(create=True)
        hb.atomic_text(self.manager.key_file, KEY + "\n")

    def state(self):
        return json.loads(self.manager.state_file.read_text())


class ParserTests(unittest.TestCase):
    def test_supported_quotes_and_standard_port_semantics(self):
        commands = [
            'mosh --ssh="ssh -p 2222" ' + SECRET + "@api.instabox.sh",
            "mosh --ssh='ssh -p 2222' " + SECRET + "@api.instabox.sh",
            "mosh --ssh 'ssh -p2222' --no-init " + SECRET + "@api.instabox.sh",
            "ssh -p 2222 " + SECRET + "@API.INSTABOX.SH",
        ]
        for command in commands:
            with self.subTest(command=command[:20]):
                self.assertEqual(hb.parse_ssh_command(command)["port"], 2222)
        self.assertEqual(hb.parse_ssh_command("ssh " + SECRET + "@api.instabox.sh")["port"], 22)
        self.assertEqual(hb.parse_ssh_command("mosh " + SECRET + "@api.instabox.sh")["port"], 22)
        self.assertEqual(hb.parse_ssh_command("ssh -p 65535 -6 " + SECRET + "@api.instabox.sh")["family"], "inet6")
        self.assertEqual(hb.parse_ssh_command("mosh -4 --ssh='ssh -p 1' " + SECRET + "@api.instabox.sh")["port"], 1)

    def test_injection_options_and_extra_commands_never_execute(self):
        destination = SECRET + "@api.instabox.sh"
        invalid = [
            "ssh " + destination + "; touch bad", "ssh " + destination + " && true",
            "ssh $(touch bad)@api.instabox.sh", "ssh `touch bad`@api.instabox.sh",
            "ssh -oProxyCommand=evil " + destination, "ssh -F /some/config " + destination,
            "ssh " + destination + " true", "ssh " + destination + "\ntrue", "ssh " + destination + " | cat",
            "mosh --ssh='ssh -o ProxyCommand=evil' " + destination,
            "mosh --ssh='evil -p 2222' " + destination, "mosh --ssh='ssh -p 2222' " + destination + " bash",
            "mosh --ssh='ssh -p 2222' --ssh='ssh -p 2222' " + destination,
            "ssh -p 0 " + destination, "ssh -p 65536 " + destination,
            "ssh -p 22 -p 2222 " + destination, "ssh -4 -6 " + destination,
            "ssh " + SECRET + "@evil.example", "ssh " + SECRET + "@api.instabox.sh.evil.example",
            "ssh " + SECRET + "@api.instabox.sh/anything", "ssh random@api.instabox.sh",
        ]
        with mock.patch("subprocess.run") as run:
            for command in invalid:
                with self.subTest(command=command[:30]):
                    with self.assertRaises(hb.HeartbeatError):
                        hb.parse_ssh_command(command)
            run.assert_not_called()

    def test_unknown_and_estimated_expiry_are_not_inferred_from_token(self):
        self.assertEqual(hb.token_expiry("", NOW), {"kind": "unknown"})
        expiry = hb.token_expiry("1.5", NOW)
        self.assertEqual(expiry, {"kind": "estimated", "expiresAt": hb.iso_time(NOW + 5400)})
        for number in ("nan", "inf", "0", "-2", "not-a-number"):
            with self.assertRaises(hb.HeartbeatError):
                hb.token_expiry(number, NOW)


class StorageAndSSHTests(Fixture):
    def test_no_terminal_never_falls_back_to_echoed_secret_input(self):
        with mock.patch.object(hb.os, "open", side_effect=OSError("no tty")), mock.patch.object(hb.getpass, "getpass") as read:
            with self.assertRaises(hb.HeartbeatError) as raised:
                hb.secret_prompt("secret")
            self.assertEqual(raised.exception.code, "tty")
            read.assert_not_called()

    def test_private_permissions_and_token_is_only_in_temporary_config(self):
        self.configure([ssh_target()])
        self.assertEqual(self.manager.run_once(), 0)
        self.assertEqual(stat.S_IMODE(self.manager.cfg.stat().st_mode), 0o700)
        for filename in (self.manager.config_file, self.manager.state_file, self.manager.known_hosts):
            self.assertEqual(stat.S_IMODE(filename.stat().st_mode), 0o600)
        filename, config, mode = self.runner.ssh_configs[0]
        self.assertEqual(mode, 0o600)
        self.assertIn("Host ib-heartbeat\n", config)
        command = next(args for args, _ in self.runner.calls if args[0] == "ssh")
        self.assertEqual(command[-2:], ["ib-heartbeat", "printf '%s\\n' 'IB_HEARTBEAT_OK'"])
        self.assertIn("User " + SECRET, config)
        self.assertIn("IdentityAgent none", config)
        self.assertIn("PubkeyAuthentication no", config)
        self.assertIn("ClearAllForwardings yes", config)
        self.assertIn("StrictHostKeyChecking accept-new", config)
        self.assertIn("ConnectTimeout 15", config)
        self.assertFalse(filename.exists())
        self.assertNotIn(SECRET, self.manager.state_file.read_text())
        self.assertNotIn(SECRET, "\n".join(self.lines))
        self.assertFalse(self.client.calls, "SSH must not request API access")

    def test_symlink_config_key_and_knownhosts_are_refused(self):
        self.manager.ensure_cfg(create=True)
        outside = self.home / "outside"
        outside.write_text("untouched")
        for filename in (self.manager.config_file, self.manager.key_file, self.manager.known_hosts):
            with self.subTest(filename=filename.name):
                filename.symlink_to(outside)
                with self.assertRaises(hb.HeartbeatError):
                    hb.read_private(filename)
                with self.assertRaises(hb.HeartbeatError):
                    hb.atomic_text(filename, "new")
                filename.unlink()
        self.assertEqual(outside.read_text(), "untouched")
        self.assertFalse(self.runner.calls)

    def test_symlink_directory_and_foreign_owner_are_refused(self):
        (self.home / ".config").mkdir()
        other = self.home / "other"
        other.mkdir()
        self.manager.cfg.symlink_to(other, target_is_directory=True)
        with self.assertRaises(hb.HeartbeatError):
            self.manager.ensure_cfg(create=True)
        self.manager.cfg.unlink()
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid() + 1)
        with mock.patch.object(hb.os, "lstat", return_value=info):
            with self.assertRaises(hb.HeartbeatError):
                hb.check_owned(self.home / "foreign")

    def test_status_does_not_fix_or_read_insecure_private_files(self):
        self.configure([ssh_target()])
        self.manager.config_file.chmod(0o644)
        with self.assertRaises(hb.HeartbeatError):
            self.manager.status()
        self.assertEqual(stat.S_IMODE(self.manager.config_file.stat().st_mode), 0o644)

    def test_ssh_error_timeout_and_missing_marker_are_never_success(self):
        self.configure([ssh_target()])
        self.runner.ssh_returncode = 255
        self.runner.ssh_stderr = "Permission denied " + SECRET + " " + KEY
        self.assertEqual(self.manager.run_once(), 2)
        self.assertEqual(self.state()["targets"][0]["errorCode"], "ssh_failed")
        self.assertNotIn(SECRET, self.manager.state_file.read_text())
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.runner.ssh_returncode, self.runner.ssh_stdout = 0, "hello\n"
        self.assertEqual(self.manager.run_once(), 2)
        self.assertEqual(self.state()["targets"][0]["errorCode"], "ssh_marker")
        self.runner.ssh_timeout = True
        self.assertEqual(self.manager.run_once(), 2)
        self.assertEqual(self.state()["targets"][0]["errorCode"], "ssh_timeout")
        self.assertFalse(list(self.manager.cfg.glob(".heartbeat-ssh-*")))

    def test_one_target_failure_isolated_and_parallelism_bounded(self):
        targets = [ssh_target(str(i), "ibssh_TEST_" + str(i)) for i in range(19)] + [api_target("bad")]
        self.configure(targets)
        self.add_key()
        self.client.failures["m_bad"] = hb.HeartbeatError("无权限 " + KEY, "forbidden")
        self.runner.delay = 0.01
        self.assertEqual(self.manager.run_once(), 2)
        rows = self.state()["targets"]
        self.assertEqual(sum(row["result"] == "success" for row in rows), 19)
        self.assertEqual(rows[-1]["errorCode"], "forbidden")
        self.assertGreater(self.runner.max_ssh, 1)
        self.assertLessEqual(self.runner.max_ssh, 4)
        self.assertNotIn(KEY, self.manager.state_file.read_text())
        self.assertEqual(self.client.calls[0][0], "PUT")

    def test_overlapping_round_is_rejected_without_network_or_old_success(self):
        self.configure([api_target()])
        self.add_key()
        another = hb.Manager(home=self.home, client=self.client, runner=self.runner, output=self.lines.append)
        with self.manager.lock() as acquired:
            self.assertTrue(acquired)
            self.assertEqual(another.run_once(), 2)
        self.assertFalse(self.client.calls)
        self.assertFalse(self.manager.state_file.exists())

    def test_killed_round_temporary_credential_is_cleaned_before_next_round(self):
        self.configure([ssh_target()])
        leftover = self.manager.cfg / ".heartbeat-ssh-interrupted"
        hb.atomic_text(leftover, "User " + SECRET + "\n")
        self.assertEqual(self.manager.run_once(), 0)
        self.assertFalse(leftover.exists())
        self.assertFalse(list(self.manager.cfg.glob(".heartbeat-ssh-*")))


class Response:
    def __init__(self, status, value):
        self.status = status
        self.value = value if isinstance(value, bytes) else json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return self.value[:size]


class HTTPTests(Fixture):
    def transport(self, response):
        calls = []
        class Opener:
            def open(self, request, timeout):
                calls.append((request, timeout))
                if isinstance(response, Exception):
                    raise response
                return response
        return hb.APIClient(opener_factory=Opener), calls

    def test_exact_lease_path_header_body_and_controller_identity(self):
        target = api_target()
        config = self.configure([target])
        identity = hb.lease_id(config["controllerId"], target["machineId"])
        self.assertEqual(identity, hb.lease_id(config["controllerId"], target["machineId"]))
        self.assertNotEqual(identity, hb.lease_id("d" * 32, target["machineId"]))
        self.assertLessEqual(len(identity), 64)
        client, calls = self.transport(Response(200, {"id": identity, "machineId": target["machineId"], "expiresAt": hb.iso_time(NOW + 900)}))
        self.manager.client = client
        self.assertEqual(self.manager.check_api(target, config, KEY)["expiresAt"], hb.iso_time(NOW + 900))
        request, timeout = calls[0]
        self.assertEqual(request.full_url, "https://api.instabox.sh/v1/machines/m_one/activity-leases/" + identity)
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(request.get_header("X-api-key"), KEY)
        self.assertFalse(any(name.lower() == "idempotency-key" for name, _ in request.header_items()))
        self.assertEqual(json.loads(request.data), {"ttlSeconds": 900})
        self.assertEqual(timeout, 20)
        self.assertEqual(hb.lease_ttl(900), 2700)

    def test_new_controller_uses_new_namespace_without_touching_legacy_paths(self):
        config = self.manager.new_config()
        self.assertEqual(self.manager.cfg, self.home / ".config" / "insta-box")
        self.assertEqual(config["leasePrefix"], "ib")
        self.manager.validate_config(config)
        self.manager.check_api(api_target(), config, KEY)
        route = self.client.calls[-1][1]
        self.assertIn("/activity-leases/ib-" + config["controllerId"] + "-", route)
        self.assertFalse((self.home / ".config" / "insta-sing-box").exists())

    def test_legacy_prefix_is_preserved_for_renewal_and_release(self):
        target = api_target()
        for explicit in (False, True):
            with self.subTest(explicit_prefix=explicit):
                config = self.configure([target])
                config.pop("leasePrefix")
                if explicit:
                    config["leasePrefix"] = "isb"
                before = json.dumps(config, sort_keys=True)
                self.manager.validate_config(config)
                self.client.calls.clear()
                self.manager.check_api(target, config, KEY)
                self.manager.release(target, config, KEY)
                expected = "/v1/machines/m_one/activity-leases/" + hb.lease_id(config["controllerId"], "m_one", "isb")
                self.assertEqual([(method, route) for method, route, _, _ in self.client.calls],
                                 [("PUT", expected), ("DELETE", expected)])
                self.assertEqual(json.dumps(config, sort_keys=True), before)

    def test_invalid_lease_prefix_is_rejected_before_remote_requests(self):
        for prefix in (None, "", "other", "ib/", [], {}):
            with self.subTest(prefix=prefix):
                config = self.manager.new_config()
                config["leasePrefix"] = prefix
                with self.assertRaises(hb.HeartbeatError):
                    self.manager.validate_config(config)
                with self.assertRaises(hb.HeartbeatError):
                    self.manager.check_api(api_target(), config, KEY)
                with self.assertRaises(hb.HeartbeatError):
                    self.manager.release(api_target(), config, KEY)
        self.assertFalse(self.client.calls)

    def test_errors_redirects_timeout_invalid_json_do_not_retry_or_leak_body(self):
        scenarios = [
            (urllib.error.HTTPError("https://api.instabox.sh/v1/machines", code, "bad " + KEY, {}, io.BytesIO(KEY.encode())), expected)
            for code, expected in ((403, "forbidden"), (409, "conflict"), (429, "rate_limited"), (302, "redirect"))
        ] + [(TimeoutError(SECRET), "timeout"), (Response(200, b"not-json " + KEY.encode()), "invalid_response")]
        for response, expected in scenarios:
            with self.subTest(expected=expected):
                client, calls = self.transport(response)
                with self.assertRaises(hb.HeartbeatError) as raised:
                    client.request("PUT", "/v1/machines/m_one/activity-leases/test", KEY, {"ttlSeconds": 900})
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn(KEY, str(raised.exception))
                self.assertNotIn(SECRET, str(raised.exception))
                self.assertEqual(len(calls), 1)
        self.assertIsNone(hb.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))

    def test_delete_accepts_only_204_or_404_and_post_requires_201(self):
        for response in (Response(204, b""), urllib.error.HTTPError("url", 404, "missing", {}, None)):
            client, _ = self.transport(response)
            self.assertIsNone(client.request("DELETE", "/v1/machines/m_one/activity-leases/test", KEY))
        client, _ = self.transport(Response(200, {}))
        with self.assertRaises(hb.HeartbeatError):
            client.request("DELETE", "/v1/machines/m_one/activity-leases/test", KEY)
        client, _ = self.transport(Response(201, {"id": "example"}))
        self.assertEqual(client.request("POST", "/v1/machines/m_one/ssh-tokens", KEY, {}), {"id": "example"})

    def test_invalid_lease_identity_expiry_and_response_shape_are_not_success(self):
        config = self.configure([api_target()])
        target = config["targets"][0]
        good = {"id": hb.lease_id(config["controllerId"], target["machineId"]), "machineId": "m_one", "expiresAt": hb.iso_time(NOW + 900)}
        invalid = [{**good, "id": "wrong"}, {**good, "machineId": "m_other"}, {**good, "expiresAt": hb.iso_time(NOW)},
                   {**good, "expiresAt": "2026-01-01"}, {**good, "expiresAt": None}, {"data": good}, []]
        for response in invalid:
            with self.subTest(response=response):
                with mock.patch.object(self.client, "request", return_value=response):
                    with self.assertRaises(hb.HeartbeatError):
                        self.manager.check_api(target, config, KEY)

    def test_paginated_machine_list_and_repeated_cursor(self):
        self.client.pages["/v1/machines"]["nextCursor"] = "a/b+ c"
        self.client.pages["/v1/machines?cursor=a%2Fb%2B+c"] = {"machines": [{"id": "m_three", "name": "Third", "state": "running"}]}
        self.assertEqual([machine["id"] for machine in self.manager.list_machines(KEY)], ["m_one", "m_two", "m_three"])
        self.client.pages["/v1/machines?cursor=a%2Fb%2B+c"]["nextCursor"] = "a/b+ c"
        with self.assertRaises(hb.HeartbeatError):
            self.manager.list_machines(KEY)

    def test_no_api_key_does_not_block_ssh_targets_or_prompt(self):
        self.configure([api_target(), ssh_target()])
        with mock.patch.object(self.manager, "secret", side_effect=AssertionError("Unexpected prompt")):
            self.assertEqual(self.manager.run_once(), 2)
        rows = self.state()["targets"]
        self.assertEqual(rows[0]["errorCode"], "key_missing")
        self.assertEqual(rows[1]["result"], "success")
        self.assertFalse(self.client.calls)


class LifecycleTests(Fixture):
    def test_interrupted_clear_never_returns_success_to_uninstaller(self):
        self.configure([ssh_target()])
        with mock.patch.object(self.manager, "clear", side_effect=KeyboardInterrupt()):
            self.assertEqual(hb.main(["clear"], manager=self.manager), 130)
        self.assertTrue(self.manager.config_file.exists())
        self.assertIn("操作未完成确认", "\n".join(self.lines))
        with mock.patch.object(self.manager, "clear", side_effect=EOFError()):
            self.assertNotEqual(hb.main(["clear"], manager=self.manager), 0)
        with mock.patch.object(self.manager, "run_once", side_effect=EOFError()):
            self.assertNotEqual(hb.main(["run"], manager=self.manager), 0)

    def test_status_unconfigured_is_read_only_and_friendly(self):
        self.assertEqual(self.manager.status(), 0)
        self.assertFalse((self.home / ".config").exists())
        self.assertFalse(self.runner.calls)
        self.assertIn("尚未配置", self.lines[-1])

    def test_stale_failed_or_revised_records_cannot_claim_health(self):
        config = self.configure([api_target()])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 0)
        self.assertEqual(self.manager.status(), 0)
        before = self.manager.config_file.stat().st_mtime_ns
        self.now += 1000
        self.assertEqual(self.manager.status(), 2)
        self.assertIn("旧成功记录已过期", "\n".join(self.lines))
        self.assertEqual(before, self.manager.config_file.stat().st_mtime_ns)
        self.now = NOW
        config["targets"][0]["revision"] = "d" * 32
        hb.atomic_json(self.manager.config_file, config)
        self.assertEqual(self.manager.status(), 2)
        self.assertIn("尚无此授权", "\n".join(self.lines))

    def test_known_and_estimated_ssh_expiry_have_different_labels(self):
        target = ssh_target()
        target["tokenExpiry"] = {"kind": "verified", "expiresAt": hb.iso_time(NOW + 100)}
        self.configure([target])
        self.manager.status()
        self.assertIn("授权到期：", "\n".join(self.lines))
        self.assertNotIn("预计到期：", "\n".join(self.lines))
        target["tokenExpiry"]["kind"] = "estimated"
        self.configure([target])
        self.lines.clear()
        self.manager.status()
        self.assertIn("预计到期：", "\n".join(self.lines))

    def test_timer_enable_failure_is_not_success_and_stable_exec_path(self):
        self.configure([ssh_target()])
        self.runner.fail_enable = True
        with self.assertRaises(hb.HeartbeatError):
            self.manager.enable_timer()
        unit = (self.manager.unit_dir / hb.SERVICE).read_text()
        self.assertEqual(hb.SERVICE, "insta-box-heartbeat.service")
        self.assertEqual(hb.TIMER, "insta-box-heartbeat.timer")
        self.assertIn("# Managed-by: InstaBox Tool Heartbeat\n", unit)
        self.assertIn('%h/.local/share/insta-box/cli/heartbeat.py', unit)
        self.assertNotIn("tool-releases", unit)
        self.assertIn("TimeoutStartSec=650", unit)
        timer = (self.manager.unit_dir / hb.TIMER).read_text()
        self.assertIn("OnStartupSec=30s", timer)
        self.assertIn("OnUnitInactiveSec=300s", timer)
        self.assertIn("RandomizedDelaySec=15s", timer)
        self.assertNotIn("退出终端后继续运行", "\n".join(self.lines))

    def test_missing_linger_respects_no_sudo_and_reports_limit(self):
        self.configure([ssh_target()])
        self.runner.linger = False
        for env in ({"IBT_NO_SUDO": "1"}, {"IB_NO_SUDO": "1"}, {"SB_NO_SUDO": "1"},
                    {"IBT_NO_SUDO": "0", "IB_NO_SUDO": "1"}, {"IBT_NO_SUDO": "0", "SB_NO_SUDO": "1"},
                    {"IBT_NO_SUDO": "1", "IB_NO_SUDO": "0", "SB_NO_SUDO": "0"}):
            with self.subTest(env=env):
                self.manager.env = env
                self.runner.calls.clear()
                self.assertEqual(self.manager.enable_timer(), 2)
                self.assertFalse(any(args[0] == "sudo" for args, _ in self.runner.calls))
                self.assertIn("退出终端后持续运行尚未确认", "\n".join(self.lines))

    def test_v3_unit_marker_is_accepted_for_update_stop_and_clear(self):
        for action in ("update", "stop", "clear"):
            with self.subTest(action=action):
                self.configure([ssh_target()])
                self.manager.write_units(300)
                for name in (hb.SERVICE, hb.TIMER):
                    unit = self.manager.unit_dir / name
                    unit.write_text(unit.read_text().replace(hb.UNIT_MARKER, "# Managed-by: Insta Box Heartbeat"))
                self.runner.active = self.runner.enabled = True
                if action == "update":
                    self.manager.write_units(300)
                    self.assertIn(hb.UNIT_MARKER, (self.manager.unit_dir / hb.SERVICE).read_text())
                elif action == "stop":
                    self.assertEqual(self.manager.stop_timer(), 0)
                    self.assertFalse(self.runner.active or self.runner.enabled)
                else:
                    self.assertEqual(self.manager.clear(), 0)
                    self.assertFalse((self.manager.unit_dir / hb.SERVICE).exists())
                    self.assertFalse((self.manager.unit_dir / hb.TIMER).exists())
        self.assertEqual(self.client.calls, [])

    def test_stop_order_releases_only_controller_leases_and_no_resume(self):
        config = self.configure([api_target(), ssh_target()])
        self.add_key()
        leftover = self.manager.cfg / ".heartbeat-ssh-stopped-process"
        hb.atomic_text(leftover, "User " + SECRET + "\n")
        self.runner.active = self.runner.enabled = True
        order = []
        original_runner, original_request = self.runner.__call__, self.client.request
        def runner(args, **kwargs):
            order.append(("local", list(args)))
            return original_runner(args, **kwargs)
        def request(method, route, key, body=None):
            order.append(("http", method, route))
            return original_request(method, route, key, body)
        self.manager.runner = runner
        self.client.request = request
        self.assertEqual(self.manager.stop(), 0)
        self.assertEqual(order[0][1], ["systemctl", "--user", "disable", "--now", hb.TIMER])
        self.assertEqual(order[1][1], ["systemctl", "--user", "stop", hb.SERVICE])
        http = [item for item in order if item[0] == "http"]
        self.assertEqual(len(http), 1)
        self.assertEqual(http[0][1], "DELETE")
        self.assertTrue(http[0][2].endswith(hb.lease_id(config["controllerId"], "m_one")))
        self.assertFalse(any("resume" in str(item) or "/start" in str(item) for item in order))
        self.assertFalse(leftover.exists())

    def test_clear_can_finish_after_lease_release_fails_but_keeps_shared_key(self):
        self.configure([api_target(), ssh_target()])
        self.add_key()
        self.manager.write_units(300)
        hb.atomic_text(self.manager.known_hosts, "host key\n")
        self.client.failures["activity-leases"] = hb.HeartbeatError("授权已过期", "unauthorized")
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.clear(), 0)
        self.assertTrue(self.manager.key_file.exists())
        self.assertFalse(self.manager.config_file.exists())
        self.assertFalse(self.manager.known_hosts.exists())
        self.assertFalse((self.manager.unit_dir / hb.TIMER).exists())
        self.assertFalse((self.manager.unit_dir / hb.SERVICE).exists())
        self.assertIn("有限有效期", "\n".join(self.lines))

    def test_damaged_config_does_not_block_stopping_and_clearing_local_timer(self):
        self.configure([ssh_target()])
        self.manager.write_units(300)
        hb.atomic_text(self.manager.config_file, "{broken json")
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.clear(), 0)
        self.assertFalse(self.runner.active)
        self.assertFalse(self.runner.enabled)
        self.assertFalse(self.manager.config_file.exists())
        self.assertFalse((self.manager.unit_dir / hb.TIMER).exists())
        self.assertFalse(self.client.calls)
        self.assertIn("配置损坏", "\n".join(self.lines))

    def test_clear_refuses_when_local_timer_or_service_may_still_run(self):
        self.configure([ssh_target()])
        self.runner.active = self.runner.enabled = self.runner.service_active = True
        self.runner.fail_stop = True
        with self.assertRaises(hb.HeartbeatError):
            self.manager.clear()
        self.assertTrue(self.manager.config_file.exists())

    def test_stop_does_not_disable_a_foreign_unit_with_the_same_name(self):
        self.configure([ssh_target()])
        self.manager.unit_dir.mkdir(parents=True, mode=0o700)
        (self.manager.unit_dir / hb.TIMER).write_text("# Another application\n[Timer]\n")
        with self.assertRaises(hb.HeartbeatError) as raised:
            self.manager.stop()
        self.assertEqual(raised.exception.code, "unit_conflict")
        self.assertFalse(self.runner.calls)

    def test_cancellation_and_explicit_api_selection_preserve_previous_config(self):
        config = self.configure([ssh_target()])
        self.add_key()
        original = self.manager.config_file.read_bytes()
        self.manager.prompt = lambda _: ""
        self.assertEqual(hb.main(["setup-api"], manager=self.manager), 0)
        self.assertEqual(self.manager.config_file.read_bytes(), original)
        self.assertFalse(any(method == "PUT" for method, *_ in self.client.calls))
        answers = iter(["2", ""])
        self.manager.prompt = lambda _: next(answers)
        with mock.patch.object(self.manager, "start", return_value=0):
            self.assertEqual(self.manager.setup_api(), 0)
        selected = self.manager.load_config()
        self.assertEqual([target["machineId"] for target in selected["targets"] if target["kind"] == "api"], ["m_two"])
        self.assertEqual(selected["targets"][0], config["targets"][0])

    def test_renew_clears_old_health_and_machine_binding_for_changed_token(self):
        target = ssh_target()
        target["rotation"] = {"enabled": True, "machineId": "m_one"}
        target["tokenExpiry"] = {"kind": "verified", "expiresAt": hb.iso_time(NOW + 1000)}
        self.configure([target])
        hb.atomic_json(self.manager.state_file, {"schema": 1, "controllerId": "a" * 32, "targets": [{"id": target["id"], "revision": target["revision"], "result": "success", "lastSuccessAt": hb.iso_time(NOW)}]})
        self.manager.secret = lambda _: "ssh -p 2222 ibssh_NEW_TEST_TOKEN@api.instabox.sh"
        self.manager.prompt = lambda _: ""
        with mock.patch.object(self.manager, "start", return_value=2):
            self.assertEqual(self.manager.renew(target["id"]), 2)
        updated = self.manager.load_config()["targets"][0]
        self.assertNotEqual(updated["revision"], target["revision"])
        self.assertNotIn("rotation", updated)
        self.assertEqual(updated["tokenExpiry"], {"kind": "unknown"})
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.status(), 2)
        self.assertIn("尚无此授权", "\n".join(self.lines))

    def test_same_token_verified_expiry_cannot_be_overwritten_by_user_estimate(self):
        target = ssh_target()
        target["tokenExpiry"] = {"kind": "verified", "expiresAt": hb.iso_time(NOW + 3600)}
        self.manager.secret = lambda _: "ssh -p 2222 " + SECRET + "@api.instabox.sh"
        answers = iter(["", "999"])
        self.manager.prompt = lambda _: next(answers)
        updated = self.manager.read_ssh_target("same", old=target)
        self.assertEqual(updated["tokenExpiry"], target["tokenExpiry"])

    def test_rotation_hook_disabled_no_key_and_enabled_atomic_revision(self):
        target = ssh_target()
        self.configure([target])
        calls = []
        def rotate(config, row, api, probe, save, now=None):
            calls.append(row["id"])
            changed = {**row, "revision": "d" * 32, "ssh": {**row["ssh"], "user": "ibssh_ROTATED_TEST_TOKEN"},
                       "tokenExpiry": {"kind": "verified", "expiresAt": hb.iso_time(NOW + 3600)}}
            probe(changed)
            save(changed)
            row.clear()
            row.update(changed)
            return {"status": "rotated", "changed": True, "message": "已更新授权"}
        self.manager.rotation_hook = rotate
        self.assertEqual(self.manager.run_once(), 0)
        self.assertFalse(calls)
        target["rotation"] = {"enabled": False, "armed": True, "machineId": "m_one"}
        self.configure([target])
        before = len(self.runner.ssh_configs)
        self.assertEqual(self.manager.run_once(), 0)
        self.assertEqual(calls, [target["id"]])
        self.assertEqual(len(self.runner.ssh_configs) - before, 1, "A verified rotated token should not get a duplicate probe")
        updated = self.manager.load_config()["targets"][0]
        self.assertEqual(updated["ssh"]["user"], "ibssh_ROTATED_TEST_TOKEN")
        self.assertEqual(self.state()["targets"][0]["revision"], updated["revision"])
        self.assertNotIn("ibssh_", self.manager.state_file.read_text())

    def test_ambiguous_rotation_does_not_claim_full_health_even_when_old_ssh_connects(self):
        target = ssh_target()
        target["rotation"] = {"enabled": True}
        self.configure([target])
        self.manager.rotation_hook = lambda *a, **k: {"status": "ambiguous", "changed": False, "message": "授权签发结果未知"}
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 2)
        self.assertEqual(self.state()["targets"][0]["result"], "success")
        self.assertEqual(self.manager.status(), 2)
        self.assertIn("授权签发结果未知", "\n".join(self.lines))

    def test_logs_redact_both_kinds_of_credential(self):
        self.assertEqual(self.manager.logs(), 0)
        output = "\n".join(self.lines)
        self.assertNotIn(KEY, output)
        self.assertNotIn(SECRET, output)
        self.assertIn("[已隐藏]", output)


class AutomaticSetupTests(Fixture):
    @contextlib.contextmanager
    def automatic_api(self):
        """Exercise the shared authorization gate with all HTTP kept offline."""
        import cloud
        def api(key):
            return types.SimpleNamespace(key=key, get=lambda path: self.client.request("GET", path, key))
        with mock.patch.object(cloud, "API", side_effect=api), \
                mock.patch.dict(os.environ, self.manager.env, clear=True), \
                mock.patch.object(cloud, "console_line", side_effect=self.lines.append):
            yield

    def test_auto_adds_running_pages_preserves_other_targets_and_persists_environment_key(self):
        rotating = ssh_target()
        rotating["rotation"] = {"enabled": True, "machineId": "m_two", "pending": {"token": SECRET}}
        old_api = {**api_target("retained"), "waitingStart": True, "observedState": "suspended"}
        before = self.configure([api_target(), old_api, rotating], interval=120)
        old_record = {"id": rotating["id"], "revision": rotating["revision"], "kind": "ssh", "result": "success",
                      "lastSuccessAt": hb.iso_time(NOW - 60)}
        hb.atomic_json(self.manager.state_file, {"schema": 1, "controllerId": before["controllerId"], "targets": [old_record]})
        self.manager.env["INSTABOX_API_KEY"] = KEY
        self.client.pages["/v1/machines"]["nextCursor"] = "second"
        self.client.pages["/v1/machines?cursor=second"] = {"machines": [
            {"id": "m_three", "name": "Three", "state": "running"},
            {"id": "m_four", "name": "Four", "state": "stopped"},
            {"id": "m_five", "name": "Five", "state": "starting"},
        ]}
        order = []
        request, runner = self.client.request, self.runner.__call__
        def track_request(method, route, key, body=None):
            order.append((method, route))
            return request(method, route, key, body)
        def track_runner(args, **kwargs):
            order.append((args[0], args[2] if len(args) > 2 else ""))
            return runner(args, **kwargs)
        self.client.request, self.manager.runner = track_request, track_runner
        with self.automatic_api(), mock.patch.object(self.manager, "rotate_target", side_effect=AssertionError("unrelated rotation")):
            self.assertEqual(hb.main(["auto"], manager=self.manager), 0)
            config = self.manager.load_config()
            self.assertEqual(hb.main(["auto"], manager=self.manager), 0)
        self.assertEqual(self.manager.load_config(), config)
        self.assertEqual(config["controllerId"], before["controllerId"])
        self.assertEqual(config["intervalSeconds"], 120)
        self.assertEqual(config["targets"][0]["id"], before["targets"][0]["id"])
        self.assertEqual(config["targets"][0]["revision"], before["targets"][0]["revision"])
        self.assertEqual(config["targets"][1:3], [old_api, rotating])
        self.assertEqual([target["machineId"] for target in config["targets"] if target["kind"] == "api"],
                         ["m_one", "m_retained", "m_three"])
        writes = [(method, route) for method, route, *_ in self.client.calls if method != "GET"]
        self.assertTrue(writes)
        self.assertTrue(all(method == "PUT" and route.split("/")[3] in ("m_one", "m_three") for method, route in writes))
        self.assertEqual(next(record for record in self.state()["targets"] if record["id"] == rotating["id"]), old_record)
        self.assertTrue(all(record["credentialPersistent"] for record in self.state()["targets"] if record.get("kind") == "api"))
        self.assertEqual(self.manager.key_file.read_text(), KEY + "\n")
        self.assertEqual(stat.S_IMODE(self.manager.key_file.stat().st_mode), 0o600)
        self.assertTrue(self.runner.active and self.runner.enabled)
        self.assertFalse(self.runner.ssh_configs)
        self.assertLess(next(index for index, event in enumerate(order) if event[0] == "PUT"), order.index(("systemctl", "enable")))
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.assertNotIn(SECRET, "\n".join(self.lines))
        self.assertNotIn(KEY, (self.manager.unit_dir / hb.SERVICE).read_text())

    def test_auto_local_matches_only_the_unique_exact_hostname_and_preserves_other_targets(self):
        previous = self.configure([api_target("retained"), ssh_target()])
        self.add_key()
        self.client.pages["/v1/machines"]["machines"][1]["state"] = "running"
        with self.automatic_api(), mock.patch.object(hb.socket, "gethostname", return_value="instabox-One"), \
                mock.patch.object(self.manager, "prompt", side_effect=AssertionError("unique hostname needs no selection")):
            self.assertEqual(hb.main(["auto-local"], manager=self.manager), 0)
        targets = self.manager.load_config()["targets"]
        self.assertEqual(targets[:2], previous["targets"])
        self.assertEqual([target["machineId"] for target in targets if target["kind"] == "api"], ["m_retained", "m_one"])
        self.assertEqual([route.split("/")[3] for method, route, *_ in self.client.calls if method == "PUT"], ["m_one"])
        self.assertFalse(self.runner.ssh_configs)

    def test_auto_local_requires_selection_for_single_machine_ambiguous_or_cleaned_names(self):
        one = {"id": "m_one", "name": "One", "state": "running"}
        cases = [("unrelated", [one], "1", "m_one"),
                 ("One", [one], "1", "m_one"),
                 ("instabox-One", [one, {**one, "id": "m_other"}], "2", "m_other"),
                 ("instabox-One", [{**one, "name": "One\x00"}], "1", "m_one")]
        for hostname, machines, answer, expected in cases:
            with self.subTest(hostname=hostname, names=[row["name"] for row in machines]), \
                    mock.patch.object(self.manager, "automatic_machines", return_value=machines), \
                    mock.patch.object(hb.socket, "gethostname", return_value=hostname), \
                    mock.patch.object(self.manager, "prompt", return_value=answer) as prompt, \
                    mock.patch.object(self.manager, "set_api_targets", return_value=0) as configure:
                self.assertEqual(self.manager.auto_local(), 0)
                prompt.assert_called_once()
                self.assertEqual([row["id"] for row in configure.call_args.args[0]], [expected])

    def test_auto_local_cancel_eof_and_bad_selection_are_nonzero_without_changing_targets(self):
        self.configure([ssh_target()])
        before = self.manager.config_file.read_bytes()
        machines = [{"id": "m_one", "name": "One", "state": "running"}]
        for answer in ("", "0", "2", "1,2", "１", EOFError()):
            prompt = mock.Mock(side_effect=answer) if isinstance(answer, BaseException) else mock.Mock(return_value=answer)
            with self.subTest(answer=repr(answer)), \
                    mock.patch.object(self.manager, "automatic_machines", return_value=machines), \
                    mock.patch.object(hb.socket, "gethostname", return_value="unidentified-host"), \
                    mock.patch.object(self.manager, "prompt", prompt):
                self.assertNotEqual(hb.main(["auto-local"], manager=self.manager), 0)
                self.assertEqual(self.manager.config_file.read_bytes(), before)
        self.assertFalse(self.client.calls)
        self.assertFalse(self.runner.calls)

    def test_auto_local_never_configures_a_nonrunning_machine_even_when_name_matches(self):
        self.configure([ssh_target()])
        before = self.manager.config_file.read_bytes()
        for state in ("suspended", "stopped", "starting", "unknown"):
            for hostname in ("instabox-One", "unidentified-host"):
                with self.subTest(state=state, hostname=hostname), \
                        mock.patch.object(self.manager, "automatic_machines", return_value=[{"id": "m_one", "name": "One", "state": state}]), \
                        mock.patch.object(hb.socket, "gethostname", return_value=hostname), \
                        mock.patch.object(self.manager, "prompt", return_value="1"):
                    self.assertEqual(hb.main(["auto-local"], manager=self.manager), 2)
                    self.assertEqual(self.manager.config_file.read_bytes(), before)
        self.assertFalse(self.client.calls)
        self.assertFalse(self.runner.calls)
        self.assertIn("先在机器管理中启动", "\n".join(self.lines))

    def test_auto_without_running_machines_does_not_change_existing_configuration(self):
        self.configure([api_target(), ssh_target()])
        self.add_key()
        before = self.manager.config_file.read_bytes()
        self.client.pages["/v1/machines"]["machines"][0]["state"] = "stopped"
        with self.automatic_api():
            self.assertEqual(hb.main(["auto"], manager=self.manager), 2)
        self.assertEqual(self.manager.config_file.read_bytes(), before)
        self.assertTrue(all(method == "GET" for method, *_ in self.client.calls))
        self.assertFalse(self.runner.calls)

    def test_auto_propagates_lease_or_timer_failure_after_saving_selected_targets(self):
        self.add_key()
        for failure in ("lease", "timer"):
            self.client.failures.clear()
            self.runner.fail_enable = failure == "timer"
            if failure == "lease":
                self.client.failures["activity-leases"] = hb.http_error(403)
            with self.subTest(failure=failure), self.automatic_api():
                self.assertEqual(hb.main(["auto"], manager=self.manager), 2)
            self.assertEqual([row["machineId"] for row in self.manager.load_config()["targets"]], ["m_one"])
            self.assertEqual(self.state()["targets"][0]["result"], "error" if failure == "lease" else "success")

    def test_auto_authorization_failure_or_missing_persistence_does_not_modify_targets(self):
        import cloud
        self.configure([ssh_target()])
        before = self.manager.config_file.read_bytes()
        for failure in ("authorization", "not_saved"):
            loader = mock.Mock(side_effect=cloud.APIError(403)) if failure == "authorization" else mock.Mock(return_value=types.SimpleNamespace(key=KEY))
            with self.subTest(failure=failure), mock.patch.object(cloud, "ensure_api", loader):
                self.assertEqual(hb.main(["auto"], manager=self.manager), 2)
                self.assertEqual(self.manager.config_file.read_bytes(), before)
                loader.assert_called_once_with(self.manager.cfg)
        self.assertFalse(self.client.calls)
        self.assertFalse(self.runner.calls)

    def test_auto_commands_reject_extra_arguments_before_authorization(self):
        for command in ("auto", "auto-local"):
            with self.subTest(command=command), \
                    mock.patch.object(self.manager, "automatic_machines", side_effect=AssertionError("arguments must be checked first")):
                self.assertEqual(hb.main([command, "1"], manager=self.manager), 2)
        self.assertFalse(self.manager.cfg.exists())


class ScheduleTests(Fixture):
    def successful_api(self, interval=150):
        config = self.configure([api_target()], interval=interval)
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 0)
        self.lines.clear()
        return config

    def test_actual_systemd_deadline_and_distinct_trigger_completion_and_lease(self):
        self.successful_api()
        before = self.manager.state_file.read_bytes()
        self.client.calls.clear()
        with mock.patch.object(self.manager, "read_key", side_effect=AssertionError("read-only status must not load a key")):
            summary = self.manager.summary()
        self.assertEqual(summary["timer"], {"active": "active", "enabled": "enabled"})
        self.assertEqual(summary["schedule"], {"state": "scheduled", "nextRunAt": hb.iso_time(NOW + 317),
                         "lastRunAt": hb.iso_time(NOW - 29), "lastCompletedAt": hb.iso_time(NOW), "source": "systemd"})
        self.assertNotEqual(summary["schedule"]["nextRunAt"], hb.iso_time(NOW + 150))
        self.assertEqual(summary["targets"][0]["leaseExpiresAt"], hb.iso_time(NOW + 900))
        self.assertEqual(self.manager.state_file.read_bytes(), before)
        self.assertEqual(self.client.calls, [])
        probes = [(args, kwargs) for args, kwargs in self.runner.calls if args[:3] in (
            ["systemctl", "--user", "show"], ["systemctl", "--user", "list-timers"])]
        self.assertTrue(probes)
        self.assertTrue(all(kwargs["timeout"] == 3 for _, kwargs in probes))
        self.assertIn(["systemctl", "--user", "list-timers", "--all", "--output=json", "--no-pager", "--no-legend", hb.TIMER],
                      [args for args, _ in probes])
        self.manager.status()
        output = "\n".join(self.lines)
        for label in ("自动保活：", "最近完成：", "下次执行：", "检查间隔：", "最近成功：", "本轮有效："):
            self.assertIn(label, output)
        self.assertIn(hb.format_timestamp(hb.iso_time(NOW + 317)), output)
        self.assertNotIn("api_one", output)
        self.assertNotIn("下次检查约", output)

    def test_brief_keeps_actual_next_run_and_result_table_without_details_or_writes(self):
        self.configure([api_target(), api_target("two"), ssh_target()], interval=150)
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.client.failures["/v1/machines/m_two/"] = hb.http_error(409)
        self.assertEqual(self.manager.run_once(), 2)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (self.manager.config_file, self.manager.state_file)}
        self.client.calls.clear()
        self.lines.clear()
        with mock.patch.object(self.manager, "read_key", side_effect=AssertionError("brief must not read a key")), \
             mock.patch.object(self.manager, "secret", side_effect=AssertionError("brief must not prompt")):
            self.assertEqual(self.manager.dispatch(["status", "--brief"]), 2)
        output = "\n".join(self.lines)
        for field in ("自动保活： ", "最近完成： ", "下次执行： ", "检查间隔： "):
            self.assertIn(field, output)
        self.assertIn(hb.format_timestamp(hb.iso_time(NOW + 317)), output)
        self.assertIn("目标名称", output)
        self.assertIn("待确认", output)
        self.assertIn("保活页 7", output)
        for detail in ("最近成功：", "本轮有效：", "状态详情：", "授权到期：", "授权说明：", "恢复控制器", "api_one", SECRET, KEY):
            self.assertNotIn(detail, output)
        self.assertLessEqual(len(self.lines), 12)
        self.assertEqual(self.client.calls, [])
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})
        self.lines.clear()
        self.assertEqual(self.manager.dispatch(["status"]), 2)
        self.assertIn("本轮有效：", "\n".join(self.lines))
        self.assertIn("授权到期：", "\n".join(self.lines))

    def test_brief_is_only_a_status_flag_and_unconfigured_is_read_only(self):
        for args in (["run", "--brief"], ["start", "--brief"], ["renew", "--brief"], ["remove", "--brief"],
                     ["status", "--brief", "extra"], ["status", "--unknown"], ["--brief"]):
            with self.subTest(args=args), self.assertRaises(hb.HeartbeatError) as raised:
                self.manager.dispatch(args)
            self.assertEqual(raised.exception.code, "arguments")
        self.assertEqual(self.manager.dispatch(["status", "--brief"]), 0)
        self.assertIn("保活页 1", "\n".join(self.lines))
        self.assertFalse(self.runner.calls or self.client.calls)
        self.assertFalse((self.home / ".config").exists())

    def test_running_oneshot_or_manual_lock_suppresses_even_an_old_future_deadline(self):
        self.successful_api()
        for state in ("activating", "active", "deactivating"):
            with self.subTest(state=state):
                self.runner.service_properties = "Id=" + hb.SERVICE + "\nLoadState=loaded\nActiveState=" + state + "\nSubState=start\n"
                summary = self.manager.summary()
                self.assertEqual(summary["schedule"]["state"], "running")
                self.assertIsNone(summary["schedule"]["nextRunAt"])
                self.assertIn("本轮执行中", hb.schedule_description(summary))
        self.runner.service_properties = None
        lock = self.manager.cfg / "heartbeat.lock"
        inode = lock.stat().st_ino
        with self.manager.lock() as acquired:
            self.assertTrue(acquired)
            summary = self.manager.summary()
            self.assertEqual(summary["schedule"]["state"], "running")
            self.assertIsNone(summary["schedule"]["nextRunAt"])
            other = hb.Manager(home=self.home, client=self.client, runner=self.runner, output=self.lines.append)
            self.assertEqual(other.run_once(), 2, "Read-only observation must not release the writer's lock")
        self.assertEqual(lock.stat().st_ino, inode)

    def test_disabled_and_partial_timer_states_never_promise_a_next_run(self):
        self.successful_api()
        for active, enabled in ((False, False), (False, True), (True, False)):
            with self.subTest(active=active, enabled=enabled):
                self.runner.active, self.runner.enabled = active, enabled
                summary = self.manager.summary()
                self.assertEqual(summary["schedule"]["state"], "disabled")
                self.assertIsNone(summary["schedule"]["nextRunAt"])
                self.assertEqual(summary["targets"][0]["status"], "disabled")
                self.assertIn("不承诺", hb.schedule_description(summary))
        self.assertIn("当前会话运行", hb.automatic_description(summary))
        self.assertIn("尚未启用自启", summary["targets"][0]["message"])

    def test_unset_schedule_differs_from_unsupported_unreadable_or_malformed_data(self):
        self.successful_api()
        for rows in ([], [{"unit": hb.TIMER, "activates": hb.SERVICE, "next": None, "last": 0}],
                     [{"unit": hb.TIMER, "activates": hb.SERVICE, "next": 2**64 - 1, "last": None}]):
            with self.subTest(rows=rows):
                self.runner.timer_rows = rows
                summary = self.manager.summary()
                self.assertEqual(summary["schedule"]["state"], "unscheduled")
                self.assertIn("尚未排定", hb.schedule_description(summary))
        invalid = ["NEXT LEFT LAST", "not-json " + SECRET, "{}", "null",
                   json.dumps([{"unit": hb.TIMER, "activates": hb.SERVICE, "next": True, "last": None}]),
                   json.dumps([{"unit": hb.TIMER, "activates": "foreign.service", "next": int((NOW + 10) * 1000000), "last": None}]),
                   json.dumps([{"unit": "foreign.timer", "activates": hb.SERVICE, "next": int((NOW + 10) * 1000000), "last": None}]),
                   json.dumps([{"unit": hb.TIMER, "activates": hb.SERVICE, "next": KEY, "last": None}]),
                   json.dumps([{"unit": hb.TIMER, "activates": hb.SERVICE, "next": 2**80, "last": None}])]
        for stdout in invalid:
            with self.subTest(stdout=stdout[:18]):
                self.runner.timer_stdout = stdout
                summary = self.manager.summary()
                self.assertEqual(summary["schedule"]["state"], "unknown")
                self.assertIsNone(summary["schedule"]["nextRunAt"])
                self.assertIn("未读取", hb.schedule_description(summary))
                self.assertNotIn(SECRET, json.dumps(summary))
                self.assertNotIn(KEY, json.dumps(summary))
        self.runner.timer_stdout = None
        self.runner.timers_returncode = 1
        self.assertEqual(self.manager.summary()["schedule"]["state"], "unknown")
        self.runner.timers_returncode = 0
        original = self.runner
        def timed_out(args, **kwargs):
            if args[0] == "systemctl" and args[2] in ("show", "list-timers"):
                raise subprocess.TimeoutExpired(args, kwargs["timeout"], output=SECRET, stderr=KEY)
            return original(args, **kwargs)
        self.manager.runner = timed_out
        self.manager.status()
        self.assertIn("未读取", "\n".join(self.lines))
        self.assertNotIn(SECRET, "\n".join(self.lines))
        self.assertNotIn(KEY, "\n".join(self.lines))

    def test_service_identity_or_unreadable_lock_prevents_a_scheduled_claim(self):
        self.successful_api()
        for properties in ("", "Id=foreign.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n",
                           "Id=" + hb.SERVICE + "\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"):
            with self.subTest(properties=properties[:16]):
                self.runner.service_properties = properties
                self.assertEqual(self.manager.summary()["schedule"]["state"], "unknown")
        self.runner.service_properties = None
        lock = self.manager.cfg / "heartbeat.lock"
        lock.unlink()
        self.assertEqual(self.manager.summary()["schedule"]["state"], "scheduled")
        self.assertFalse(lock.exists(), "Read-only status must not create a lock")
        external = self.home / "external"
        external.write_text("unchanged")
        lock.symlink_to(external)
        self.assertEqual(self.manager.summary()["schedule"]["state"], "unknown")
        self.assertEqual(external.read_text(), "unchanged")

    def test_expiry_requires_same_controller_revision_and_successful_round(self):
        config = self.successful_api()
        good = self.state()
        for changed in ({**good, "controllerId": "d" * 32}, {**good, "schema": 999}):
            hb.atomic_json(self.manager.state_file, changed)
            summary = self.manager.summary()
            self.assertIsNone(summary["schedule"]["lastCompletedAt"])
            self.assertIsNone(summary["targets"][0]["leaseExpiresAt"])
        hb.atomic_json(self.manager.state_file, good)
        config["targets"][0]["revision"] = "d" * 32
        hb.atomic_json(self.manager.config_file, config)
        self.assertIsNone(self.manager.summary()["targets"][0]["leaseExpiresAt"])
        config["targets"][0]["revision"] = "c" * 32
        hb.atomic_json(self.manager.config_file, config)
        self.now = NOW + 901
        row = self.manager.summary()["targets"][0]
        self.assertEqual(row["status"], "stale")
        self.assertEqual(row["leaseExpiresAt"], hb.iso_time(NOW + 900))
        self.manager.status()
        self.assertIn("已过期", "\n".join(self.lines))
        self.now = NOW
        self.client.failures["activity-leases"] = hb.http_error(409)
        self.assertEqual(self.manager.run_once(), 2)
        row = self.manager.summary()["targets"][0]
        self.assertEqual(row["lastSuccessAt"], hb.iso_time(NOW))
        self.assertIsNone(row["leaseExpiresAt"], "A failed round must not reuse the previous lease expiry")
        self.assertNotEqual(row["status"], "healthy")
        self.runner.active = self.runner.enabled = False
        self.lines.clear()
        self.manager.status()
        output = "\n".join(self.lines)
        self.assertNotIn("下一轮会继续检查", output)
        self.assertIn("保活页 6 → 机器管理 → 2", output)

    def test_unconfigured_summary_does_not_probe_or_create_anything(self):
        summary = self.manager.summary()
        self.assertEqual(summary["schedule"], {"state": "disabled", "nextRunAt": None, "lastRunAt": None,
                                              "lastCompletedAt": None, "source": None})
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.client.calls, [])
        self.assertFalse((self.home / ".config").exists())

    def test_display_hides_internal_ids_and_keeps_width_aware_selection(self):
        from cloud import display_width
        one, two = api_target(), api_target("two")
        one["label"], two["label"] = "香港节点e\u0301", "English node"
        config = self.configure([one, two])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 0)
        output = "\n".join(self.lines)
        self.assertIn("保活成功", output)
        self.assertNotIn("下次检查约", output)
        self.assertNotIn(one["id"], output)
        table = self.lines[:3]
        positions = [display_width(line[:line.index("API")]) for line in table[1:]]
        self.assertEqual(positions[0], positions[1])
        self.lines.clear()
        self.manager.prompt = lambda _: "2"
        self.assertEqual(self.manager.select_target(config), two)
        self.assertNotIn(one["id"], "\n".join(self.lines))
        self.assertEqual(self.manager.select_target(config, one["id"]), one)
        with self.assertRaisesRegex(hb.HeartbeatError, "按编号选择"):
            self.manager.select_target(config, "missing")

    def test_round_feedback_keeps_table_and_failure_reason_without_repeating_times(self):
        one, two = api_target(), api_target("two")
        one["label"], two["label"] = "香港节点", "English node"
        self.configure([one, two])
        self.add_key()
        self.client.failures["/m_two/"] = hb.HeartbeatError("网络连接失败 " + KEY, "network")
        self.assertEqual(self.manager.run_once(), 2)
        output = "\n".join(self.lines)
        self.assertIn("目标名称", output)
        self.assertIn("保活成功", output)
        self.assertIn("执行失败", output)
        self.assertIn("2. English node\n  状态详情： 网络连接失败 [已隐藏]", output)
        self.assertNotIn("1. 香港节点", output)
        self.assertNotIn("最近成功：", output)
        self.assertNotIn("本轮有效：", output)
        self.assertNotIn(KEY, output)

    def test_full_status_groups_dates_and_ssh_credentials_with_their_target(self):
        one, ssh = api_target(), ssh_target()
        one["label"], ssh["label"] = "API 节点", "SSH 节点"
        ssh["tokenExpiry"] = {"kind": "verified", "expiresAt": hb.iso_time(NOW + 3600)}
        self.configure([one, ssh])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 0)
        self.lines.clear()
        self.assertEqual(self.manager.status(), 0)
        output = "\n".join(self.lines)
        self.assertNotIn("目标名称", output, "full details should not repeat the summary table")
        self.assertEqual(output.count("1. API 节点"), 1)
        self.assertEqual(output.count("2. SSH 节点"), 1)
        api_block, ssh_block = output.split("1. API 节点\n", 1)[1].split("2. SSH 节点\n", 1)
        self.assertIn("  最近成功： " + hb.format_timestamp(hb.iso_time(NOW)), api_block)
        self.assertIn("  本轮有效： " + hb.format_timestamp(hb.iso_time(NOW + 900)), api_block)
        self.assertIn("  授权到期： " + hb.format_timestamp(hb.iso_time(NOW + 3600)), ssh_block)
        self.assertIn("  验证范围： 仅确认单轮 SSH 连通", ssh_block)
        self.assertNotIn("授权到期：", api_block)
        self.assertNotIn("本轮有效：", ssh_block)
        self.assertNotIn("（同日）", output)
        for line in self.lines:
            if line.startswith("  "):
                label = line[2:].split("：", 1)[0]
                self.assertEqual(len(label), 4, line)
        self.assertIn("后台驻留： 已确认（Linger）", output)
        self.assertNotIn(KEY, output)
        self.assertNotIn(SECRET, output)

    def test_shared_formatters_do_not_leak_invalid_values_or_call_unknown_unconfigured(self):
        self.assertEqual(hb.format_timestamp(SECRET), "未记录")
        self.assertEqual(hb.format_timestamp(None), "未记录")
        if time.localtime(NOW).tm_gmtoff == 0:
            self.assertIn("UTC", hb.format_timestamp(hb.iso_time(NOW)))
        for summary in (None, {}, {"configured": None, "unavailable": True}, {"configured": True, "timer": [], "schedule": []}):
            self.assertNotIn("尚未配置", hb.automatic_description(summary))
            self.assertIn("未读取", hb.schedule_description(summary))
        self.assertEqual(hb.automatic_description({"configured": False}), "尚未配置")


class FleetInterfaceTests(Fixture):
    def test_summary_is_read_only_secret_free_and_uses_explicit_ssh_binding(self):
        unbound, bound = ssh_target("unbound"), ssh_target("bound", "ibssh_ANOTHER_FAKE_TOKEN")
        bound["rotation"] = {"enabled": False, "machineId": "m_two", "pending": {"token": SECRET}}
        bound["label"] = "test " + SECRET
        self.configure([api_target(), unbound, bound])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.assertEqual(self.manager.run_once(), 0)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (self.manager.config_file, self.manager.state_file)}
        with mock.patch.object(self.manager, "read_key", side_effect=AssertionError("summary must not read a key")), mock.patch.object(self.client, "request", side_effect=AssertionError("summary must not use API")), mock.patch.object(self.manager, "secret", side_effect=AssertionError("summary must not prompt")):
            summary = self.manager.summary()
        self.assertTrue(summary["configured"])
        self.assertEqual(summary["timer"], {"active": "active", "enabled": "enabled"})
        self.assertEqual([row["machineId"] for row in summary["targets"]], ["m_one", None, "m_two"])
        self.assertEqual([row["status"] for row in summary["targets"]], ["healthy"] * 3)
        self.assertNotIn(SECRET, json.dumps(summary))
        self.assertNotIn(KEY, json.dumps(summary))
        self.assertNotIn("pending", json.dumps(summary))
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})

    def test_summary_never_promotes_expired_or_different_controller_success(self):
        config = self.configure([api_target()])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.manager.run_once()
        good = self.state()
        expired = json.loads(json.dumps(good))
        expired["targets"][0]["expiresAt"] = hb.iso_time(NOW - 1)
        hb.atomic_json(self.manager.state_file, expired)
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "stale")
        for changed in ({**good, "controllerId": "d" * 32}, {**good, "schema": 999}):
            hb.atomic_json(self.manager.state_file, changed)
            row = self.manager.summary()["targets"][0]
            self.assertEqual(row["status"], "unverified")
            self.assertIsNone(row["lastSuccessAt"])
        hb.atomic_json(self.manager.state_file, good)
        self.runner.active = self.runner.enabled = False
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "disabled")
        config["targets"][0]["revision"] = "e" * 32
        hb.atomic_json(self.manager.config_file, config)
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "unverified")

    def test_summary_distinguishes_verified_expiry_from_user_estimate(self):
        target = ssh_target()
        target["tokenExpiry"] = {"kind": "verified", "expiresAt": hb.iso_time(NOW - 1)}
        self.configure([target])
        self.runner.active = self.runner.enabled = True
        self.manager.run_once()
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "token_expired")
        target["tokenExpiry"]["kind"] = "estimated"
        self.configure([target])
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "healthy")

    def test_waiting_state_read_failures_are_real_failures_and_do_not_send_put(self):
        target = {**api_target(), "waitingStart": True, "observedState": "suspended"}
        self.configure([target])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        for error in (hb.http_error(403), hb.HeartbeatError("网络连接失败", "network"), hb.HeartbeatError("请求超时", "timeout")):
            with self.subTest(code=error.code):
                self.client.failures["/v1/machines/m_one"] = error
                self.client.calls.clear()
                self.assertEqual(self.manager.run_once(), 2)
                record = self.state()["targets"][0]
                self.assertEqual(record["result"], "error")
                self.assertEqual(record["errorCode"], error.code)
                self.assertIn("运行状态检查失败", record["error"])
                self.assertEqual(self.manager.summary()["targets"][0]["status"], "failed")
                self.assertEqual([call[0] for call in self.client.calls], ["GET"])

    def test_waiting_state_response_identity_and_type_are_checked(self):
        self.configure([{**api_target(), "waitingStart": True, "observedState": "suspended"}])
        self.add_key()
        for response in ({"id": "m_other", "state": "running"}, {"id": "m_one", "state": []}):
            with self.subTest(response=response), mock.patch.object(self.client, "request", return_value=response) as request:
                self.assertEqual(self.manager.run_once(), 2)
                self.assertEqual(self.state()["targets"][0]["errorCode"], "invalid_response")
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.args[0], "GET")
        for value in ({}, [], 1):
            config = self.manager.load_config()
            config["targets"][0]["observedState"] = value
            with self.assertRaises(hb.HeartbeatError) as raised:
                self.manager.validate_config(config)
            self.assertEqual(raised.exception.code, "config")

    def test_state_conflict_is_not_auth_failure_or_an_assertion_of_manual_pause(self):
        self.configure([api_target()])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.manager.run_once()
        self.client.calls.clear()
        self.lines.clear()
        self.client.failures["activity-leases"] = hb.http_error(409)
        self.assertEqual(self.manager.run_once(), 2)
        record = self.state()["targets"][0]
        self.assertEqual((record["result"], record["errorCode"]), ("waiting", "conflict"))
        self.assertEqual(record["lastSuccessAt"], hb.iso_time(NOW))
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "unverified")
        self.assertEqual([call[0] for call in self.client.calls], ["PUT"])
        self.assertIn("当前状态暂不接受保活", "\n".join(self.lines))
        self.assertNotIn("人工暂停", "\n".join(self.lines))
        self.assertNotIn("租约", "\n".join(self.lines))

    def test_configuration_conflict_does_not_overwrite_new_rotation_or_targets(self):
        selected = [{"id": "m_one", "name": "One", "state": "running"}]
        for action in (lambda: self.manager.set_api_targets(selected, enabled=False), lambda: self.manager.refresh_observed_targets(selected)):
            original = self.configure([api_target(), ssh_target()])
            changed = json.loads(json.dumps(original))
            changed["targets"][1]["rotation"] = {"enabled": True, "machineId": "m_two", "pending": {"token": SECRET}}
            changed["targets"].append(api_target("two"))
            real_lock = self.manager.lock
            @contextlib.contextmanager
            def concurrent_update():
                hb.atomic_json(self.manager.config_file, changed)
                with real_lock() as acquired:
                    yield acquired
            with mock.patch.object(self.manager, "lock", concurrent_update), self.assertRaises(hb.HeartbeatError) as raised:
                action()
            self.assertEqual(raised.exception.code, "config_changed")
            self.assertEqual(self.manager.load_config(), changed)
            self.assertFalse(self.client.calls)
            self.assertFalse(self.runner.calls)

    def test_bulk_target_change_respects_an_existing_run_lock(self):
        original = self.configure([api_target(), ssh_target()])
        with self.manager.lock() as acquired:
            self.assertTrue(acquired)
            second = hb.Manager(home=self.home, client=self.client, runner=self.runner, env={"SB_NO_SUDO": "1"})
            with self.assertRaises(hb.HeartbeatError) as raised:
                second.set_api_targets([{"id": "m_one", "state": "running"}], enabled=False)
        self.assertEqual(raised.exception.code, "busy")
        self.assertEqual(self.manager.load_config(), original)
        self.assertFalse(self.client.calls)

    def test_waiting_api_recovery_and_ssh_rotation_persist_without_lost_updates(self):
        target = ssh_target()
        target["rotation"] = {"enabled": True, "machineId": "m_two"}
        self.configure([{**api_target(), "waitingStart": True, "observedState": "suspended"}, target])
        self.add_key()
        gate = threading.Barrier(2)
        request = self.client.request
        def concurrent_request(method, route, key, body=None):
            if method == "GET" and route == "/v1/machines/m_one":
                gate.wait(timeout=2)
            return request(method, route, key, body)
        def rotate(config, row, api, probe, save, now=None):
            gate.wait(timeout=2)
            updated = {**row, "revision": "d" * 32, "ssh": {**row["ssh"], "user": "ibssh_ROTATED_CONCURRENT_TOKEN"}}
            probe(updated)
            save(updated)
            row.clear()
            row.update(updated)
            return {"status": "rotated", "changed": True, "message": "已更新授权"}
        self.client.request = concurrent_request
        self.manager.rotation_hook = rotate
        self.assertEqual(self.manager.run_once(), 0)
        targets = self.manager.load_config()["targets"]
        self.assertFalse(targets[0]["waitingStart"])
        self.assertEqual(targets[1]["ssh"]["user"], "ibssh_ROTATED_CONCURRENT_TOKEN")
        self.assertEqual(targets[1]["revision"], "d" * 32)
        self.assertEqual([row["revision"] for row in self.state()["targets"]], [row["revision"] for row in targets])
        self.assertNotIn("ibssh_", self.manager.state_file.read_text())

    def test_environment_key_can_probe_but_cannot_claim_persistent_timer_authorization(self):
        self.manager.env["INSTABOX_API_KEY"] = KEY
        with mock.patch.object(self.manager, "secret", side_effect=AssertionError("unexpected secret prompt")):
            self.assertEqual(self.manager.set_api_targets([{"id": "m_one", "name": "One", "state": "running"}]), 2)
        self.assertFalse(self.manager.key_file.exists())
        self.assertEqual(self.state()["targets"][0]["result"], "success")
        self.assertFalse(self.state()["targets"][0]["credentialPersistent"])
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "unverified")
        self.assertIn("ibt key set", "\n".join(self.lines))
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.assertNotIn(KEY, (self.manager.unit_dir / hb.SERVICE).read_text())
        self.assertNotIn(KEY, str(self.runner.calls))
        self.add_key()
        self.assertEqual(self.manager.start(), 0)
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "healthy")

    def test_removing_last_target_requires_timer_stop_before_config_or_remote_cleanup(self):
        self.configure([api_target()])
        self.add_key()
        original = self.manager.config_file.read_bytes()
        self.runner.active = self.runner.enabled = self.runner.service_active = True
        self.runner.fail_stop = True
        self.assertEqual(self.manager.set_api_targets([{"id": "m_one"}], enabled=False), 2)
        self.assertEqual(self.manager.config_file.read_bytes(), original)
        self.assertFalse(self.client.calls)

    def test_removing_one_target_cannot_promote_unknown_state_schema(self):
        config = self.configure([api_target(), api_target("two")])
        self.add_key()
        self.runner.active = self.runner.enabled = True
        self.manager.run_once()
        state = self.state()
        state["schema"] = 999
        hb.atomic_json(self.manager.state_file, state)
        self.client.calls.clear()
        self.assertEqual(self.manager.set_api_targets([{"id": "m_one"}], enabled=False), 0)
        self.assertEqual(self.manager.load_config()["targets"], [config["targets"][1]])
        self.assertEqual(self.state()["targets"], [])
        self.assertIsNone(self.state()["checkedAt"])
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "unverified")
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0][0], "DELETE")
        self.assertTrue(self.client.calls[0][1].endswith(hb.lease_id(config["controllerId"], "m_one")))

    def test_refresh_does_not_create_targets_or_restart_a_disabled_timer(self):
        self.assertEqual(self.manager.refresh_observed_targets([{"id": "m_one", "state": "running"}]), 0)
        self.assertFalse(self.manager.cfg.exists())
        target = {**api_target(), "waitingStart": True, "observedState": "suspended"}
        self.configure([target, ssh_target()])
        self.assertEqual(self.manager.refresh_observed_targets([{"id": "m_one", "state": "running"}, {"id": "m_new", "state": "running"}]), 0)
        config = self.manager.load_config()
        self.assertEqual(len(config["targets"]), 2)
        self.assertFalse(config["targets"][0]["waitingStart"])
        self.assertNotEqual(config["targets"][0]["revision"], target["revision"])
        self.assertFalse(self.client.calls)
        self.assertFalse(any("enable" in args for args, _ in self.runner.calls))
        self.assertEqual(self.manager.summary()["targets"][0]["status"], "unverified")

    def test_setup_default_selects_only_previously_selected_running_machines(self):
        self.configure([api_target(), api_target("two"), ssh_target()])
        self.client.pages["/v1/machines"]["machines"].append({"id": "m_three", "name": "New", "state": "running"})
        self.add_key()
        prompts = []
        self.manager.prompt = lambda question: prompts.append(question) or ""
        with mock.patch.object(self.manager, "start", return_value=0):
            self.assertEqual(self.manager.setup_api(), 0)
        self.assertIn("[1]", prompts[0])
        self.assertEqual([target["machineId"] for target in self.manager.load_config()["targets"] if target["kind"] == "api"], ["m_one"])
        output = "\n".join(self.lines)
        self.assertIn("不会替你开机", output)
        self.assertNotIn("手动生命周期", output)
        self.assertNotIn("租约", output)


if __name__ == "__main__":
    unittest.main()
