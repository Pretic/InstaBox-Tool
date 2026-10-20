"""Offline WebSocket diagnostics: fake sockets, services and private files only."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import node_probe as np

NOW = 1800000000.0
MONO = 1000.0
IDENTITY = "11111111-1111-4111-8111-111111111111"
PATH = "/ws-" + "a" * 36
HOST = "offline-fixture.trycloudflare.com"
SECRET = "ibssh_FAKE_PRIVATE_SECRET"
KEY = "ibk_FAKE_PRIVATE_KEY"
NODE_INSTANCE = "b" * 32
QUICK_INSTANCE = "c" * 32


class Runner:
    def __init__(self):
        self.calls = []
        self.node = {"active": "active", "sub": "running", "pid": 101, "restarts": 0, "invocation": NODE_INSTANCE, "start": 990_000_000}
        self.quick = {"active": "active", "sub": "running", "pid": 202, "restarts": 0, "invocation": QUICK_INSTANCE, "start": 990_000_000}
        self.returncode = 0
        self.stdout = None
        self.callback = None
        self.version = "cloudflared version 2026.10.1 (built today)\n"

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if self.callback:
            self.callback(args)
        if args[0] == "systemctl":
            if args[:3] != ["systemctl", "--user", "show"]:
                raise AssertionError("Diagnostics must not mutate a service")
            blocks = []
            for name, item in ((np.NODE_SERVICE, self.node), (np.QUICK_SERVICE, self.quick)):
                blocks.append("\n".join(("Id=" + name, "LoadState=loaded", "ActiveState=" + item["active"],
                                         "SubState=" + item["sub"], "NRestarts=" + str(item["restarts"]),
                                         "ExecMainStatus=0", "MainPID=" + str(item["pid"]),
                                         "InvocationID=" + item["invocation"],
                                         "ExecMainStartTimestampMonotonic=" + str(item["start"]))))
            return subprocess.CompletedProcess(args, self.returncode, self.stdout if self.stdout is not None else "\n\n".join(blocks), SECRET + KEY)
        if args[-1:] == ["--version"]:
            return subprocess.CompletedProcess(args, 0, self.version, SECRET + KEY)
        raise AssertionError("Unexpected diagnostic command")


class Transport:
    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])
        self.callback = None

    def probe(self, host, port, path, *, tls, timeout):
        self.calls.append({"host": host, "port": port, "path": path, "tls": tls, "timeout": timeout})
        if self.callback:
            self.callback(host, tls)
        return self.results.pop(0) if self.results else np.safe_result("ok", 101)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        os.chmod(self.home, 0o700)
        self.app = self.home / ".local/share/insta-box"
        for parent in (self.home / ".local", self.home / ".local/share", self.app, self.app / "bin"):
            parent.mkdir(mode=0o700)
        self.private("state.conf", "mode=quick\ndomain=\nuuid=" + IDENTITY + "\npath=" + PATH + "\nport=20000\n")
        self.config = {"inbounds": [{"type": "vless", "tag": "vless-ws", "listen": "127.0.0.1", "listen_port": 20000,
                                     "users": [{"uuid": IDENTITY}], "transport": {"type": "ws", "path": PATH}}]}
        self.private("config.json", json.dumps(self.config))
        self.private("quick.log", self.log())
        self.private("quick-protocol", "auto\n")
        self.private("bin/cloudflared", "fake binary never executed", 0o700)
        self.runner, self.transport = Runner(), Transport()
        self.sleeps = []
        self.probe = np.Probe(self.home, runner=self.runner, transport=self.transport, clock=lambda: NOW,
                              monotonic=lambda: MONO, sleeper=self.sleeps.append, env={})

    def private(self, name, text, mode=0o600):
        filename = self.app / name
        filename.write_text(text)
        filename.chmod(mode)
        return filename

    @staticmethod
    def log(host=HOST, invocation=QUICK_INSTANCE, registered=False):
        result = "IBT_QUICK_INVOCATION=" + invocation + "\n" + np.timestamp(NOW - 9) + " INF Starting tunnel\n"
        result += "https://" + host + "\n" + "Initial protocol quic\n"
        if registered:
            result += "Registered tunnel connection protocol=http2\n"
        return result + "private discarded: " + SECRET + " " + KEY + " " + PATH + " " + IDENTITY + "\n"

    def safe_report(self, report):
        lines = []
        np.render(report, lines.append)
        rendered = json.dumps(report, ensure_ascii=False) + "\n".join(lines)
        for value in (IDENTITY, PATH, SECRET, KEY, HOST, NODE_INSTANCE, QUICK_INSTANCE):
            self.assertNotIn(value, rendered)
        return lines


class ProbeTests(Fixture):
    def test_success_requires_real_handshakes_and_current_services_not_registration(self):
        result = self.probe.check_quick(expect_host=HOST.upper())
        self.assertEqual(result["exitCode"], 0)
        self.assertFalse(result["connector"]["registered"])
        self.assertTrue(result["domain"]["logCurrent"])
        self.assertEqual([call["tls"] for call in self.transport.calls], [False, True])
        self.assertEqual([call["path"] for call in self.transport.calls], [PATH, PATH])
        self.assertEqual([call["host"] for call in self.transport.calls], ["127.0.0.1", HOST])
        self.assertEqual(len(self.runner.calls), 2)
        self.safe_report(result)

    def test_registered_log_does_not_make_failed_public_probe_green(self):
        self.private("quick.log", self.log(registered=True))
        self.transport.results = [np.safe_result("ok", 101), {"code": "http_status", "httpStatus": 502, "body": SECRET, "url": PATH}]
        result = self.probe.check_quick()
        self.assertEqual(result["exitCode"], 1)
        self.assertEqual(result["public"]["httpStatus"], 502)
        self.assertTrue(result["connector"]["registered"])
        self.safe_report(result)

    def test_inactive_unreadable_or_incomplete_service_is_not_success(self):
        for change in (lambda: self.runner.quick.update(active="inactive", sub="dead"),
                       lambda: setattr(self.runner, "returncode", 1),
                       lambda: self.runner.node.update(invocation=""),
                       lambda: self.runner.quick.update(pid=0),
                       lambda: self.runner.quick.update(start=0)):
            with self.subTest(change=change):
                self.runner = Runner()
                self.probe.runner = self.runner
                change()
                result = self.probe.check_quick()
                self.assertNotEqual(result["exitCode"], 0)
                self.safe_report(result)

    def test_host_expectation_and_mid_probe_domain_change_are_not_success(self):
        result = self.probe.check_quick(expect_host="old-address.trycloudflare.com")
        self.assertEqual(result["exitCode"], 1)
        self.assertEqual(result["public"]["reason"], "unexpected_domain")
        self.assertEqual(len(self.transport.calls), 1)
        self.transport.calls.clear()
        self.transport.callback = lambda host, tls: self.private("quick.log", self.log("replacement.trycloudflare.com")) if tls else None
        result = self.probe.check_quick(expect_host=HOST)
        self.assertEqual(result["exitCode"], 1)
        self.assertTrue(result["domain"]["changedDuringProbe"])
        self.safe_report(result)

    def test_pid_invocation_or_restart_change_during_probe_is_not_success(self):
        changes = ({"pid": 203}, {"invocation": "d" * 32}, {"restarts": 1}, {"start": 999_000_000})
        for change in changes:
            with self.subTest(change=change):
                self.runner = Runner()
                self.probe.runner = self.runner
                self.transport.callback = lambda host, tls: self.runner.quick.update(change) if tls else None
                result = self.probe.check_quick()
                self.assertEqual(result["exitCode"], 1)
                self.assertTrue(result["servicesChanged"])
                self.safe_report(result)

    def test_old_or_unknown_invocation_log_cannot_confirm_current_domain(self):
        for invocation in ("e" * 32, "unknown", ""):
            with self.subTest(invocation=invocation):
                self.private("quick.log", self.log(invocation=invocation))
                result = self.probe.check_quick()
                self.assertEqual(result["exitCode"], 1)
                self.assertFalse(result["domain"]["logCurrent"])
                self.assertEqual(result["domain"]["status"], "unconfirmed")
        self.private("quick.log", self.log() + "IBT_QUICK_INVOCATION=" + QUICK_INSTANCE + "\n")
        self.assertEqual(self.probe.check_quick()["exitCode"], 1)

    def test_legacy_log_first_timestamp_must_belong_to_current_start(self):
        path = self.private("quick.log", np.timestamp(NOW - 9) + " INF start\nhttps://" + HOST + "\n")
        os.utime(path, (NOW, NOW))
        self.assertEqual(self.probe.check_quick()["exitCode"], 0)
        self.private("quick.log", np.timestamp(NOW - 60) + " INF old start\nhttps://" + HOST + "\n" + np.timestamp(NOW) + " ERR recent old-process error\n")
        os.utime(path, (NOW, NOW))
        self.assertEqual(self.probe.check_quick()["exitCode"], 1)

    def test_local_only_and_fixed_only_skip_public_and_check_current_node(self):
        for mode in ("local", "fixed"):
            with self.subTest(mode=mode):
                self.transport.calls.clear()
                if mode == "fixed":
                    text = (self.app / "state.conf").read_text().replace("mode=quick\ndomain=", "mode=fixed\ndomain=example.invalid")
                    self.private("state.conf", text)
                    self.runner.quick.update(active="inactive", sub="dead")
                result = self.probe.diagnose(local_only=mode == "local")
                self.assertEqual(result["exitCode"], 0)
                self.assertEqual(len(self.transport.calls), 1)
                self.assertFalse(self.transport.calls[0]["tls"])
                self.assertEqual(result["public"]["reason"], "local_only" if mode == "local" else "fixed_only")
        self.transport.callback = lambda host, tls: self.runner.node.update(invocation="f" * 32)
        self.assertEqual(self.probe.diagnose(local_only=True)["exitCode"], 1)

    def test_mismatch_or_missing_config_never_probes_network(self):
        inbound = self.config["inbounds"][0]
        inbound["listen_port"] = 22222
        inbound["users"][0]["uuid"] = "22222222-2222-4222-8222-222222222222"
        inbound["transport"]["path"] = "/ws-" + "b" * 36
        self.private("config.json", json.dumps(self.config))
        result = self.probe.diagnose()
        self.assertEqual(result["exitCode"], 2)
        self.assertEqual(result["config"], {"status": "mismatch", "portMatches": False, "uuidMatches": False, "pathMatches": False})
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.runner.calls, [])
        self.safe_report(result)
        (self.app / "state.conf").unlink()
        self.assertEqual(self.probe.diagnose()["config"]["status"], "missing")

    def test_unsafe_config_links_modes_and_ancestors_are_read_only_errors(self):
        path = self.app / "config.json"
        for failure in ("mode", "symlink", "hardlink", "ancestor"):
            with self.subTest(failure=failure):
                if path.is_symlink() or path.exists():
                    path.unlink()
                self.private("config.json", json.dumps(self.config))
                if failure == "mode":
                    path.chmod(0o644)
                elif failure == "symlink":
                    path.unlink()
                    path.symlink_to(self.app / "state.conf")
                elif failure == "hardlink":
                    os.link(path, self.app / "linked")
                else:
                    (self.home / ".local").chmod(0o775)
                result = self.probe.diagnose()
                self.assertEqual(result["exitCode"], 2)
                self.assertEqual(result["config"]["code"], "unsafe_files")
                self.assertFalse(self.transport.calls)
                if failure == "mode":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                if failure == "hardlink":
                    (self.app / "linked").unlink()
                (self.home / ".local").chmod(0o700)

    def test_protocol_version_and_proxy_values_are_allowlisted_and_sanitized(self):
        self.private("quick.log", self.log(registered=True) + "Initial protocol " + SECRET + "\nRegistered tunnel connection protocol=" + KEY + "\n")
        self.probe.env = {"HTTPS_PROXY": "http://" + SECRET + ":" + KEY + "@private.invalid:9"}
        result = self.probe.diagnose()
        self.assertEqual(result["connector"]["configuredProtocol"], "auto")
        self.assertEqual(result["connector"]["initialProtocol"], "quic")
        self.assertEqual(result["connector"]["registeredProtocol"], "http2")
        self.assertEqual(result["connector"]["version"], "2026.10.1")
        self.assertTrue(result["proxyEnvironmentPresent"])
        lines = self.safe_report(result)
        self.assertTrue(any("下次启动生效" in line for line in lines))
        self.private("quick-protocol", KEY + "\n")
        self.runner.version = SECRET
        result = self.probe.diagnose()
        self.assertEqual(result["connector"]["configuredProtocol"], "unknown")
        self.assertIsNone(result["connector"]["version"])
        (self.app / "quick-protocol").unlink()
        self.assertEqual(self.probe.configured_protocol(), "legacy-quic")
        self.safe_report(result)

    def test_retries_have_bounded_count_and_do_not_retry_config_errors(self):
        self.transport.results = [np.safe_result("ok", 101), np.safe_result("timeout"), np.safe_result("ok", 101), np.safe_result("ok", 101)]
        result = self.probe.check_quick(attempts=5, timeout=8)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(len(self.transport.calls), 4)
        (self.app / "state.conf").unlink()
        self.sleeps.clear()
        self.assertEqual(self.probe.check_quick(attempts=5)["exitCode"], 2)
        self.assertEqual(self.sleeps, [])

    def test_whole_attempt_budget_is_shared_with_commands_and_both_probes(self):
        elapsed = [MONO]
        self.probe.monotonic = lambda: elapsed[0]
        self.runner.callback = lambda args: elapsed.__setitem__(0, elapsed[0] + 1)
        self.transport.callback = lambda host, tls: elapsed.__setitem__(0, elapsed[0] + 2)
        result = self.probe.check_quick(timeout=8)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual([call["timeout"] for call in self.transport.calls], [7, 5])
        self.assertTrue(all(0 < kwargs["timeout"] <= 2 for _, kwargs in self.runner.calls))

    def test_quiet_exit_codes_and_invalid_arguments_never_echo_input(self):
        cases = [(["check-quick", "--quiet", "--expect-host", HOST], 0),
                 (["check-quick", "--quiet", "--expect-host", "https://" + SECRET + ".invalid"], 2),
                 (["check-quick", "--quiet", "--attempts", "6"], 2),
                 (["check-quick", "--quiet", "--timeout", "nan"], 2),
                 (["status", "--quiet", SECRET], 2),
                 (["check-quick", "--quiet", "--help"], 0)]
        for args, expected in cases:
            with self.subTest(args=args):
                output, stdout, stderr = [], io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = np.main(args, probe=self.probe, output=output.append)
                self.assertEqual(code, expected)
                self.assertEqual(output, [])
                self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.transport.results = [np.safe_result("refused"), np.safe_result("timeout")]
        self.assertEqual(np.main(["check-quick", "--quiet"], probe=self.probe, output=lambda line: self.fail("Quiet output")), 1)
        (self.app / "state.conf").unlink()
        self.assertEqual(np.main(["check-quick", "--quiet"], probe=self.probe, output=lambda line: self.fail("Quiet output")), 2)

    def test_json_and_argument_errors_do_not_disclose_credentials(self):
        output = []
        self.assertEqual(np.main(["status", "--json"], probe=self.probe, output=output.append), 0)
        result = json.loads(output.pop())
        self.assertEqual(result["scope"], "websocket")
        self.safe_report(result)
        self.assertEqual(np.main(["status", SECRET], probe=self.probe, output=output.append), 2)
        self.assertNotIn(SECRET, "".join(output))

    def test_internal_probe_error_is_not_network_failure_and_stops_retries(self):
        self.transport.results = [{"code": SECRET, "stderr": KEY}]
        result = self.probe.check_quick(attempts=5)
        self.assertEqual(result["exitCode"], 2)
        self.assertEqual(result["local"]["code"], "internal")
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.sleeps, [])
        self.safe_report(result)

    def test_duplicate_service_identity_is_unconfirmed_without_raw_output(self):
        original = self.runner(["systemctl", "--user", "show"])
        self.runner.stdout = original.stdout + "\n\n" + original.stdout.split("\n\n", 1)[0]
        result = self.probe.check_quick()
        self.assertEqual(result["exitCode"], 1)
        self.assertEqual(result["nodeService"]["status"], "unknown")
        self.safe_report(result)


class WaitingTests(Fixture):
    def clock(self, after_sleep=None):
        elapsed = [0.0]
        self.probe.monotonic = lambda: MONO + elapsed[0]
        def sleep(seconds):
            self.sleeps.append(seconds)
            elapsed[0] += seconds
            if after_sleep is not None:
                after_sleep(elapsed[0])
        self.probe.sleeper = sleep
        return elapsed

    def no_address(self):
        self.private("quick.log", "IBT_QUICK_INVOCATION=" + QUICK_INSTANCE + "\n" + np.timestamp(NOW - 9) + " INF Starting tunnel\n")

    def test_waits_beyond_five_fast_rounds_for_address_then_public_readiness(self):
        self.no_address()
        elapsed = self.clock(lambda seconds: self.private("quick.log", self.log()) if seconds >= 6 else None)
        def network(host, tls):
            if tls and elapsed[0] < 8:
                self.transport.results.insert(0, np.safe_result("timeout"))
        self.transport.callback = network
        progress = []
        report = self.probe.check_quick(attempts=1, timeout=8, wait_seconds=12, progress=progress.append)
        self.assertEqual(report["exitCode"], 0)
        self.assertEqual(elapsed[0], 8)
        self.assertEqual(len(self.sleeps), 8)
        self.assertTrue(report["domain"]["logCurrent"])
        self.assertTrue(any("等待临时地址（已等待 5 秒）" in line for line in progress))
        self.assertTrue(any("检查公网握手" in line for line in progress))
        for line in progress:
            self.assertTrue(line.startswith("  连接进度： "))
            for secret in (IDENTITY, PATH, SECRET, KEY, HOST, NODE_INSTANCE, QUICK_INSTANCE):
                self.assertNotIn(secret, line)
        self.safe_report(report)

    def test_old_log_and_successful_handshakes_cannot_finish_wait_early(self):
        self.private("quick.log", self.log(invocation="d" * 32, registered=True))
        elapsed = self.clock()
        report = self.probe.check_quick(wait_seconds=6, timeout=8)
        self.assertEqual(elapsed[0], 6)
        self.assertEqual(report["exitCode"], 1)
        self.assertEqual(report["domain"]["status"], "unconfirmed")
        self.assertFalse(report["domain"]["logCurrent"])
        self.assertEqual(report["local"]["code"], "ok")
        self.assertEqual(report["public"]["code"], "ok")
        self.safe_report(report)

    def test_rounds_and_network_timeouts_are_clipped_to_total_deadline(self):
        elapsed = self.clock()
        observed = []
        class BudgetTransport:
            def probe(self, host, port, path, *, tls, timeout):
                observed.append((elapsed[0], timeout, tls))
                elapsed[0] += min(timeout, 3 if tls else 1)
                return np.safe_result("timeout" if tls or timeout < 1 else "ok")
        self.probe.transport = BudgetTransport()
        report = self.probe.check_quick(wait_seconds=7, timeout=8)
        self.assertEqual(report["exitCode"], 1)
        self.assertEqual(elapsed[0], 7)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(len(observed), 4)
        for started, timeout, _ in observed:
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 7 - started)
        self.assertEqual(observed[-1][1], 1)
        self.safe_report(report)

    def test_last_sleep_is_clipped_to_fractional_remaining_budget(self):
        self.no_address()
        elapsed = self.clock()
        report = self.probe.check_quick(wait_seconds=2.25, timeout=8)
        self.assertEqual(report["exitCode"], 1)
        self.assertEqual(elapsed[0], 2.25)
        self.assertEqual(self.sleeps, [1, 1, 0.25])
        self.assertEqual([call["timeout"] for call in self.transport.calls], [2.25, 1.25, 0.25])

    def test_configuration_error_stops_wait_without_retry_or_sleep(self):
        (self.app / "state.conf").unlink()
        elapsed = self.clock()
        report = self.probe.check_quick(wait_seconds=60, timeout=8)
        self.assertEqual(report["exitCode"], 2)
        self.assertEqual(elapsed[0], 0)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.transport.calls, [])

    def test_wait_cli_quiet_remains_silent_and_rejects_unbounded_values(self):
        self.no_address()
        elapsed = self.clock()
        output = []
        self.assertEqual(np.main(["check-quick", "--wait-seconds", "2.25", "--quiet"], probe=self.probe, output=output.append), 1)
        self.assertEqual(elapsed[0], 2.25)
        self.assertEqual(output, [])
        for value in ("-1", "61", "nan", "inf", SECRET):
            with self.subTest(value=value):
                self.assertEqual(np.main(["check-quick", "--wait-seconds", value, "--quiet"], probe=self.probe, output=output.append), 2)
                self.assertEqual(output, [])


class RecommendationTests(Fixture):
    def report(self):
        return self.probe.diagnose()

    def advice(self, report, expected):
        self.assertEqual(np.recommend(report), expected)
        lines = self.safe_report(report)
        advice = "\n".join(label + "： " + text for label, text in np.ACTION_GUIDANCE[expected])
        self.assertIn(advice.splitlines()[0], "\n".join(lines))
        if expected != "try_http2":
            self.assertNotIn("HTTP/2", advice)
        return advice

    def test_config_failures_take_precedence_over_later_quic_errors(self):
        for status in ("missing", "error", "mismatch", "unknown"):
            with self.subTest(status=status):
                report = self.report()
                report["exitCode"] = 2
                report["config"]["status"] = status
                report["connector"]["signal"] = "quic_timeout"
                report["public"] = np.safe_result("timeout")
                self.advice(report, "check_config")

    def test_node_and_local_failures_take_precedence_over_public_errors(self):
        for status, code, action in (("stopped", "ok", "check_node"),
                                     ("running", "refused", "check_node"),
                                     ("running", "http_status", "check_node"),
                                     ("unknown", "ok", "check_node_state"),
                                     ("running", "internal", "retry_probe")):
            with self.subTest(status=status, code=code):
                report = self.report()
                report["exitCode"] = 1
                report["nodeService"]["status"] = status
                report["local"] = np.safe_result(code, 404 if code == "http_status" else None)
                report["public"] = np.safe_result("timeout")
                report["connector"]["signal"] = "quic_timeout"
                self.advice(report, action)
        report = self.report()
        report.update(exitCode=1, servicesChanged=True)
        self.advice(report, "check_node_state")

    def test_domain_identity_and_connector_state_must_be_confirmed(self):
        for status in ("missing", "error", "unconfirmed", "changed"):
            with self.subTest(status=status):
                report = self.report()
                report["exitCode"] = 1
                report["domain"]["status"] = status
                text = self.advice(report, "check_domain")
                self.assertIn("先确认", text)
                self.assertIn("更换域名", text)
        report = self.report()
        report["domain"]["logCurrent"] = False
        self.advice(report, "check_domain")
        for status in ("unknown", "stopped"):
            report = self.report()
            report["exitCode"] = 1
            report["connector"]["status"] = status
            self.advice(report, "check_connector")

    def test_dns_and_tls_errors_never_suggest_transport_switch(self):
        for code, action in (("dns", "check_dns"), ("tls", "check_tls"), ("tls_certificate", "check_tls")):
            with self.subTest(code=code):
                report = self.report()
                report["exitCode"] = 1
                report["public"] = np.safe_result(code)
                report["connector"]["signal"] = "quic_timeout"
                text = self.advice(report, action)
                if action == "check_tls":
                    self.assertIn("本机时间", text)
                    self.assertIn("校验开启", text)

    def test_http_status_and_websocket_errors_have_specific_advice(self):
        cases = [(502, "check_origin"), (503, "check_edge"), (530, "check_edge"),
                 (302, "check_access"), (401, "check_access"), (403, "check_access"),
                 (429, "check_limits"), (404, "check_websocket"), (200, "check_websocket")]
        for status, action in cases:
            with self.subTest(status=status):
                report = self.report()
                report["exitCode"] = 1
                report["public"] = np.safe_result("http_status", status)
                report["connector"]["signal"] = "quic_timeout"
                text = self.advice(report, action)
                self.assertNotIn("HTTP 1033", text)
                if action == "check_edge":
                    self.assertIn("可能", text)
                    self.assertIn("不能确定", text)
        for code in ("http_invalid", "accept_invalid", "upgrade_invalid"):
            report = self.report()
            report["exitCode"] = 1
            report["public"] = np.safe_result(code)
            self.advice(report, "check_websocket")
        self.assertNotIn("httpStatus", np.safe_result("http_status", 1033))

    def test_http2_requires_current_quic_timeout_and_network_failure(self):
        report = self.report()
        report["exitCode"] = 1
        report["connector"]["signal"] = "quic_timeout"
        for code in ("timeout", "refused", "network"):
            report["public"] = np.safe_result(code)
            self.assertIn("确认切换", self.advice(report, "try_http2"))
        report["connector"]["signal"] = None
        self.advice(report, "check_network")
        report["connector"]["signal"] = "quic_timeout"
        report["domain"]["logCurrent"] = False
        self.advice(report, "check_domain")

    def test_quic_history_does_not_suggest_http2_already_in_use(self):
        for key, value in (("configuredProtocol", "http2"), ("configuredProtocol", "unknown"),
                           ("initialProtocol", "http2"), ("registeredProtocol", "http2")):
            with self.subTest(key=key, value=value):
                report = self.report()
                report["exitCode"] = 1
                report["public"] = np.safe_result("timeout")
                report["connector"].update(signal="quic_timeout")
                report["connector"][key] = value
                self.advice(report, "check_network")

    def test_success_points_client_minus_one_to_link_logs_and_test_url(self):
        report = self.report()
        text = self.advice(report, "check_client")
        for value in ("-1", "当前链接", "客户端核心日志", "真实延迟测试 URL", "VLESS", "代理出站"):
            self.assertIn(value, text)
        self.assertNotIn("地址提醒", text)
        for reason in ("local_only", "fixed_only"):
            with self.subTest(reason=reason):
                report["public"] = {**np.safe_result("skipped"), "reason": reason}
                report["domain"]["status"] = "skipped"
                text = self.advice(report, "check_public")
                self.assertIn("公网检查已跳过", text)

    def test_json_action_matches_render_is_pure_allowlisted_and_has_no_private_values(self):
        output = []
        self.assertEqual(np.main(["status", "--json"], probe=self.probe, output=output.append), 0)
        report = json.loads(output.pop())
        before = copy.deepcopy(report)
        self.assertEqual(report["nextAction"], "check_client")
        self.assertEqual(np.recommend(report), report["nextAction"])
        self.assertEqual(report, before)
        self.safe_report(report)
        for item in (None, [], SECRET):
            self.assertEqual(np.recommend(item), "retry_probe")
        report["public"] = {"code": {"secret": SECRET}, "body": KEY, "url": PATH}
        self.assertEqual(np.recommend(report), "retry_probe")
        for action, lines in np.ACTION_GUIDANCE.items():
            self.assertRegex(action, r"^[a-z0-9_]+$")
            for label, text in lines:
                self.assertEqual(len(label), 4)
                self.assertTrue(all("\u4e00" <= char <= "\u9fff" for char in label))
                self.assertNotIn(SECRET, text)


class FakeSocket:
    def __init__(self, behavior="ok"):
        self.behavior = behavior
        self.closed = False
        self.request = b""
        self.response = b""
        self.connected = None
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected = address
        if self.behavior == "refused":
            raise ConnectionRefusedError(SECRET)

    def sendall(self, request):
        self.request = request
        key = request.split(b"Sec-WebSocket-Key: ", 1)[1].split(b"\r\n", 1)[0]
        accept = base64.b64encode(hashlib.sha1(key + np.WS_GUID).digest())
        if self.behavior == "accept":
            accept = SECRET.encode()
        if self.behavior == "redirect":
            self.response = b"HTTP/1.1 302 Found\r\nLocation: https://" + SECRET.encode() + b".invalid\r\n\r\n"
            return
        if self.behavior == "oversize":
            self.response = b"HTTP/1.1 101 Switching Protocols\r\nX-Long: " + b"a" * np.MAX_HEADER
            return
        self.response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n"
        if self.behavior == "duplicate":
            self.response += b"Sec-WebSocket-Accept: " + accept + b"\r\n"
        elif self.behavior == "missing_upgrade":
            self.response = self.response.replace(b"Upgrade: WebSocket\r\n", b"")
        elif self.behavior == "unsolicited":
            self.response += b"Sec-WebSocket-Protocol: private\r\n"
        self.response += b"\r\n" + SECRET.encode()

    def recv(self, count):
        result, self.response = self.response[:count], self.response[count:]
        return result

    def close(self):
        self.closed = True


class TLSContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self, behavior="ok"):
        self.hosts = []
        self.behavior = behavior

    def wrap_socket(self, connection, *, server_hostname):
        self.hosts.append(server_hostname)
        if self.behavior == "certificate":
            raise ssl.SSLCertVerificationError(SECRET + KEY)
        return connection


class TransportTests(unittest.TestCase):
    def transport(self, behavior="ok", tls_behavior="ok"):
        connection, context = FakeSocket(behavior), TLSContext(tls_behavior)
        self.resolutions = []
        def resolver(*args):
            self.resolutions.append(args)
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))]
        return np.WebSocketTransport(resolver=resolver, socket_factory=lambda *args: connection,
                                     ssl_context_factory=lambda: context, random_bytes=lambda count: b"a" * count), connection, context

    def test_valid_local_and_tls_handshakes_verify_accept_and_close(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                transport, connection, context = self.transport()
                result = transport.probe(HOST if tls else "127.0.0.1", 443 if tls else 20000, PATH, tls=tls, timeout=1)
                self.assertEqual(result, {"status": "passed", "code": "ok", "httpStatus": 101})
                self.assertTrue(connection.closed)
                self.assertIn(("GET " + PATH + " HTTP/1.1").encode(), connection.request)
                self.assertEqual(len(self.resolutions), 1 if tls else 0)
                self.assertEqual(context.hosts, [HOST] if tls else [])
                self.assertNotIn(IDENTITY.encode(), connection.request)
                self.assertNotIn(SECRET, json.dumps(result))

    def test_101_alone_invalid_accept_and_unsolicited_protocol_do_not_pass(self):
        for behavior, expected in (("accept", "accept_invalid"), ("duplicate", "accept_invalid"),
                                   ("missing_upgrade", "upgrade_invalid"), ("unsolicited", "upgrade_invalid"),
                                   ("oversize", "http_invalid"), ("refused", "refused")):
            with self.subTest(behavior=behavior):
                transport, connection, _ = self.transport(behavior)
                result = transport.probe("127.0.0.1", 20000, PATH, tls=False, timeout=1)
                self.assertEqual(result["code"], expected)
                self.assertTrue(connection.closed)
                self.assertNotIn(SECRET, json.dumps(result))

    def test_tls_validation_and_redirects_cannot_be_bypassed(self):
        transport, _, context = self.transport(tls_behavior="certificate")
        self.assertEqual(transport.probe(HOST, 443, PATH, tls=True, timeout=1)["code"], "tls_certificate")
        context.behavior = "ok"
        context.check_hostname = False
        self.assertEqual(transport.probe(HOST, 443, PATH, tls=True, timeout=1)["code"], "tls_certificate")
        transport, connection, _ = self.transport("redirect")
        result = transport.probe(HOST, 443, PATH, tls=True, timeout=1)
        self.assertEqual(result, {"status": "failed", "code": "http_status", "httpStatus": 302})
        self.assertEqual(len(self.resolutions), 1)
        self.assertTrue(connection.closed)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_untrusted_destination_or_request_path_never_opens_a_socket(self):
        transport = np.WebSocketTransport(socket_factory=lambda *args: self.fail("Unexpected socket"))
        for host, port, path, tls in (("example.com", 443, PATH, True), (HOST, 80, PATH, True),
                                      ("127.0.0.2", 20000, PATH, False), ("127.0.0.1", 20000, PATH + "\r\n" + SECRET, False),
                                      (HOST + ".evil.invalid", 443, PATH, True), (HOST, 443, None, True)):
            with self.subTest(host=host, path=path):
                self.assertEqual(transport.probe(host, port, path, tls=tls, timeout=1)["code"], "internal")

    def test_blocked_dns_is_bounded_and_late_resolution_cannot_connect(self):
        release, done = threading.Event(), threading.Event()
        observed = []
        def resolver(*args):
            observed.append(threading.current_thread().daemon)
            release.wait(2)
            done.set()
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))]
        opened = []
        transport = np.WebSocketTransport(resolver=resolver, socket_factory=lambda *args: opened.append(args))
        started = time.monotonic()
        try:
            result = transport.probe(HOST, 443, PATH, tls=True, timeout=0.04)
            self.assertEqual(result["code"], "timeout")
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(observed, [True])
        finally:
            release.set()
            self.assertTrue(done.wait(1))
        self.assertEqual(opened, [])


if __name__ == "__main__":
    unittest.main()
