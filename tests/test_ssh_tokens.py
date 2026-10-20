"""Offline token replacement tests; every credential and machine is synthetic."""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import heartbeat as hb
import ssh_tokens as tokens


OLD = "ibssh_TEST_OLD_CREDENTIAL"
NEW = "ibssh_TEST_NEW_CREDENTIAL"
KEY = "ibk_TEST_API_CREDENTIAL"
MACHINE_A = "m_" + "a" * 26
MACHINE_B = "m_" + "b" * 26


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = hb.parse_time("2026-10-20T12:00:00Z")
        self.messages, self.calls, self.probes, self.saves = [], [], [], []
        self.api_error = None
        self.probe_errors = []
        self.new_expiry = None
        self.manager = hb.Manager(home=self.temp.name, clock=lambda: self.now,
                                  output=self.messages.append, env={})
        self.manager.ensure_cfg(create=True)
        self.config = self.manager.new_config()
        expiry = hb.iso_time(self.now + 1800)
        self.target = {
            "id": "ssh_test", "label": "Test machine", "kind": "ssh", "revision": "a" * 32,
            "ssh": {"user": OLD, "host": hb.GATEWAY, "port": 2222, "family": None},
            "tokenExpiry": {"kind": "verified", "expiresAt": expiry},
            "rotation": {"enabled": True, "armed": False, "machineId": MACHINE_A,
                         "ttlSeconds": 86400, "renewBeforeSeconds": 3600,
                         "activeExpiresAt": expiry, "activeTokenId": "cn_TEST_OLD",
                         "activeFingerprint": tokens.fingerprint(OLD)},
        }
        self.config["targets"] = [self.target]
        hb.atomic_json(self.manager.config_file, self.config)
        hb.atomic_text(self.manager.key_file, KEY + "\n")

    def save(self, updated):
        self.saves.append(copy.deepcopy(updated))
        self.manager.persist_target(self.config, updated)

    def api(self, method, route, body=None):
        self.calls.append((method, route, copy.deepcopy(body)))
        if method != "POST" or not route.endswith("/ssh-tokens"):
            self.fail("Unexpected endpoint, particularly a token revocation")
        on_disk = self.manager.load_config(required=True)["targets"][0]
        intent = on_disk["rotation"]["intent"]
        self.assertEqual(intent["state"], "in_flight")
        self.assertEqual(intent["body"], body)
        self.assertEqual(on_disk["ssh"]["user"], OLD)
        self.assertEqual(stat.S_IMODE(os.stat(self.manager.config_file).st_mode), 0o600)
        if self.api_error:
            raise self.api_error
        expiry = hb.iso_time(self.new_expiry if self.new_expiry is not None else self.now + body["ttlSeconds"])
        return {"id": "cn_TEST_NEW", "name": body["name"], "machineId": route.split("/")[3],
                "token": NEW, "host": hb.GATEWAY, "port": 2222,
                "command": "ssh -p 2222 " + NEW + "@" + hb.GATEWAY,
                "expiresAt": expiry, "hostKeyFingerprint": "SHA256:TEST_ONLY"}

    def probe(self, candidate):
        self.probes.append(copy.deepcopy(candidate))
        on_disk = self.manager.load_config(required=True)["targets"][0]
        self.assertEqual(on_disk["ssh"]["user"], OLD, "Never replace before verification")
        self.assertEqual(on_disk["rotation"]["pending"]["ssh"]["user"], NEW)
        if self.probe_errors:
            error = self.probe_errors.pop(0)
            if error:
                raise error
        return {}

    def run_rotation(self, **kwargs):
        with self.manager.lock() as acquired:
            self.assertTrue(acquired)
            return tokens.maybe_rotate(self.config, self.target, self.api, self.probe,
                                       self.save, now=self.now, **kwargs)

    def reload(self):
        self.config = self.manager.load_config(required=True)
        self.target = self.config["targets"][0]

    def test_disabled_never_reads_api_key_or_issues_a_token(self):
        self.target.pop("rotation")
        self.assertEqual(self.run_rotation()["status"], "disabled")
        self.target["rotation"] = {"enabled": False, "armed": False}
        self.assertEqual(self.run_rotation()["status"], "disabled")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.probes, [])
        self.assertEqual(self.saves, [])

    def test_not_due_does_not_issue(self):
        expiry = hb.iso_time(self.now + 7200)
        self.target["rotation"]["activeExpiresAt"] = expiry
        self.target["tokenExpiry"]["expiresAt"] = expiry
        self.assertEqual(self.run_rotation()["status"], "not_due")
        self.assertEqual(self.calls, [])

    def test_short_ttl_cannot_claim_rotation_before_next_timer_round(self):
        self.target["rotation"].update(ttlSeconds=60, renewBeforeSeconds=1)
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.probes, [])

    def test_larger_interval_rechecks_rotation_scheduling_margin(self):
        self.target["rotation"]["renewBeforeSeconds"] = 1800
        expiry = hb.iso_time(self.now + 7200)
        self.target["rotation"]["activeExpiresAt"] = expiry
        self.assertEqual(self.run_rotation()["status"], "not_due")
        self.config["intervalSeconds"] = 900
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_due_token_is_persisted_probed_then_atomically_replaces(self):
        original_revision = self.target["revision"]
        result = self.run_rotation()
        self.assertEqual(result["status"], "rotated")
        self.assertTrue(result["changed"])
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.calls[0][2]["name"].startswith("ib-rotate-"))
        self.assertEqual(len(self.probes), 1)
        self.assertEqual(self.target["ssh"]["user"], NEW)
        self.assertEqual(self.target["tokenExpiry"], {"kind": "verified", "expiresAt": hb.iso_time(self.now + 86400)})
        self.assertNotEqual(self.target["revision"], original_revision)
        self.assertNotIn("pending", self.target["rotation"])
        self.assertNotIn("intent", self.target["rotation"])
        self.assertNotIn(NEW, result["message"])
        self.assertNotIn(KEY, result["message"])
        self.reload()
        self.assertEqual(self.target["ssh"]["user"], NEW)

    def test_timeout_keeps_same_durable_intent_and_never_reposts(self):
        self.api_error = hb.HeartbeatError("timeout " + KEY + " " + NEW, "timeout")
        self.assertEqual(self.run_rotation()["status"], "ambiguous")
        intent = copy.deepcopy(self.target["rotation"]["intent"])
        self.reload()  # simulate a controller restart
        self.assertEqual(self.run_rotation()["status"], "ambiguous")
        self.assertEqual(self.run_rotation(force=True)["status"], "ambiguous")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.target["rotation"]["intent"], intent)
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertNotIn(KEY, json.dumps(self.target))

    def test_only_explicit_ambiguous_confirmation_allows_a_new_grant(self):
        self.api_error = hb.HeartbeatError("lost reply", "network")
        self.run_rotation()
        original_name = self.calls[0][2]["name"]
        self.api_error = None
        result = self.run_rotation(force=True, allow_ambiguous=True)
        self.assertEqual(result["status"], "rotated")
        self.assertEqual(len(self.calls), 2)
        self.assertNotEqual(original_name, self.calls[1][2]["name"])

    def test_crash_after_intent_before_reply_is_also_ambiguous(self):
        legacy_body = {"name": "isb-rotate-legacy-request", "ttlSeconds": 86400}
        self.target["rotation"]["intent"] = {
            "state": "in_flight", "localId": "x" * 32, "attempts": 1,
            "body": legacy_body,
        }
        self.assertEqual(self.run_rotation()["status"], "ambiguous")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.target["rotation"]["intent"]["body"], legacy_body)
        self.reload()
        self.assertEqual(self.run_rotation()["status"], "ambiguous")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.target["rotation"]["intent"]["body"], legacy_body)

    def test_legacy_rejected_request_retries_its_original_body(self):
        legacy_body = {"name": "isb-rotate-legacy-rejected", "ttlSeconds": 86400}
        self.target["rotation"]["intent"] = {
            "state": "rejected", "localId": "a" * 32, "attempts": 1,
            "retryAt": self.now - 1, "body": copy.deepcopy(legacy_body),
        }
        self.assertEqual(self.run_rotation()["status"], "rotated")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][2], legacy_body)

    def test_probe_failure_keeps_old_token_and_next_run_only_verifies_pending(self):
        self.probe_errors = [hb.HeartbeatError("invalid " + NEW, "ssh_failed")]
        result = self.run_rotation()
        self.assertEqual(result["status"], "pending")
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertEqual(self.target["rotation"]["pending"]["ssh"]["user"], NEW)
        self.reload()
        result = self.run_rotation()
        self.assertEqual(result["status"], "rotated")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.probes), 2)

    def test_estimated_expiry_cannot_override_platform_record(self):
        self.target["tokenExpiry"] = {"kind": "estimated", "expiresAt": hb.iso_time(self.now + 86400 * 365)}
        self.assertEqual(self.run_rotation()["status"], "rotated")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.target["tokenExpiry"]["kind"], "verified")
        self.assertEqual(self.target["tokenExpiry"]["expiresAt"], hb.iso_time(self.now + 86400))

    def test_premature_user_estimate_is_repaired_without_issuing(self):
        actual = hb.iso_time(self.now + 7200)
        self.target["rotation"]["activeExpiresAt"] = actual
        self.target["tokenExpiry"] = {"kind": "estimated", "expiresAt": hb.iso_time(self.now - 3600)}
        self.assertEqual(self.run_rotation()["status"], "not_due")
        self.assertEqual(self.target["tokenExpiry"], {"kind": "verified", "expiresAt": actual})
        self.assertEqual(self.calls, [])

    def test_definite_auth_failures_are_redacted_and_retry_is_bounded(self):
        for code in ("unauthorized", "forbidden"):
            with self.subTest(code=code):
                self.target["rotation"].pop("intent", None)
                self.calls.clear()
                self.api_error = hb.HeartbeatError("API body leaked " + KEY + " " + NEW, code)
                for attempt in range(5):
                    result = self.run_rotation()
                    self.now += tokens.RETRY_DELAY + 1
                    self.assertEqual(result["status"], "blocked")
                    self.assertNotIn(KEY, result["message"])
                    self.assertNotIn(NEW, result["message"])
                self.assertEqual(len(self.calls), tokens.MAX_REJECTED_ATTEMPTS)
                self.assertEqual(len({call[2]["name"] for call in self.calls}), 1)
                self.assertEqual(self.target["ssh"]["user"], OLD)

    def test_no_binding_never_guesses_machine_from_opaque_token(self):
        self.target["rotation"].pop("machineId")
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_changed_active_token_needs_rebinding(self):
        self.target["ssh"]["user"] = "ibssh_TEST_DIFFERENT_USER_PASTE"
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_controller_restart_after_old_expiry_can_replace_with_valid_api(self):
        expiry = hb.iso_time(self.now - 86400)
        self.target["rotation"]["activeExpiresAt"] = expiry
        self.target["tokenExpiry"]["expiresAt"] = expiry
        self.assertEqual(self.run_rotation()["status"], "rotated")
        self.assertEqual(self.target["ssh"]["user"], NEW)

    def test_short_platform_expiry_is_needs_action_without_token_churn(self):
        self.new_expiry = self.now + 1200
        result = self.run_rotation()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(self.target["rotation"]["needsAction"], "short_lifetime")
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertEqual(self.probes, [])
        self.reload()
        self.now += 1800
        for _ in range(5):
            self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(len(self.calls), 1)
        self.new_expiry = self.now + 86400
        self.assertEqual(self.run_rotation(force=True)["status"], "rotated")
        self.assertEqual(len(self.calls), 2)

    def test_already_expired_response_blocks_background_reissuance(self):
        self.new_expiry = self.now - 1
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(self.target["rotation"]["needsAction"], "short_lifetime")
        self.reload()
        self.now += 300
        self.assertEqual(self.run_rotation()["status"], "blocked")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.probes, [])
        self.assertEqual(self.target["ssh"]["user"], OLD)

    def test_disabled_manual_rotation_does_not_reenable_schedule(self):
        self.target["rotation"].update(enabled=False, armed=False)
        self.assertEqual(self.run_rotation(force=True)["status"], "rotated")
        self.assertFalse(self.target["rotation"]["enabled"])

    def test_pending_setup_enables_only_after_actual_ssh_success(self):
        self.target["rotation"].update(enabled=False, armed=True)
        self.probe_errors = [hb.HeartbeatError("failed", "ssh_failed")]
        self.assertEqual(self.run_rotation()["status"], "pending")
        self.assertFalse(self.target["rotation"]["enabled"])
        self.assertEqual(self.run_rotation()["status"], "rotated")
        self.assertTrue(self.target["rotation"]["enabled"])
        self.assertFalse(self.target["rotation"]["armed"])

    def test_intent_must_reach_private_storage_before_post(self):
        with self.manager.lock():
            with self.assertRaises(OSError):
                tokens.maybe_rotate(self.config, self.target, self.api, self.probe,
                                    mock.Mock(side_effect=OSError("disk full")), now=self.now)
        self.assertEqual(self.calls, [])

    def test_post_success_then_commit_failure_preserves_pending_for_recovery(self):
        def fail_final_save(updated):
            if updated["ssh"]["user"] == NEW:
                raise OSError("disk full")
            self.save(updated)

        with self.manager.lock():
            with self.assertRaises(OSError):
                tokens.maybe_rotate(self.config, self.target, self.api, self.probe,
                                    fail_final_save, now=self.now)
        self.reload()
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertIn("pending", self.target["rotation"])
        self.assertEqual(self.run_rotation()["status"], "rotated")
        self.assertEqual(len(self.calls), 1)

    def test_rotate_off_retains_pending_without_revoking_any_token(self):
        self.probe_errors = [hb.HeartbeatError("failed", "ssh_failed")]
        self.run_rotation()
        count = len(self.calls)
        self.assertEqual(tokens.disable(self.manager, self.target["id"]), 0)
        self.reload()
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertIn("pending", self.target["rotation"])
        self.assertEqual(self.run_rotation()["status"], "disabled")
        self.assertEqual(len(self.calls), count)
        self.assertTrue(all(method == "POST" for method, _, _ in self.calls))

    def test_setup_requires_explicit_api_machine_selection(self):
        self.target.pop("rotation")
        hb.atomic_json(self.manager.config_file, self.config)
        prompts = iter(["2", "", "", "y"])
        self.manager.prompt = lambda _: next(prompts)
        self.manager.authorize = mock.Mock(return_value=KEY)
        self.manager.list_machines = mock.Mock(return_value=[
            {"id": MACHINE_A, "name": "A", "state": "running"},
            {"id": MACHINE_B, "name": "B", "state": "running"},
        ])
        self.manager.client = SimpleNamespace(request=lambda method, route, key, body=None: self.api(method, route, body))
        self.manager.check_ssh = self.probe
        self.assertEqual(tokens.setup(self.manager, self.target["id"]), 0)
        self.reload()
        self.assertEqual(self.target["rotation"]["machineId"], MACHINE_B)
        self.assertIn(MACHINE_B, self.calls[0][1])
        self.assertTrue(self.target["rotation"]["enabled"])

    def test_missing_key_in_explicit_setup_can_cancel_without_guessing(self):
        self.target.pop("rotation")
        hb.atomic_json(self.manager.config_file, self.config)
        self.manager.key_file.unlink()
        self.manager.secret = mock.Mock(return_value="")
        self.manager.client = mock.Mock()
        with self.assertRaises(hb.Cancelled):
            tokens.setup(self.manager, self.target["id"])
        self.manager.secret.assert_called_once()
        self.manager.client.request.assert_not_called()

    def test_setup_rejects_advance_shorter_than_schedule_before_signing(self):
        self.target.pop("rotation")
        hb.atomic_json(self.manager.config_file, self.config)
        prompts = iter(["1", "1", "0.01"])
        self.manager.prompt = lambda _: next(prompts)
        self.manager.authorize = mock.Mock(return_value=KEY)
        self.manager.list_machines = mock.Mock(return_value=[
            {"id": MACHINE_A, "name": "A", "state": "running"},
        ])
        self.manager.client = mock.Mock()
        with self.assertRaises(hb.HeartbeatError) as failure:
            tokens.setup(self.manager, self.target["id"])
        self.assertEqual(failure.exception.code, "rotation_config")
        self.manager.client.request.assert_not_called()
        self.reload()
        self.assertNotIn("rotation", self.target)

    def test_api_response_command_is_not_executed(self):
        original = self.api

        def bad_response(method, route, body=None):
            response = original(method, route, body)
            response["command"] += "; touch /tmp/should-not-exist"
            return response

        with self.manager.lock():
            result = tokens.maybe_rotate(self.config, self.target, bad_response, self.probe,
                                         self.save, now=self.now)
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(self.probes, [])
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertEqual(self.run_rotation()["status"], "ambiguous")
        self.assertEqual(len(self.calls), 1)

    def test_real_manager_run_hook_recovers_pending_and_updates_status(self):
        """Real Manager -> imported maybe_rotate -> real SSH config creation."""
        self.manager.client = SimpleNamespace(request=lambda method, route, key, body=None: self.api(method, route, body))
        new_failures = [True]
        argv_seen, ssh_users = [], []
        linger_query = ["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"]

        def runner(args, **kwargs):
            argv_seen.append(args)
            self.assertNotIn(OLD, " ".join(args))
            self.assertNotIn(NEW, " ".join(args))
            self.assertNotIn(KEY, " ".join(args))
            if args[0] == "ssh":
                file = Path(args[args.index("-F") + 1])
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
                body = file.read_text()
                user = NEW if NEW in body else OLD
                ssh_users.append(user)
                if user == NEW and new_failures:
                    new_failures.pop()
                    return SimpleNamespace(returncode=255, stdout="", stderr="synthetic failure " + NEW)
                return SimpleNamespace(returncode=0, stdout=hb.SSH_MARKER + "\n", stderr="")
            if "is-active" in args:
                return SimpleNamespace(returncode=0, stdout="active\n", stderr="")
            if "is-enabled" in args:
                return SimpleNamespace(returncode=0, stdout="enabled\n", stderr="")
            if args[:4] == ["systemctl", "--user", "show", hb.SERVICE]:
                return SimpleNamespace(returncode=0, stdout="Id=" + hb.SERVICE + "\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n", stderr="")
            if args[:3] == ["systemctl", "--user", "list-timers"]:
                return SimpleNamespace(returncode=0, stdout="[]\n", stderr="")
            if args == linger_query:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            self.fail("Unexpected subprocess")

        self.manager.runner = runner
        original_revision = self.target["revision"]
        self.assertEqual(self.manager.run_once(), 2)
        self.reload()
        self.assertEqual(self.target["ssh"]["user"], OLD)
        self.assertIn("pending", self.target["rotation"])
        self.assertEqual(len(self.calls), 1)
        self.now += 300
        self.assertEqual(self.manager.run_once(), 0)
        self.reload()
        self.assertEqual(self.target["ssh"]["user"], NEW)
        self.assertNotEqual(self.target["revision"], original_revision)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(ssh_users, [NEW, OLD, NEW], "Do not probe the verified new token twice")
        state = self.manager.read_json(self.manager.state_file, {})["targets"][0]
        self.assertEqual(state["revision"], self.target["revision"])
        self.assertEqual(state["rotationStatus"], "rotated")
        self.assertEqual(state["tokenExpiry"]["kind"], "verified")
        self.assertEqual(self.manager.status(), 0)
        self.assertEqual([args for args in argv_seen if args[0] == "loginctl"], [linger_query])
        all_output = "\n".join(self.messages) + self.manager.state_file.read_text()
        for secret in (OLD, NEW, KEY):
            self.assertNotIn(secret, all_output)
        self.assertEqual(list(self.manager.cfg.glob(".heartbeat-ssh-*")), [])

    def test_http_201_is_supported_without_idempotency_or_redirect_following(self):
        captured = []

        class Response:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"id":"cn_TEST"}'

        class Opener:
            def open(self, request, timeout):
                captured.append(request)
                return Response()

        client = hb.APIClient(opener_factory=Opener)
        result = client.request("POST", "/v1/machines/" + MACHINE_A + "/ssh-tokens", KEY,
                                {"name": "synthetic", "ttlSeconds": 86400})
        self.assertEqual(result["id"], "cn_TEST")
        headers = dict(captured[0].header_items())
        self.assertNotIn("Idempotency-key", headers)
        self.assertIsNone(hb.NoRedirect().redirect_request(captured[0], None, 302, "Found", {}, "https://example.invalid/"))

    def test_ctrl_c_has_nonzero_exit_and_preserves_unknown_intent(self):
        self.api_error = hb.HeartbeatError("lost reply", "network")
        self.run_rotation()
        before = self.manager.config_file.read_bytes()
        with mock.patch.object(tokens, "dispatch", side_effect=KeyboardInterrupt):
            self.assertEqual(tokens.main(["rotate-now", self.target["id"]], self.manager), 130)
        self.assertEqual(self.manager.config_file.read_bytes(), before)
        self.assertIn("token-status", self.messages[-1])
        with mock.patch.object(tokens, "dispatch", side_effect=hb.Cancelled):
            self.assertEqual(tokens.main(["rotate-now", self.target["id"]], self.manager), 0)


if __name__ == "__main__":
    unittest.main()
