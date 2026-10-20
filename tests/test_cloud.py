#!/usr/bin/env python3
"""Offline HTTP contract tests: never read real keys or contact InstaBox."""

import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request


SPEC = importlib.util.spec_from_file_location("ib_cloud", Path(__file__).resolve().parents[1] / "cloud.py")
cloud = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud)

KEY = "ibk_offline_test_not_a_real_key"


def machine(mid="m_testone", name="box", state="running", **extra):
    result = {"id": mid, "name": name, "state": state, "operationId": None,
              "spec": {"vcpus": 4, "memMiB": 8192, "persistentDiskGiB": 20},
              "runtime": {"ready": state == "running"}, "free": True,
              "autoSuspendAfterSeconds": 1800, "timeoutAt": None, "onTimeout": "pause"}
    result.update(extra)
    return result


def operation(state="queued", action="start", op_id="op_testone", **extra):
    result = {"id": op_id, "machineId": "m_testone", "type": action,
              "state": state, "phase": "scheduling", "error": None}
    result.update(extra)
    return result


class Response(io.BytesIO):
    def __init__(self, status, payload):
        super().__init__(json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload)
        self.status = status


class HTTP:
    """An urllib opener with queued HTTP replies; no sockets are opened."""
    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def open(self, request, timeout):
        parsed = urllib.parse.urlsplit(request.full_url)
        assert (parsed.scheme, parsed.netloc) == ("https", "api.instabox.sh")
        call = {"method": request.get_method(), "path": parsed.path,
                "query": urllib.parse.parse_qs(parsed.query),
                "headers": {k.lower(): v for k, v in request.header_items()},
                "body": json.loads(request.data) if request.data else None, "timeout": timeout}
        self.calls.append(call)
        if not self.steps:
            raise AssertionError("Unexpected HTTP request: " + call["method"] + " " + call["path"])
        step = self.steps.pop(0)
        if callable(step):
            step = step(call)
        if isinstance(step, Exception):
            raise step
        status, payload = step
        if status >= 300:
            raise urllib.error.HTTPError(request.full_url, status, "test", {}, Response(status, payload))
        return Response(status, payload)


class Clock:
    def __init__(self):
        self.value = 0

    def now(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class Heartbeat:
    """Injected local-controller contract; it never reads keys or runs services."""
    def __init__(self):
        self.data = {"configured": False, "timer": {"active": "inactive", "enabled": "disabled"},
                     "checkedAt": None, "targets": []}
        self.updates, self.refreshes = [], []
        self.result = 0

    def summary(self):
        return json.loads(json.dumps(self.data))

    def set_api_targets(self, machines, enabled=True):
        self.updates.append((json.loads(json.dumps(machines)), enabled))
        return self.result

    def refresh_observed_targets(self, machines):
        self.refreshes.extend(json.loads(json.dumps(machines)))
        return 0


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.config = self.home / ".config" / "insta-box"
        self.lines = []
        self.clock = Clock()
        self.hb = Heartbeat()

    def client(self, http, ask=None):
        return cloud.Cloud(cloud.API(KEY, http), self.config, say=self.lines.append,
                           ask=ask, clock=self.clock.now, sleep=self.clock.advance,
                           heartbeat_manager=self.hb)

    def output(self):
        return "\n".join(self.lines)

    def test_overview_all_pages_combines_only_current_controller_status(self):
        machines = [machine(name="北京节点"), machine("m_two", "东京", "running"),
                    machine("m_three", "暂停的机器", "suspended"), machine("m_four", "SSH 目标"),
                    machine("m_five", "尚未保活", "suspended")]
        self.hb.data = {"configured": True, "timer": {"active": "active", "enabled": "enabled"},
                        "checkedAt": "2026-10-20T00:00:00Z", "targets": [
                            {"machineId": "m_testone", "kind": "api", "status": "healthy"},
                            {"machineId": "m_two", "kind": "api", "status": "stale"},
                            {"machineId": "m_three", "kind": "api", "status": "healthy"},
                            {"machineId": "m_four", "kind": "ssh", "status": "healthy"}]}
        http = HTTP((200, {"machines": machines[:2], "nextCursor": "page2"}),
                    (200, {"machines": machines[2:]}))
        self.assertEqual(self.client(http).overview(), 0)
        output = self.output()
        for text in ["共 5 台", "运行 3 台", "暂停 2 台", "最近保活正常", "记录已过期", "暂停待启动", "SSH·最近连通", "未配置", "表中只显示本机任务状态"]:
            self.assertIn(text, output)
        self.assertEqual([call["method"] for call in http.calls], ["GET", "GET"])
        self.assertFalse((self.config / "machine.json").exists())
        self.assertEqual(self.hb.updates, [])
        self.assertEqual(self.hb.refreshes, [])

    def test_overview_inactive_timer_never_uses_historical_success_as_healthy(self):
        self.hb.data.update(configured=True, targets=[{"machineId": "m_testone", "kind": "api", "status": "healthy"}])
        c = self.client(HTTP())
        c.overview([machine()])
        self.assertIn("已停用", self.output())
        self.assertNotIn("最近保活正常", self.output())

    def test_overview_shows_observed_schedule_without_changing_targets(self):
        import heartbeat as hb
        self.hb.data.update(configured=True, timer={"active": "active", "enabled": "enabled"},
                            checkedAt="2026-10-20T09:30:00Z",
                            schedule={"state": "scheduled", "nextRunAt": "2026-10-20T09:32:47Z",
                                      "lastCompletedAt": "2026-10-20T09:30:01Z", "source": "systemd"})
        client = self.client(HTTP())
        client.overview([machine()])
        self.assertIn("最近完成： " + hb.format_timestamp("2026-10-20T09:30:01Z"), self.output())
        self.assertIn("下次执行： " + hb.format_timestamp("2026-10-20T09:32:47Z"), self.output())
        self.assertIn("后台自动执行", self.output())
        self.assertEqual(client.api.opener.calls, [])
        self.assertEqual(self.hb.updates, [])
        self.assertEqual(self.hb.refreshes, [])
        self.lines.clear()
        self.hb.data.update(configured=None, timer={}, schedule={}, unavailable=True)
        client.overview([machine()])
        self.assertNotIn("自动保活： 尚未配置", self.output())
        self.assertNotIn("后台自动执行", self.output())

    def test_overview_malformed_machine_state_is_unknown_without_false_health(self):
        self.hb.data.update(configured=True, timer={"active": "active", "enabled": "enabled"},
                            targets=[{"machineId": "m_testone", "kind": "api", "status": "healthy"}])
        c = self.client(HTTP())
        for invalid in [[], {"private": KEY}]:
            c.overview([machine(state=invalid)])
        self.assertIn("未知", self.output())
        self.assertIn("等待机器就绪", self.output())
        self.assertNotIn("最近保活正常", self.output())
        self.assertNotIn(KEY, self.output())

    def test_overview_unbound_ssh_does_not_guess_machine_or_expose_token(self):
        self.hb.data.update(configured=True, targets=[{"kind": "ssh", "machineId": None, "status": "healthy", "label": "box"}])
        c = self.client(HTTP())
        c.overview([machine(name="box ibssh_offline_hidden\x1b[0m")])
        self.assertIn("未配置", self.output())
        self.assertIn("未明确绑定机器", self.output())
        self.assertNotIn("ibssh_", self.output())
        self.assertNotIn("\x1b", self.output())
        self.assertNotIn("SSH·最近连通", self.output())

    def test_overview_cjk_columns_and_truncated_duplicate_names_are_identifiable(self):
        names = ["中文组合e\u0301", "ASCII", "重复名称" * 10, "重复名称" * 10 + "尾"]
        c = self.client(HTTP())
        c.overview([machine("m_" + str(index), name) for index, name in enumerate(names)])
        rows = [line for line in self.lines if re.match(r"\s*[1-4]\s", line)]
        columns = [cloud.display_width(line[:line.index("运行中")]) for line in rows]
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(set(columns)), 1)
        self.assertIn("3=m_2", self.output())
        self.assertIn("4=m_3", self.output())
        self.assertIn("…", self.output())

    def test_overview_real_local_summary_checks_controller_revision_and_expiry(self):
        import heartbeat as hb
        now = 1792454400
        manager = hb.Manager(home=self.home, clock=lambda: now, output=self.lines.append)
        manager.ensure_cfg(create=True)
        config = manager.new_config()
        config["targets"] = [{"id": "api_one", "kind": "api", "machineId": "m_testone", "label": "box", "revision": "b" * 32}]
        hb.atomic_json(manager.config_file, config)
        record = {"id": "api_one", "revision": "b" * 32, "result": "success",
                  "lastSuccessAt": hb.iso_time(now - 1000), "checkedAt": hb.iso_time(now - 1000),
                  "expiresAt": hb.iso_time(now - 100)}
        state = {"schema": 1, "controllerId": config["controllerId"], "checkedAt": hb.iso_time(now - 1000), "targets": [record]}
        hb.atomic_json(manager.state_file, state)
        manager.timer_state = lambda: ("active", "enabled")
        manager.read_key = mock.Mock(side_effect=AssertionError("overview must not read an API key"))
        manager.client = mock.Mock()
        manager.client.request.side_effect = AssertionError("overview must not call the heartbeat API")
        c = self.client(HTTP())
        c.heartbeat_manager = manager
        before = manager.config_file.read_bytes()
        c.overview([machine()])
        self.assertIn("记录已过期", self.output())
        self.assertNotIn("最近保活正常", self.output())
        self.lines.clear()
        record.update(lastSuccessAt=hb.iso_time(now), expiresAt=hb.iso_time(now + 900), revision="c" * 32)
        hb.atomic_json(manager.state_file, state)
        c.overview([machine()])
        self.assertIn("等待验证", self.output())
        self.assertNotIn("最近保活正常", self.output())
        self.assertEqual(manager.config_file.read_bytes(), before)

    def test_default_cloud_command_is_read_only_overview(self):
        http = HTTP((200, {"machines": [machine()]}))
        c = self.client(http, ask=lambda _: self.fail("overview must not choose a target"))
        with mock.patch.object(cloud, "Cloud", return_value=c), mock.patch.object(cloud, "load_api", return_value=c.api):
            self.assertEqual(cloud.main([]), 0)
        self.assertIn("机器总览", self.output())
        self.assertEqual(len(http.calls), 1)
        self.assertFalse((self.config / "machine.json").exists())

    def test_info_choose_ignores_saved_target(self):
        cloud.atomic_private(self.config / "machine.json", {"sandboxId": "m_testone", "name": "old"})
        two = machine("m_two", "second")
        http = HTTP((200, {"machines": [machine(), two]}), (200, two))
        c = self.client(http, ask=lambda _: "2")
        with mock.patch.object(cloud, "Cloud", return_value=c), mock.patch.object(cloud, "load_api", return_value=c.api):
            self.assertEqual(cloud.main(["info", "--choose"]), 0)
        self.assertEqual(http.calls[-1]["path"], "/v1/machines/m_two")
        self.assertEqual(self.hb.refreshes, [])

    def test_operations_chooses_from_current_list_instead_of_saved_target(self):
        cloud.atomic_private(self.config / "machine.json", {"sandboxId": "m_testone", "name": "old"})
        two = machine("m_two", "second", operationId="op_second")
        http = HTTP((200, {"machines": [machine(), two]}), (200, two),
                    (200, operation("queued", op_id="op_second", machineId="m_two")))
        c = self.client(http, ask=lambda _: "2")
        with mock.patch.object(cloud, "Cloud", return_value=c), mock.patch.object(cloud, "load_api", return_value=c.api):
            self.assertEqual(cloud.main(["operations", "--wait", "0"]), 3)
        self.assertTrue(all(call["method"] == "GET" for call in http.calls))
        self.assertIn("op_second", self.output())

    def test_batch_preserves_selection_order_deduplicates_and_reports_four_outcomes(self):
        one, two, three, four = machine(), machine("m_two", "second", "stopped"), machine("m_three", "third", "stopped"), machine("m_four", "fourth", "suspended")
        http = HTTP((200, {"machines": [one, two, three, four]}), (200, two),
                    (202, operation("succeeded", op_id="op_second", machineId="m_two")),
                    (200, machine("m_two", "second")), (200, one), (200, three),
                    (503, {"error": {"message": KEY}}), (200, four),
                    (403, {"error": {"message": KEY}}))
        c = self.client(http, ask=lambda _: "2,1,3,2,4")
        self.assertEqual(c.batch("start", wait=0), 3)
        self.assertEqual([call["path"] for call in http.calls if call["method"] == "POST"],
                         ["/v1/machines/m_two/start", "/v1/machines/m_three/start", "/v1/machines/m_four/start"])
        self.assertIn("完成 1 台 · 跳过 1 台 · 失败 1 台 · 未确认 1 台", self.output())
        self.assertEqual(c.read_record("m_three")["state"], "unknown")
        self.assertEqual([row["id"] for row in self.hb.refreshes], ["m_two", "m_testone"])
        self.assertEqual(self.hb.updates, [])
        self.assertNotIn(KEY, self.output())

    def test_batch_stop_confirms_once_and_skips_paused_without_starting(self):
        one, two = machine(state="suspended"), machine("m_two", "second")
        http = HTTP((200, {"machines": [one, two]}), (200, one), (200, two),
                    (202, operation("succeeded", "stop", "op_second", machineId="m_two")),
                    (200, machine("m_two", "second", "stopped")))
        prompts, answers = [], iter(["1,2", "yes"])
        c = self.client(http, ask=lambda prompt: prompts.append(prompt) or next(answers))
        self.assertEqual(c.batch("stop", wait=0), 0)
        self.assertEqual(len(prompts), 2)
        posts = [call["path"] for call in http.calls if call["method"] == "POST"]
        self.assertEqual(posts, ["/v1/machines/m_two/stop"])
        self.assertIn("停止操作不适用", self.output())
        self.assertIn("当前终端", self.output())
        self.assertIn("放在最后", self.output())
        self.assertIn("结束运行中的进程", self.output())
        self.assertIn("完成 1 台 · 跳过 1 台", self.output())

    def test_batch_checks_fresh_state_before_submitting(self):
        http = HTTP((200, {"machines": [machine(state="stopped")]}), (200, machine()))
        self.assertEqual(self.client(http).batch("start", ["m_testone"]), 0)
        self.assertEqual([call["method"] for call in http.calls], ["GET", "GET"])
        self.assertIn("跳过 1 台", self.output())

    def test_batch_does_not_skip_pending_request_even_if_machine_already_running(self):
        http = HTTP((202, operation()), (200, {"machines": [machine()]}), (200, machine()),
                    (200, operation("queued")))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        self.assertEqual(c.batch("start", ["m_testone"], wait=0), 3)
        self.assertIn("跳过 0 台", self.output())
        self.assertIn("未确认 1 台", self.output())
        self.assertEqual(sum(call["method"] == "POST" for call in http.calls), 1)

    def test_batch_different_unknown_intent_is_unconfirmed_not_skipped_or_overwritten(self):
        http = HTTP(urllib.error.URLError(KEY), (200, {"machines": [machine()]}), (200, machine()))
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.lifecycle("stop", machine(), yes=True)
        before = c.read_record("m_testone")
        self.assertEqual(c.batch("start", ["m_testone"], wait=0), 3)
        self.assertEqual(c.read_record("m_testone"), before)
        self.assertIn("未确认 1 台", self.output())
        self.assertIn("跳过 0 台", self.output())

    def test_batch_invalid_selection_then_empty_cancels_before_any_mutation(self):
        http = HTTP((200, {"machines": [machine(), machine("m_two")]}))
        answers = iter(["1,9", ""])
        c = self.client(http, ask=lambda _: next(answers))
        self.assertEqual(c.batch("start"), 0)
        self.assertEqual(len(http.calls), 1)
        self.assertFalse(c.record_path("m_testone").exists())
        self.assertIn("不会自动选择全部", self.output())

    def test_batch_pause_cancellation_sends_no_mutation(self):
        http = HTTP((200, {"machines": [machine()]}))
        answers = iter(["1", "n"])
        self.assertEqual(self.client(http, ask=lambda _: next(answers)).batch("pause"), 0)
        self.assertEqual(len(http.calls), 1)

    def test_batch_explicit_invalid_target_cannot_partially_execute(self):
        http = HTTP((200, {"machines": [machine()]}))
        with self.assertRaises(cloud.CloudError):
            self.client(http).batch("start", ["m_testone", "m_missing"])
        self.assertEqual(len(http.calls), 1)

    def test_batch_interrupt_preserves_request_and_returns_130_without_next_target(self):
        one, two = machine(state="stopped"), machine("m_two", "second", "stopped")
        http = HTTP((200, {"machines": [one, two]}), (200, one), KeyboardInterrupt())
        c = self.client(http)
        # HTTP's regular Exception check intentionally does not swallow interrupts.
        http.steps[-1] = lambda call: (_ for _ in ()).throw(KeyboardInterrupt())
        with mock.patch.object(cloud, "Cloud", return_value=c), mock.patch.object(cloud, "load_api", return_value=c.api), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cloud.entrypoint(["batch", "start", "m_testone", "m_two"]), 130)
        self.assertEqual(c.read_record("m_testone")["state"], "prepared")
        self.assertFalse(c.record_path("m_two").exists())
        self.assertEqual(len(http.calls), 3)

    def test_protect_on_passes_only_explicit_targets_to_heartbeat(self):
        one, two = machine(), machine("m_two", "second", "suspended")
        http = HTTP((200, {"machines": [one, two]}))
        self.assertEqual(self.client(http, ask=lambda _: "2").protect(True), 0)
        targets, enabled = self.hb.updates[0]
        self.assertTrue(enabled)
        self.assertEqual([row["id"] for row in targets], ["m_two"])
        self.assertEqual(targets[0]["state"], "suspended")
        self.assertEqual(len(http.calls), 1)
        self.assertIn("开启保活不会开机", self.output())

    def test_protect_off_warns_about_bound_ssh_and_keeps_heartbeat_result(self):
        self.hb.data["targets"] = [{"kind": "ssh", "machineId": "m_testone", "status": "healthy"}]
        self.hb.result = 2
        http = HTTP((200, {"machines": [machine()]}))
        answers = iter(["1", "y"])
        self.assertEqual(self.client(http, ask=lambda _: next(answers)).protect(False), 2)
        self.assertFalse(self.hb.updates[0][1])
        self.assertIn("SSH 探测与凭据仍保留", self.output())

    def test_protect_off_cancel_leaves_all_targets_intact(self):
        http = HTTP((200, {"machines": [machine()]}))
        answers = iter(["1", "n"])
        self.assertEqual(self.client(http, ask=lambda _: next(answers)).protect(False), 0)
        self.assertEqual(self.hb.updates, [])

    def test_protect_preserves_safe_local_error_and_hides_credentials(self):
        from heartbeat import HeartbeatError
        self.hb.set_api_targets = mock.Mock(side_effect=HeartbeatError("保活锁忙，请稍后重试 " + KEY, "busy"))
        c = self.client(HTTP((200, {"machines": [machine()]})))
        with self.assertRaises(cloud.CloudError) as caught:
            c.protect(True, ["m_testone"])
        self.assertIn("保活锁忙", str(caught.exception))
        self.assertNotIn(KEY, str(caught.exception))

    def test_pagination_selection_is_read_only_and_clears_stale_status(self):
        one, two = machine(), machine("m_testtwo", "shared", "suspended")
        cloud.atomic_private(self.config / "machine.json", {"sandboxId": one["id"], "name": one["name"]})
        cloud.atomic_private(self.config / "keepalive-state.json", {"result": "confirmed", "sandboxId": one["id"]})
        http = HTTP((200, {"machines": [one], "nextCursor": "next+/="}),
                    (200, {"machines": [one, two], "nextCursor": None}))
        c = self.client(http)
        self.assertEqual(c.select_target("shared")["id"], two["id"])
        self.assertEqual(http.calls[1]["query"], {"cursor": ["next+/="]})
        self.assertTrue(all(x["method"] == "GET" for x in http.calls))
        self.assertFalse((self.config / "keepalive-state.json").exists())
        saved = cloud.read_private(self.config / "machine.json")
        self.assertEqual(saved, {"sandboxId": two["id"], "name": "shared"})
        self.assertEqual(stat.S_IMODE((self.config / "machine.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o700)

    def test_duplicate_names_refuse_and_do_not_default_to_all(self):
        http = HTTP((200, {"machines": [machine(), machine("m_two")], "nextCursor": None}))
        with self.assertRaisesRegex(cloud.CloudError, "唯一"):
            self.client(http).select_target("box")
        self.assertFalse((self.config / "machine.json").exists())

    def test_multiple_org_machines_require_choice_or_saved_target(self):
        machines = [machine(), machine("m_two", "other")]
        prompts = []
        c = self.client(HTTP((200, {"machines": machines})), ask=lambda prompt: prompts.append(prompt) or "2")
        self.assertEqual(c.select_target()["id"], "m_two")
        self.assertEqual(len(prompts), 1)
        self.assertIn("组织其他成员", self.output())
        c = self.client(HTTP((200, {"machines": machines})), ask=lambda _: self.fail("saved target should not prompt"))
        self.assertEqual(c.select_target()["id"], "m_two")

    def test_missing_saved_target_does_not_retarget_the_remaining_machine(self):
        cloud.atomic_private(self.config / "machine.json", {"sandboxId": "m_old", "name": "old"})
        c = self.client(HTTP((200, {"machines": [machine()]})))
        with self.assertRaisesRegex(cloud.CloudError, "重新选择"):
            c.select_target()

    def test_cursor_loop_is_rejected(self):
        c = self.client(HTTP((200, {"machines": [], "nextCursor": "same"}),
                            (200, {"machines": [], "nextCursor": "same"})))
        with self.assertRaisesRegex(cloud.CloudError, "游标异常"):
            c.list_machines()

    def test_info_cli_does_not_wake_or_change_remote_policy(self):
        current = machine(state="suspended", operationId="op_testone")
        http = HTTP((200, {"machines": [current]}), (200, current),
                    (200, operation("running", "suspend", phase="snapshotting")))
        stream = io.StringIO()
        with mock.patch.object(Path, "home", return_value=self.home), \
             mock.patch.dict(os.environ, {"INSTABOX_API_KEY": KEY}, clear=True), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(stream):
            self.assertEqual(cloud.entrypoint(["info"]), 0)
        self.assertEqual([c["method"] for c in http.calls], ["GET", "GET", "GET"])
        self.assertIn("snapshotting", stream.getvalue())
        self.assertIn("已暂停", stream.getvalue())
        self.assertNotIn(KEY, stream.getvalue())

    def test_mutation_saved_before_post_and_202_is_polled_to_success(self):
        saved = []

        def accept(call):
            record = cloud.read_private(self.config / "cloud-requests" / "m_testone.json")
            saved.append(record)
            self.assertEqual(record["state"], "prepared")
            self.assertEqual(call["headers"]["idempotency-key"], record["idempotencyKey"])
            self.assertEqual(call["headers"]["x-api-key"], KEY)
            self.assertIsNone(call["body"])
            self.assertNotIn("vault", call["headers"])
            return 202, operation()

        http = HTTP(accept, (200, operation("running")), (200, operation("succeeded")),
                    (200, machine(runtime={"ready": True, "processesPreserved": False})))
        self.assertEqual(self.client(http).lifecycle("start", machine(state="stopped")), 0)
        self.assertEqual(http.calls[0]["path"], "/v1/machines/m_testone/start")
        self.assertIn("wait", http.calls[1]["query"])
        self.assertLessEqual(http.calls[1]["timeout"], 30)
        self.assertIn("仅表示受理", self.output())
        self.assertIn("冷启动", self.output())
        self.assertNotIn(KEY, json.dumps(saved))
        self.assertEqual(cloud.read_private(self.config / "cloud-requests/m_testone.json")["state"], "succeeded")

    def test_unknown_submission_retries_same_key_and_body(self):
        http = HTTP(urllib.error.URLError("secret=" + KEY), (202, operation()),
                    (200, operation("succeeded")), (200, machine()))
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.lifecycle("start", machine(state="stopped"))
        self.assertEqual(cloud.read_private(c.record_path("m_testone"))["state"], "unknown")
        self.assertEqual(c.lifecycle("start", machine(state="running")), 0)
        self.assertEqual(http.calls[0]["headers"]["idempotency-key"], http.calls[1]["headers"]["idempotency-key"])
        self.assertEqual(http.calls[0]["body"], http.calls[1]["body"])
        self.assertNotIn(KEY, self.output())

    def test_legacy_unknown_request_reuses_original_key_and_body_after_rename(self):
        http = HTTP((202, operation("succeeded", "stop")), (200, machine(state="stopped")))
        c = self.client(http)
        legacy = {"schema": 1, "machineId": "m_testone", "action": "stop",
                  "body": {"timeoutSeconds": 17}, "idempotencyKey": "isb-cloud-" + "a" * 32,
                  "authFingerprint": cloud.hashlib.sha256(KEY.encode("ascii")).hexdigest(),
                  "createdAt": cloud.utc_now(), "state": "unknown", "operationId": None}
        c.save_record(legacy)
        self.assertEqual(c.read_record("m_testone")["idempotencyKey"], legacy["idempotencyKey"])
        self.assertEqual(c.lifecycle("stop", machine(), yes=True, shutdown_timeout=17), 0)
        self.assertEqual(http.calls[0]["headers"]["idempotency-key"], legacy["idempotencyKey"])
        self.assertEqual(http.calls[0]["body"], legacy["body"])
        self.assertEqual(c.read_record("m_testone")["idempotencyKey"], legacy["idempotencyKey"])

    def test_unknown_submission_cannot_be_overwritten_by_a_different_action(self):
        http = HTTP(TimeoutError("contains " + KEY))
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.lifecycle("start", machine(state="stopped"))
        with self.assertRaisesRegex(cloud.CloudError, "未确认"):
            c.lifecycle("stop", machine(), yes=True)
        self.assertEqual(len(http.calls), 1)

    def test_auth_rejection_on_retry_does_not_erase_an_unknown_result(self):
        http = HTTP(TimeoutError(), (401, {"error": {"code": "api_key_expired"}}))
        c = self.client(http)
        for _ in range(2):
            with self.assertRaises(cloud.APIError):
                c.lifecycle("start", machine(state="stopped"))
        self.assertEqual(cloud.read_private(c.record_path("m_testone"))["state"], "unknown")
        with self.assertRaisesRegex(cloud.CloudError, "未确认"):
            c.lifecycle("stop", machine(), yes=True)
        self.assertEqual(len(http.calls), 2)

    def test_corrupt_request_record_is_not_overwritten(self):
        http = HTTP()
        c = self.client(http)
        cloud.atomic_private(c.record_path("m_testone"), {"state": "corrupt", "secret": KEY})
        with self.assertRaisesRegex(cloud.CloudError, "记录损坏"):
            c.lifecycle("start", machine(state="stopped"))
        self.assertEqual(http.calls, [])

    def test_unconfirmed_request_is_not_replayed_after_dedupe_window(self):
        http = HTTP(TimeoutError())
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.lifecycle("start", machine(state="stopped"))
        record = cloud.read_private(c.record_path("m_testone"))
        record["createdAt"] = "2000-01-01T00:00:00+00:00"
        cloud.atomic_private(c.record_path("m_testone"), record)
        with self.assertRaisesRegex(cloud.CloudError, "7 天"):
            c.lifecycle("start", machine(state="stopped"))
        self.assertEqual(len(http.calls), 1)

    def test_successful_new_intent_uses_a_fresh_idempotency_key(self):
        http = HTTP((202, operation("succeeded")), (200, machine()),
                    (202, operation("succeeded", "stop", "op_testtwo")), (200, machine(state="stopped")))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped")), 0)
        self.assertEqual(c.lifecycle("stop", machine(), yes=True, shutdown_timeout=12), 0)
        posts = [x for x in http.calls if x["method"] == "POST"]
        self.assertNotEqual(posts[0]["headers"]["idempotency-key"], posts[1]["headers"]["idempotency-key"])
        for post in posts:
            self.assertRegex(post["headers"]["idempotency-key"], r"^ib-cloud-[a-f0-9]{32}$")
        self.assertEqual(posts[1]["body"], {"timeoutSeconds": 12})

    def test_pending_retry_queries_known_operation_without_post(self):
        http = HTTP((202, operation()), (200, operation("succeeded")), (200, machine()))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        self.assertEqual(c.lifecycle("start", machine(state="starting")), 0)
        self.assertEqual([x["method"] for x in http.calls], ["POST", "GET", "GET"])

    def test_pending_retry_rejects_a_different_operation_id(self):
        http = HTTP((202, operation()), (200, operation("succeeded", op_id="op_other")))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        before = c.read_record("m_testone")
        with self.assertRaises(cloud.APIError):
            c.lifecycle("start", machine(state="starting"))
        self.assertEqual(c.read_record("m_testone"), before)
        self.assertNotIn("已成功完成", self.output())

    def test_explicit_operation_query_rejects_a_different_operation_id(self):
        http = HTTP((200, operation("succeeded", op_id="op_other")))
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.operation("op_testone", wait=0)
        self.assertFalse(c.record_path("m_testone").exists())
        self.assertNotIn("已成功完成", self.output())

    def test_selected_machine_operation_rejects_a_different_machine(self):
        one = machine(operationId="op_testone")
        http = HTTP((200, {"machines": [one]}), (200, one),
                    (200, operation("succeeded", machineId="m_other")))
        c = self.client(http)
        with self.assertRaises(cloud.APIError):
            c.operation(wait=0)
        self.assertFalse(c.record_path("m_testone").exists())
        self.assertFalse(c.record_path("m_other").exists())
        self.assertNotIn("已成功完成", self.output())

    def test_operation_command_queries_and_resolves_saved_pending_request(self):
        def refresh_with_lock(call):
            with self.assertRaisesRegex(cloud.CloudError, "另一个命令"):
                with cloud.request_lock(c.record_path("m_testone").with_suffix(".lock")):
                    self.fail("operation must hold the lifecycle request lock")
            return 200, operation("succeeded")

        http = HTTP((202, operation()), (200, operation("queued")), refresh_with_lock,
                    (200, machine()))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        self.assertEqual(c.operation("op_testone", wait=0), 0)
        self.assertEqual(cloud.read_private(c.record_path("m_testone"))["state"], "succeeded")
        self.assertEqual([x["method"] for x in http.calls], ["POST", "GET", "GET", "GET"])
        self.assertEqual(self.hb.refreshes, [], "Read-only operation queries must not activate protection")

    def test_old_operation_query_cannot_overwrite_a_newer_request(self):
        def response_after_new_request(call):
            newer = c.read_record("m_testone")
            newer.update(operationId="op_testtwo", state="running", action="stop")
            c.save_record(newer)
            return 200, operation("succeeded")

        http = HTTP((202, operation()), response_after_new_request, (200, machine()))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        self.assertEqual(c.operation("op_testone", wait=0), 0)
        record = c.read_record("m_testone")
        self.assertEqual(record["operationId"], "op_testtwo")
        self.assertEqual(record["state"], "running")
        self.assertEqual(record["action"], "stop")

    def test_operation_query_refuses_to_write_while_lifecycle_lock_is_held(self):
        http = HTTP((202, operation()), (200, operation("succeeded")))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=0), 3)
        with cloud.request_lock(c.record_path("m_testone").with_suffix(".lock")):
            with self.assertRaisesRegex(cloud.CloudError, "另一个命令"):
                c.operation("op_testone", wait=0)
        self.assertEqual(c.read_record("m_testone")["state"], "queued")

    def test_operation_success_does_not_claim_a_different_current_state_is_ready(self):
        http = HTTP((202, operation("succeeded")), (200, machine(state="suspended")))
        self.assertEqual(self.client(http).lifecycle("start", machine(state="stopped")), 3)
        self.assertIn("当前状态与该动作的目标不同", self.output())

    def test_failed_operation_never_reports_completion_and_hides_error(self):
        failure = operation("failed", error={"code": "no_capacity", "message": "API KEY " + KEY + " private@example.test"})
        http = HTTP((202, operation()), (200, failure))
        self.assertEqual(self.client(http).lifecycle("start", machine(state="stopped")), 1)
        self.assertIn("no_capacity", self.output())
        self.assertNotIn("已成功完成", self.output())
        self.assertNotIn(KEY, self.output())
        self.assertNotIn("private@example", self.output())

    def test_poll_deadline_preserves_operation_id_for_later_query(self):
        def still_running(call):
            self.clock.advance(2)
            return 200, operation("running")

        http = HTTP((202, operation()), still_running)
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped"), wait=2), 3)
        self.assertEqual(len(http.calls), 2)
        self.assertLessEqual(http.calls[1]["timeout"], 2)
        record = cloud.read_private(c.record_path("m_testone"))
        self.assertEqual(record["operationId"], "op_testone")
        self.assertEqual(record["state"], "running")
        self.assertIn("待确认", self.output())
        self.assertIn("ibt cloud operation op_testone", self.output())

    def test_poll_http_error_keeps_pending_record(self):
        http = HTTP((202, operation()), (403, {"error": {"code": "permission_denied", "message": KEY}}))
        c = self.client(http)
        self.assertEqual(c.lifecycle("start", machine(state="stopped")), 3)
        self.assertEqual(cloud.read_private(c.record_path("m_testone"))["state"], "queued")
        self.assertIn("HTTP 403", self.output())
        self.assertNotIn(KEY, self.output())

    def test_wake_409_never_falls_back_to_resume_or_start(self):
        http = HTTP((409, {"error": {"code": "operation_conflict", "operationId": "op_testone", "message": KEY}}))
        c = self.client(http)
        with self.assertRaisesRegex(cloud.APIError, "op_testone"):
            c.wake(machine(state="suspended"))
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(http.calls[0]["path"], "/v1/machines/m_testone/wake")
        self.assertNotIn("idempotency-key", http.calls[0]["headers"])
        self.assertIsNone(http.calls[0]["body"])
        self.assertEqual(http.calls[0]["timeout"], 60)
        self.assertIn("不会改用", self.output())

    def test_wake_allows_transport_margin_over_platform_45_second_wait(self):
        def wake_near_platform_deadline(call):
            self.assertGreater(call["timeout"], 45)
            self.clock.advance(45)
            return 200, machine()

        http = HTTP(wake_near_platform_deadline)
        self.assertEqual(self.client(http).wake(machine(state="suspended")), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cloud.parser().parse_args(["wake", "--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("45秒", output.getvalue())

    def test_stop_requires_confirmation_and_cancellation_sends_nothing(self):
        prompts = []
        http = HTTP()
        c = self.client(http, ask=lambda prompt: prompts.append(prompt) or "n")
        self.assertEqual(c.lifecycle("stop", machine()), 0)
        self.assertEqual(http.calls, [])
        self.assertIn("m_testone", prompts[0])
        self.assertIn("box", prompts[0])
        self.assertIn("结束运行中的进程", self.output())
        self.assertFalse(c.record_path("m_testone").exists())

    def test_pause_confirmation_uses_suspend_with_no_body(self):
        http = HTTP((202, operation("succeeded", "suspend")), (200, machine(state="suspended")))
        c = self.client(http, ask=lambda _: "yes")
        self.assertEqual(c.lifecycle("pause", machine()), 0)
        self.assertEqual(http.calls[0]["path"], "/v1/machines/m_testone/suspend")
        self.assertIsNone(http.calls[0]["body"])

    def test_resume_uses_optional_body_omission_and_idempotency_header(self):
        http = HTTP((202, operation("succeeded", "resume")), (200, machine()))
        self.assertEqual(self.client(http).lifecycle("resume", machine(state="suspended")), 0)
        self.assertEqual(http.calls[0]["path"], "/v1/machines/m_testone/resume")
        self.assertIsNone(http.calls[0]["body"])
        self.assertIn("idempotency-key", http.calls[0]["headers"])

    def test_stop_paused_and_resume_stopped_do_not_change_state(self):
        c = self.client(HTTP())
        with self.assertRaisesRegex(cloud.CloudError, "不能直接 stop"):
            c.lifecycle("stop", machine(state="suspended"), yes=True)
        with self.assertRaisesRegex(cloud.CloudError, "start"):
            c.lifecycle("resume", machine(state="stopped"))

    def test_noninteractive_stop_requires_yes(self):
        c = self.client(HTTP())
        with mock.patch.object(cloud.sys, "stdin", io.StringIO("y\n")):
            with self.assertRaisesRegex(cloud.CloudError, "--yes"):
                c.lifecycle("stop", machine())
        self.assertEqual(c.api.opener.calls, [])

    def test_account_output_uses_allowlist(self):
        me = {"manualLifecycle": False, "alwaysOnAllowed": False, "fixedAutoSuspendSeconds": 1800,
              "idleChoicesSeconds": [300, 1800], "maxTimeoutSeconds": 14400,
              "name": "PRIVATE NAME", "login": "PRIVATE LOGIN", "email": "private@example.test",
              "csrfToken": KEY, "adminUrl": "https://private.example.test/"}
        usage = {"machines": 2, "snapshots": 1, "storedBytes": 123,
                 "computedAt": "2026-10-20T00:00:00Z", "storage": {"machines": [{"name": "PRIVATE MACHINE"}]},
                 "limits": {"maxMachines": 5, "maxSnapshots": 10, "maxStoredGiB": 200, "token": KEY}}
        http = HTTP((200, me), (200, usage))
        self.client(http).account()
        self.assertEqual([c["path"] for c in http.calls], ["/v1/me", "/v1/usage"])
        self.assertIn("14400", self.output())
        self.assertIn("非机器强制寿命", self.output())
        self.assertIn("自主调整： 否（空闲规则与运行期限）", self.output())
        self.assertNotIn("manualLifecycle", self.output())
        self.assertNotIn("无启停权限", self.output())
        for secret in [KEY, "PRIVATE", "private@example", "private.example", "csrfToken", "adminUrl"]:
            self.assertNotIn(secret, self.output())

    def test_error_statuses_are_distinct_and_do_not_echo_sensitive_payloads(self):
        for status in [401, 403, 409, 429, 503]:
            with self.subTest(status=status):
                http = HTTP((status, {"error": {"code": KEY, "message": KEY + " email@example.test\x1b[31m"}}))
                with self.assertRaises(cloud.APIError) as caught:
                    cloud.API(KEY, http).get("/v1/me")
                message = str(caught.exception)
                self.assertIn(str(status), message)
                self.assertNotIn(KEY, message)
                self.assertNotIn("email@", message)
                self.assertNotIn("\x1b", message)
                if status == 403:
                    self.assertIn("套餐策略", message)

    def test_truncated_http_response_is_reported_without_partial_body(self):
        http_mock = HTTP(http.client.IncompleteRead(KEY.encode("ascii")))
        with self.assertRaises(cloud.APIError) as caught:
            cloud.API(KEY, http_mock).get("/v1/me")
        self.assertNotIn(KEY, str(caught.exception))
        self.assertTrue(caught.exception.uncertain)

    def test_redirects_are_rejected_without_following(self):
        http = HTTP((302, {"error": {"message": KEY}}))
        with self.assertRaisesRegex(cloud.APIError, "重定向"):
            cloud.API(KEY, http).get("/v1/me")
        self.assertEqual(len(http.calls), 1)
        request = urllib.request.Request(cloud.API_ROOT + "/v1/me", headers={"X-API-Key": KEY})
        self.assertIsNone(cloud.NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://untrusted.example/"))

    def test_control_characters_and_tokens_are_sanitized(self):
        c = self.client(HTTP())
        ssh_token = "ibssh_offline_test_not_a_real_token"
        c.show_info(machine(name="safe\x1b[31m\n" + KEY + " " + ssh_token))
        c.show_operation(operation("running", phase="booting\x00\x1b " + KEY + " " + ssh_token))
        self.assertNotIn(KEY, self.output())
        self.assertNotIn(ssh_token, self.output())
        self.assertNotIn("\x00", self.output())
        self.assertNotIn("\x1b", self.output())
        self.assertIn("[已隐藏]", self.output())

    def test_missing_values_are_unknown_not_false_success(self):
        c = self.client(HTTP())
        c.show_info({"id": "m_testone", "name": "box"})
        self.assertIn("未知", self.output())
        self.assertNotIn("已配置", self.output())
        self.assertIn("运行期限： 未知", self.output())

    def test_symlink_files_and_config_dirs_are_refused(self):
        outside = self.home / "outside"
        outside.write_text("do not touch", encoding="utf-8")
        cloud.private_dir(self.config)
        key = self.config / "api-key"
        key.symlink_to(outside)
        with self.assertRaisesRegex(cloud.CloudError, "符号链接"):
            cloud.read_private(key, json_data=False)
        with self.assertRaisesRegex(cloud.CloudError, "符号链接"):
            cloud.atomic_private(key, KEY)
        self.assertEqual(outside.read_text(), "do not touch")
        key.unlink()
        linked = self.home / "linked"
        linked.symlink_to(self.config, target_is_directory=True)
        with self.assertRaisesRegex(cloud.CloudError, "符号链接"):
            cloud.atomic_private(linked / "request.json", {})

    def test_private_config_does_not_block_on_a_fifo(self):
        cloud.private_dir(self.config)
        fifo = self.config / "api-key"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(cloud.CloudError, "普通文件"):
            cloud.read_private(fifo, json_data=False)

    def test_key_prompt_validates_before_private_save(self):
        http = HTTP((200, {"name": "PRIVATE", "csrfToken": KEY}))
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cloud.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(cloud.getpass, "getpass", return_value=KEY), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(io.StringIO()) as captured:
            cloud.load_api(self.config)
        self.assertEqual([c["path"] for c in http.calls], ["/v1/me"])
        self.assertEqual(cloud.read_private(self.config / "api-key", json_data=False), KEY)
        self.assertEqual(stat.S_IMODE((self.config / "api-key").stat().st_mode), 0o600)
        self.assertNotIn(KEY, captured.getvalue())
        self.assertNotIn("PRIVATE", captured.getvalue())

    def test_rejected_key_is_not_saved(self):
        http = HTTP((401, {"error": {"message": KEY}}))
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cloud.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(cloud.getpass, "getpass", return_value=KEY), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(cloud.APIError):
                cloud.load_api(self.config)
        self.assertFalse((self.config / "api-key").exists())

    def test_shared_cached_key_is_reused_without_prompt_or_validation_request(self):
        cloud.atomic_private(self.config / "api-key", KEY + "\n")
        http = HTTP()
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cloud.getpass, "getpass", side_effect=AssertionError("must reuse shared cache")), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http):
            self.assertEqual(cloud.load_api(self.config).key, KEY)
        self.assertEqual(http.calls, [])

    def test_key_set_uses_python_validation_before_private_replacement(self):
        old = "ibk_offline_old_key"
        cloud.atomic_private(self.config / "api-key", old)
        http = HTTP((200, {"email": "private@example.test", "csrfToken": KEY}))
        with mock.patch.object(Path, "home", return_value=self.home), \
             mock.patch.object(cloud, "load_api", side_effect=AssertionError("key command must dispatch first")), \
             mock.patch.object(cloud.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(cloud.getpass, "getpass", return_value=KEY), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cloud.main(["key", "set"]), 0)
        self.assertEqual([call["path"] for call in http.calls], ["/v1/me"])
        self.assertEqual(cloud.read_private(self.config / "api-key", json_data=False), KEY)
        self.assertEqual(stat.S_IMODE((self.config / "api-key").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o700)
        self.assertIn("一次输入", output.getvalue())
        self.assertIn("共用", output.getvalue())
        self.assertNotIn(KEY, output.getvalue())
        self.assertNotIn("private@example", output.getvalue())

    def test_key_set_rejection_preserves_previous_shared_key(self):
        old = "ibk_offline_old_key"
        cloud.atomic_private(self.config / "api-key", old)
        http = HTTP((401, {"error": {"message": KEY}}))
        with mock.patch.object(Path, "home", return_value=self.home), \
             mock.patch.object(cloud, "load_api", side_effect=AssertionError("key command must dispatch first")), \
             mock.patch.object(cloud.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(cloud.getpass, "getpass", return_value=KEY), \
             mock.patch.object(cloud.urllib.request, "build_opener", return_value=http), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(cloud.entrypoint(["key", "set"]), 1)
        self.assertEqual(cloud.read_private(self.config / "api-key", json_data=False), old)
        self.assertNotIn(KEY, error.getvalue())
        self.assertNotIn(old, error.getvalue())

    def test_key_status_and_forget_are_offline_and_do_not_read_secret_content(self):
        cloud.atomic_private(self.config / "api-key", KEY)
        with mock.patch.object(Path, "home", return_value=self.home), \
             mock.patch.object(cloud, "read_private", side_effect=AssertionError("metadata only")), \
             mock.patch.object(cloud, "load_api", side_effect=AssertionError("must be offline")), \
             mock.patch.object(cloud, "API", side_effect=AssertionError("must be offline")), \
             mock.patch.object(cloud.getpass, "getpass", side_effect=AssertionError("must not prompt")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cloud.main(["key", "status"]), 0)
            self.assertEqual(cloud.main(["key", "forget"]), 0)
            self.assertEqual(cloud.main(["key", "status"]), 0)
        self.assertFalse((self.config / "api-key").exists())
        self.assertIn("已保存在本机", output.getvalue())
        self.assertIn("尚未保存在本机", output.getvalue())
        self.assertIn("云端授权未撤销", output.getvalue())
        self.assertNotIn(KEY, output.getvalue())

    def test_key_status_and_forget_refuse_unsafe_permissions(self):
        path = self.config / "api-key"
        cloud.atomic_private(path, KEY)
        path.chmod(0o644)
        for action in ["status", "forget"]:
            with self.subTest(action=action), self.assertRaisesRegex(cloud.CloudError, "600"):
                cloud.manage_key(self.config, action)
            self.assertTrue(path.exists())

    def test_key_forget_refuses_symlinks_without_removing_target(self):
        cloud.private_dir(self.config)
        original = self.home / "original"
        original.write_text("synthetic preserved data")
        (self.config / "api-key").symlink_to(original)
        with self.assertRaisesRegex(cloud.CloudError, "符号链接"):
            cloud.manage_key(self.config, "forget")
        self.assertEqual(original.read_text(), "synthetic preserved data")

    def test_key_status_missing_cache_does_not_create_files_or_prompt(self):
        with mock.patch.object(Path, "home", return_value=self.home), \
             mock.patch.object(cloud, "load_api", side_effect=AssertionError("must be offline")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cloud.main(["key"]), 0)
        self.assertFalse(self.config.exists())

    def test_key_set_refuses_getpass_echo_fallback_and_preserves_old_key(self):
        cloud.atomic_private(self.config / "api-key", KEY)
        with mock.patch.object(cloud.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(cloud.getpass, "getpass", side_effect=cloud.getpass.GetPassWarning("echo unavailable")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(cloud.CloudError, "回显"):
                cloud.manage_key(self.config, "set")
        self.assertEqual(cloud.read_private(self.config / "api-key", json_data=False), KEY)

    def test_bad_cli_arguments_do_not_echo_values(self):
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            with self.assertRaises(SystemExit):
                cloud.parser().parse_args(["stop", "--shutdown-timeout", KEY])
        self.assertNotIn(KEY, captured.getvalue())


if __name__ == "__main__":
    unittest.main()
