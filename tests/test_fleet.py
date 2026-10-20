"""Cross-module fleet workflows using real managers and offline transports."""

import copy
import unittest

from test_heartbeat import Fixture, KEY, ssh_target
import cloud


class FleetAPI:
    key = KEY

    def __init__(self, client):
        self.client = client

    def get(self, path):
        return self.client.request("GET", path, self.key)


class FleetIntegrationTests(Fixture):
    def fleet(self):
        machines = [
            {"id": "m_" + name, "name": name, "state": "running" if index == 0 else "suspended"}
            for index, name in enumerate(["insta", "instwo", "insthree", "insfour", "insfive"])
        ]
        self.client.pages = {"/v1/machines": {"machines": machines}}
        for machine in machines:
            self.client.pages["/v1/machines/" + machine["id"]] = machine
        return machines, cloud.Cloud(FleetAPI(self.client), self.manager.cfg,
                                     say=self.lines.append, heartbeat_manager=self.manager)

    def test_five_machine_api_workflow_preserves_independent_ssh_and_resumes_after_web_start(self):
        machines, fleet = self.fleet()
        existing_ssh = ssh_target()
        self.configure([existing_ssh])
        self.add_key()
        # 2 means the configuration is saved but a target still needs attention
        # (here: it is intentionally waiting for the user to start it).
        self.assertEqual(fleet.protect(True, ["insta", "instwo"]), 2)
        configured = self.manager.load_config()
        self.assertEqual(len(configured["targets"]), 3)
        self.assertEqual(configured["leasePrefix"], "ib")
        self.assertIn(existing_ssh, configured["targets"])
        self.assertTrue(self.runner.active and self.runner.enabled)
        self.assertFalse(any(method == "PUT" and "/m_instwo/" in path
                             for method, path, _, _ in self.client.calls))

        before_config = self.manager.config_file.read_bytes()
        before_state = self.manager.state_file.read_bytes()
        self.client.calls.clear()
        self.lines.clear()
        self.assertEqual(fleet.overview(), 0)
        self.assertEqual([(call[0], call[1]) for call in self.client.calls], [("GET", "/v1/machines")])
        self.assertEqual(self.manager.config_file.read_bytes(), before_config)
        self.assertEqual(self.manager.state_file.read_bytes(), before_state)
        self.assertTrue(any("共 5 台" in line and "运行 1 台" in line for line in self.lines))
        self.assertTrue(any("instwo" in line and "暂停待启动" in line for line in self.lines))
        self.assertTrue(any("insfive" in line and "未配置" in line for line in self.lines))
        self.assertTrue(any("SSH" in line and "未明确绑定" in line for line in self.lines))

        # A user starts the waiting VM in the web console. No cloud start command
        # is issued here: the next background round must discover the change.
        machines[1]["state"] = "running"
        self.client.calls.clear()
        self.assertEqual(self.manager.run_once(), 0)
        self.assertTrue(any(method == "GET" and path == "/v1/machines/m_instwo"
                            for method, path, _, _ in self.client.calls))
        self.assertTrue(any(method == "PUT" and "/m_instwo/" in path
                            for method, path, _, _ in self.client.calls))
        self.assertFalse(any(method == "POST" for method, _, _, _ in self.client.calls))
        self.lines.clear()
        fleet.overview()
        self.assertTrue(any("instwo" in line and "最近保活正常" in line for line in self.lines))

        self.client.calls.clear()
        self.assertEqual(fleet.protect(False, ["insta"], yes=True), 0)
        remaining = self.manager.load_config()["targets"]
        self.assertIn(existing_ssh, remaining)
        self.assertEqual([target["machineId"] for target in remaining if target["kind"] == "api"], ["m_instwo"])
        deletions = [path for method, path, _, _ in self.client.calls if method == "DELETE"]
        self.assertEqual(len(deletions), 1)
        self.assertIn("/m_insta/activity-leases/ib-" + configured["controllerId"] + "-", deletions[0])
        self.assertTrue(self.runner.active and self.runner.enabled)
        self.assertEqual(self.manager.key_file.read_text().strip(), KEY)

    def test_real_summary_never_turns_stale_or_disabled_success_into_healthy_dashboard(self):
        _, fleet = self.fleet()
        self.add_key()
        self.assertEqual(fleet.protect(True, ["insta"]), 0)
        self.lines.clear()
        fleet.overview()
        self.assertTrue(any("insta" in line and "最近保活正常" in line for line in self.lines))
        original_config = copy.deepcopy(self.manager.load_config())
        self.now += 3600
        self.lines.clear()
        fleet.overview()
        self.assertFalse(any("最近保活正常" in line for line in self.lines))
        self.assertTrue(any("insta" in line and "记录已过期" in line for line in self.lines))
        self.runner.active = self.runner.enabled = False
        self.lines.clear()
        fleet.overview()
        self.assertTrue(any("insta" in line and "已停用" in line for line in self.lines))
        self.assertEqual(self.manager.load_config(), original_config)


if __name__ == "__main__":
    unittest.main()
