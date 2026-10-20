"""Offline migration/rollback regressions; no cloud or real systemd operations."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import migrate as migration


REF = "a" * 40
TOKEN = "ibssh_FAKE_MIGRATION_TOKEN"
KEY = "ibk_FAKE_MIGRATION_KEY"


def private_file(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Newly created nested fixture directories must satisfy the production checks.
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    path.chmod(mode)


class Systemd:
    def __init__(self, home):
        self.home = home
        self.directory = home / ".config/systemd/user"
        self.states = {}
        self.calls = []
        self.failures = {}
        self.identity_overrides = {}
        self.on_start = None

    def state(self, name):
        if name not in self.states:
            path = self.directory / name
            enabled = "static" if path.exists() and "[Install]" not in path.read_text() else "disabled"
            self.states[name] = {"active": False, "enabled": enabled}
        return self.states[name]

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[0] == "bash":
            return subprocess.CompletedProcess(args, 0, "0.0.1\n", "")
        assert args[:2] == ["systemctl", "--user"], args
        action = args[2]
        if action == "daemon-reload":
            return subprocess.CompletedProcess(args, 0, "", "")
        name = args[3]
        path = self.directory / name
        state = self.state(name)
        code, output = 0, ""
        if self.failures.get((action, name), 0):
            self.failures[(action, name)] -= 1
            return subprocess.CompletedProcess(args, 1, "", "mock failure " + KEY)
        if action == "show":
            fields = self.identity_overrides.get(name, {
                "LoadState": "loaded" if path.exists() else "not-found",
                "FragmentPath": str(path) if path.exists() else "", "DropInPaths": "",
            })
            output = "\n".join(key + "=" + value for key, value in fields.items()) + "\n"
        elif action == "is-active":
            code, output = (0, "active\n") if state["active"] else (3, "inactive\n")
        elif action == "is-enabled":
            # Actual systemd may emit an empty stdout, with the error in stderr.
            if not path.exists():
                code, output = 1, ""
            else:
                if "[Install]" not in path.read_text() and state["enabled"] in ("disabled", "static"):
                    state["enabled"] = "static"
                output = state["enabled"] + "\n"
                code = 0 if state["enabled"] in ("enabled", "static") else 1
        elif action == "stop":
            state["active"] = False
        elif action == "disable":
            state["enabled"] = "disabled"
        elif action == "enable":
            state["enabled"] = "enabled"
        elif action == "start":
            state["active"] = True
            if self.on_start:
                code = self.on_start(name) or 0
            if path.exists() and "Type=oneshot" in path.read_text().splitlines():
                state["active"] = False
        else:
            raise AssertionError("Unexpected local command")
        return subprocess.CompletedProcess(args, code, output, "")


class AbruptExit(BaseException):
    pass


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ib-migration-", dir=ROOT.parent)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o700)
        for name in migration.FILES:
            content = "#!/usr/bin/env bash\n# Managed-by: InstaBox Tool CLI\nprintf '%s\\n' '0.0.1'\n" if name == "ibt.sh" else "fixture " + name + "\n"
            private_file(self.bundle / name, content, 0o700)
        self.rehash_bundle()
        self.systemd = Systemd(self.home)
        self.lines = []
        self.installer = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        self.original = {}
        self.original_states = {}

    def tearDown(self):
        self.temporary.cleanup()

    def rehash_bundle(self):
        lines = [hashlib.sha256((self.bundle / name).read_bytes()).hexdigest() + "  " + name for name in migration.FILES]
        private_file(self.bundle / "SHA256SUMS", "\n".join(lines) + "\n")

    def legacy(self, *, cli_symlink=True, heartbeat_active=False):
        app, cfg = self.home / migration.OLD_APP, self.home / migration.OLD_CFG
        app.mkdir(parents=True, mode=0o700)
        cfg.mkdir(parents=True, mode=0o700)
        private_file(app / "state.conf", "uuid=unchanged-uuid\ndomain=fixture.example\npath=/ws-existing\nport=20000\n")
        private_file(app / "config.json", '{"uuid":"unchanged-uuid","listen_port":20000}\n')
        private_file(app / "bin/start-quick-tunnel", migration.OLD_QUICK, 0o700)
        private_file(app / "user-note.txt", "leave this user file unchanged\n")
        private_file(cfg / "api-key", KEY + "\n")
        heartbeat = {"schema": 1, "controllerId": "b" * 32, "intervalSeconds": 300,
                     "targets": [{"id": "api_one", "kind": "api", "machineId": "m_one", "label": "One", "revision": "c" * 32}]}
        private_file(cfg / "heartbeat.json", json.dumps(heartbeat))
        private_file(cfg / "heartbeat-state.json", '{"schema":1,"checkedAt":"unchanged","targets":[]}\n')
        private_file(cfg / "heartbeat_known_hosts", "dummy gateway host key\n")
        private_file(cfg / "cloud-requests/m_one.json", json.dumps({"idempotencyKey": "isb-cloud-" + "d" * 32,
                     "state": "unknown", "body": {"token": TOKEN}}))
        private_file(self.home / ".config/cloudflared/token", "existing cloudflare token\n")
        release = app / "tool-releases/legacy-cache"
        private_file(release / "isb.sh", "#!/usr/bin/env bash\n# Managed-by: Insta-Sing-box CLI\nprintf '%s\\n' '2.3.0'\n", 0o700)
        if cli_symlink:
            (app / "cli").symlink_to(release, target_is_directory=True)
        else:
            (app / "cli").mkdir(mode=0o700)
            shutil.copy2(release / "isb.sh", app / "cli/isb.sh")
        private_file(self.home / ".local/bin/isb", '#!/usr/bin/env bash\n# Managed-by: Insta-Sing-box CLI\nexec bash "$HOME/.local/share/insta-sing-box/cli/isb.sh" "$@"\n', 0o700)
        private_file(self.home / ".bashrc", b"# user settings\n" + migration.OLD_PATH_LINE + b"\n", 0o644)
        matrix = [(True, "disabled"), (False, "enabled"), (True, "enabled"),
                  (heartbeat_active, "static"), (True, "enabled")]
        for (old, new), (active, enabled) in zip(migration.UNIT_MAP.items(), matrix):
            heartbeat_unit = "heartbeat" in old
            marker = migration.OLD_MARKER + (" Heartbeat" if heartbeat_unit else "")
            if old.endswith(".timer"):
                unit = marker + "\n[Timer]\nOnStartupSec=30s\nUnit=insta-singbox-heartbeat.service\n[Install]\nWantedBy=timers.target\n"
            else:
                unit = marker + "\n[Service]\nType=" + ("oneshot" if heartbeat_unit else "simple") + "\nExecStart=%h/" + migration.OLD_APP + "/bin/example\n"
                if enabled != "static":
                    unit += "[Install]\nWantedBy=default.target\n"
            private_file(self.systemd.directory / old, unit)
            self.systemd.states[old] = {"active": active, "enabled": enabled}
        self.original_states = {name: dict(state) for name, state in self.systemd.states.items()}
        self.original = {str(path.relative_to(self.home)): path.read_bytes() for path in self.home.rglob("*") if path.is_file() and not path.is_symlink()}
        self.old_cli_link = os.readlink(app / "cli") if cli_symlink else None
        return heartbeat

    def assert_original_restored(self):
        for relative, contents in self.original.items():
            self.assertEqual((self.home / relative).read_bytes(), contents, relative)
        self.assertFalse((self.home / migration.NEW_APP).exists())
        self.assertFalse((self.home / migration.NEW_CFG).exists())
        if self.old_cli_link:
            self.assertEqual(os.readlink(self.home / migration.OLD_APP / "cli"), self.old_cli_link)
        for name, state in self.original_states.items():
            self.assertEqual(self.systemd.state(name), state, name)

    def test_migration_preserves_private_state_identity_and_each_service_bit(self):
        original_heartbeat = self.legacy()
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assertFalse((self.home / migration.OLD_APP).exists())
        self.assertFalse((self.home / migration.OLD_CFG).exists())
        for relative, contents in self.original.items():
            if relative.startswith(migration.OLD_APP + "/") and relative not in (migration.OLD_APP + "/bin/start-quick-tunnel",):
                self.assertEqual((self.home / relative.replace(migration.OLD_APP, migration.NEW_APP, 1)).read_bytes(), contents)
            if relative.startswith(migration.OLD_CFG + "/") and relative != migration.OLD_CFG + "/heartbeat.json":
                self.assertEqual((self.home / relative.replace(migration.OLD_CFG, migration.NEW_CFG, 1)).read_bytes(), contents)
        self.assertEqual(json.loads((self.home / migration.NEW_CFG / "heartbeat.json").read_bytes()), {**original_heartbeat, "leasePrefix": "isb"})
        self.assertEqual((self.home / migration.NEW_APP / "bin/start-quick-tunnel").read_bytes(), migration.QUICK)
        for old, new in migration.UNIT_MAP.items():
            self.assertFalse((self.systemd.directory / old).exists())
            unit = (self.systemd.directory / new).read_text()
            self.assertIn(migration.NEW_MARKER, unit)
            self.assertNotIn(migration.OLD_APP, unit)
            self.assertEqual(self.systemd.state(new), self.original_states[old])
        mutations = [call for call in self.systemd.calls if len(call) > 2 and call[2] in ("stop", "disable", "start", "enable")]
        self.assertEqual(mutations[0][2:], ["stop", "insta-singbox-heartbeat.timer"])
        self.assertNotIn(["systemctl", "--user", "start", "insta-box-tunnel.service"], mutations)
        self.assertNotIn(["systemctl", "--user", "enable", "insta-box-node.service"], mutations)
        self.assertTrue((self.home / migration.NEW_APP / "cli").is_symlink())
        self.assertFalse(self.installer.work.exists())
        self.assertEqual((self.home / ".bashrc").read_bytes().count(migration.NEW_PATH_LINE), 1)
        self.assertNotIn(migration.OLD_PATH_LINE, (self.home / ".bashrc").read_bytes())
        self.assertIn(migration.BRIDGE_MARKER, (self.home / ".local/bin/isb").read_text())
        bridge = subprocess.run(["bash", str(self.home / ".local/bin/isb"), "--version"], env={**os.environ, "HOME": str(self.home)}, capture_output=True, text=True)
        self.assertEqual(bridge.returncode, 0, bridge.stderr)
        self.assertEqual(bridge.stdout.strip(), "0.0.1")
        self.assertFalse((self.home / ".local/bin/isb").exists())
        self.assertNotIn(TOKEN, "\n".join(self.lines))
        self.assertNotIn(KEY, "\n".join(self.lines))

    def test_legacy_directory_cli_is_retained_as_a_local_backup(self):
        self.legacy(cli_symlink=False)
        self.installer.install(self.bundle, REF)
        backups = list((self.home / migration.NEW_APP).glob("cli-before-3.0-*"))
        self.assertEqual(len(backups), 1)
        self.assertIn("2.3.0", (backups[0] / "isb.sh").read_text())

    def test_fresh_install_leaves_unrelated_legacy_commands_untouched(self):
        paths = [self.home / ".local/bin" / name for name in ("isb", "ib")]
        for path in paths:
            private_file(path, "#!/bin/sh\nprintf 'another tool'\n", 0o700)
        before = {path: path.read_bytes() for path in paths}
        self.installer.install(self.bundle, REF)
        for path in paths:
            self.assertEqual(path.read_bytes(), before[path])
        self.assertFalse(any(call[0] == "systemctl" for call in self.systemd.calls))

    def test_v3_rename_preserves_data_and_both_unit_markers_without_systemd_actions(self):
        app, cfg = self.home / migration.NEW_APP, self.home / migration.NEW_CFG
        app.mkdir(parents=True, mode=0o700)
        cfg.mkdir(parents=True, mode=0o700)
        private_file(app / "state.conf", "uuid=existing-v3-node\ndomain=fixture.example\n")
        private_file(app / "config.json", '{"uuid":"existing-v3-node"}\n')
        private_file(cfg / "api-key", KEY + "\n")
        private_file(cfg / "heartbeat.json", json.dumps({"schema": 1, "leasePrefix": "ib", "controllerId": "b" * 32,
                     "intervalSeconds": 300, "targets": [{"id": "ssh_one", "revision": "c" * 32,
                     "ssh": {"user": TOKEN}, "rotation": {"intent": {"status": "ambiguous", "body": {"name": "ib-rotate-preserved"}}}}]}))
        private_file(cfg / "cloud-requests/m_one.json", '{"idempotencyKey":"ib-cloud-preserved","state":"unknown"}\n')
        private_file(cfg / "heartbeat_known_hosts", "known gateway key\n")
        release = app / "tool-releases/previous-v3"
        private_file(release / "ib.sh", "#!/bin/sh\n# Managed-by: Insta Box CLI\nprintf '3.0.0\\n'\n", 0o700)
        (app / "cli").symlink_to(release, target_is_directory=True)
        private_file(self.home / ".local/bin/ib", '#!/bin/sh\n# Managed-by: Insta Box CLI\nexec "$HOME/.local/share/insta-box/cli/ib.sh" "$@"\n', 0o700)
        private_file(self.home / ".local/bin/isb", '#!/bin/sh\n# Managed-by: Insta Box migration bridge\nexec "$HOME/.local/bin/ib" "$@"\n', 0o700)
        private_file(self.home / ".bashrc", migration.V3_PATH_LINE + b"\n", 0o644)
        for index, name in enumerate(migration.UNIT_MAP.values()):
            marker = (migration.V3_MARKER if index % 2 == 0 else migration.NEW_MARKER) + (" Heartbeat" if "heartbeat" in name else "")
            private_file(self.systemd.directory / name, marker + "\n[Service]\nType=simple\n[Install]\nWantedBy=default.target\n")
            self.systemd.states[name] = {"active": index % 2 == 0, "enabled": "enabled" if index % 3 else "disabled"}
        preserved = {path: path.read_bytes() for root in (cfg, self.systemd.directory) for path in root.rglob("*") if path.is_file()}
        preserved.update({app / name: (app / name).read_bytes() for name in ("state.conf", "config.json")})
        states = {name: dict(value) for name, value in self.systemd.states.items()}
        inodes = (app.stat().st_ino, cfg.stat().st_ino)
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        for path, original in preserved.items():
            self.assertEqual(path.read_bytes(), original, str(path.relative_to(self.home)))
        self.assertEqual((app.stat().st_ino, cfg.stat().st_ino), inodes)
        self.assertEqual(self.systemd.states, states)
        self.assertFalse(any(call[0] == "systemctl" for call in self.systemd.calls))
        self.assertEqual((self.home / ".bashrc").read_bytes(), migration.NEW_PATH_LINE + b"\n")
        self.assertIn(migration.NEW_MARKER + " CLI", (self.home / ".local/bin/ibt").read_text())
        for name in ("ib", "isb"):
            bridge = self.home / ".local/bin" / name
            self.assertIn(migration.BRIDGE_MARKER, bridge.read_text())
            result = subprocess.run(["bash", str(bridge), "--version"], env={**os.environ, "HOME": str(self.home)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "0.0.1")
            self.assertFalse(bridge.exists())

    def test_rollback_accepts_previous_v3_unit_markers(self):
        self.legacy()
        def crash(name):
            if name == "restored:insta-box-heartbeat.timer":
                for unit in migration.UNIT_MAP.values():
                    path = self.systemd.directory / unit
                    path.write_text(path.read_text().replace(migration.NEW_MARKER, migration.V3_MARKER))
                raise AbruptExit()
        self.installer.checkpoint = crash
        with self.assertRaises(AbruptExit):
            self.installer.install(self.bundle, REF)
        # A journal from v3.0 records the previous unit marker in fingerprints.
        journal = json.loads(self.installer.journal_path.read_bytes())
        for entry in journal["ops"]:
            path = self.home / entry.get("path", "")
            if entry["kind"] == "replace" and path.parent == self.systemd.directory and path.name in migration.UNIT_MAP.values():
                entry["after"] = migration.fingerprint(path)
        private_file(self.installer.journal_path, json.dumps(journal))
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with retry.installation_lock():
            try:
                retry.recover()
            finally:
                retry.release_locks()
        self.assert_original_restored()
        self.assertFalse(retry.work.exists())

    def test_known_legacy_runtime_files_are_repaired_without_changing_data_or_service_state(self):
        self.legacy()
        self.installer.install(self.bundle, REF)
        app, cfg = self.home / migration.NEW_APP, self.home / migration.NEW_CFG
        launcher = app / "bin/start-quick-tunnel"
        private_file(launcher, migration.V3_QUICK, 0o700)
        log = app / "quick.log"
        private_file(log, "existing tunnel address and log contents\n", 0o664)
        cache = (app / "cli").resolve() / "__pycache__"
        private_file(cache / "heartbeat.cpython-313.pyc", "old generated cache", 0o664)
        cache.chmod(0o775)
        preserved = {path: (path.read_bytes(), path.stat().st_ino) for path in (log, app / "state.conf", app / "config.json", cfg / "api-key", cfg / "heartbeat.json", cfg / "cloud-requests/m_one.json")}
        units = {path: path.read_bytes() for path in self.systemd.directory.iterdir()}
        self.systemd.calls.clear()
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        for path, (content, inode) in preserved.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertFalse(cache.exists())
        self.assertEqual(launcher.read_bytes(), migration.QUICK)
        for path, contents in units.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertFalse(any(call[0] == "systemctl" for call in self.systemd.calls))

    def test_303_launcher_upgrades_without_restarting_or_replacing_live_node_state(self):
        self.legacy()
        self.installer.install(self.bundle, REF)
        app = self.home / migration.NEW_APP
        launcher = app / "bin/start-quick-tunnel"
        private_file(launcher, migration.PREVIOUS_QUICK, 0o700)
        private_file(app / "quick.log", "https://existing-fixture.trycloudflare.com\n")
        private_file(app / "quick-protocol", "http2\n")
        files = [app / name for name in ("quick.log", "quick-protocol", "state.conf", "config.json")]
        before = {path: (path.read_bytes(), path.stat().st_ino) for path in files}
        self.systemd.calls.clear()
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assertEqual(launcher.read_bytes(), migration.QUICK)
        for path, previous in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino), previous)
        self.assertFalse(any(call[0] == "systemctl" for call in self.systemd.calls))

    def test_legacy_log_repair_requires_a_known_launcher_unit_and_independent_file(self):
        self.legacy()
        app = self.home / migration.OLD_APP
        log = app / "quick.log"
        launcher = app / "bin/start-quick-tunnel"
        unit = self.systemd.directory / "insta-singbox-quick.service"
        outside = self.home / "unrelated-log"
        private_file(outside, "must remain unchanged", 0o664)
        original_unit = unit.read_bytes()
        for kind in ("symlink", "hardlink", "custom_launcher", "foreign_unit"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    log.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, log)
                else:
                    private_file(log, "legacy contents", 0o664)
                    if kind == "custom_launcher":
                        private_file(launcher, "#!/bin/sh\necho custom\n", 0o700)
                    else:
                        private_file(unit, "# Another application\n")
                with self.assertRaises(migration.MigrationError):
                    self.installer.preflight(self.bundle, REF)
                self.assertEqual(outside.read_text(), "must remain unchanged")
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o664)
                if not log.is_symlink():
                    self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o664)
                log.unlink()
                private_file(launcher, migration.OLD_QUICK, 0o700)
                private_file(unit, original_unit)
        self.assertFalse(any(call[0] == "systemctl" and call[2] in ("stop", "start") for call in self.systemd.calls))

    def test_python_cache_cleanup_refuses_unknown_linked_or_foreign_items(self):
        self.installer.install(self.bundle, REF)
        release = (self.home / migration.NEW_APP / "cli").resolve()
        cache = release / "__pycache__"
        outside = self.home / "personal-file"
        private_file(outside, "personal contents", 0o664)
        for kind in ("unknown", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                cache.mkdir(mode=0o775)
                cache.chmod(0o775)
                path = cache / ("notes.txt" if kind == "unknown" else "heartbeat.cpython-313.pyc")
                if kind == "symlink":
                    path.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, path)
                else:
                    private_file(path, "user notes", 0o664)
                with self.assertRaises(migration.MigrationError):
                    self.installer.preflight(self.bundle, REF)
                self.assertTrue(os.path.lexists(path))
                self.assertEqual(outside.read_text(), "personal contents")
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o664)
                path.unlink()
                cache.rmdir()
        actual = outside.stat()
        changed = list(actual)
        changed[4] = os.getuid() + 1
        with mock.patch.object(migration.os, "fstat", return_value=os.stat_result(changed)):
            with self.assertRaises(migration.MigrationError):
                migration.Installer.runtime_file(outside)

    @staticmethod
    def sdk_tree(app, *, writable=True, management_mode=0o700):
        """Reproduce an old npm tree, including ordinary internal bin links."""
        app.mkdir(mode=0o700, parents=True, exist_ok=True)
        sdk = app / "management"
        modules = sdk / "node_modules"
        mode = 0o664 if writable else 0o644
        private_file(modules / "@insforge/instabox-sdk/package.json",
                     json.dumps({"name": "@insforge/instabox-sdk", "version": "0.5.3-beta.1+fixture"}), mode)
        private_file(modules / "@insforge/instabox-sdk/dist/index.js", "// existing SDK; never execute\n", mode)
        private_file(modules / "@insforge/instabox-sdk/dist/private-data.json", '{"keep":"all bytes"}\n', 0o600)
        private_file(modules / "fixture-tool/bin/cli.js", "#!/usr/bin/env node\n// never execute\n", 0o775 if writable else 0o755)
        private_file(modules / ".package-lock.json", '{"name":"existing-lock","lockfileVersion":3}\n', mode)
        (modules / ".bin").mkdir(mode=0o700)
        (modules / ".bin/fixture-cli").symlink_to("../fixture-tool/bin/cli.js")
        private_file(sdk / "platform.mjs", "// existing platform helper; keep this file\n", 0o700)
        for path in (modules, *modules.rglob("*")):
            if stat.S_ISDIR(path.lstat().st_mode):
                path.chmod(0o775 if writable else 0o755)
        sdk.chmod(management_mode)
        return sdk

    @staticmethod
    def tree_snapshot(root):
        records = {}
        for path in (root, *sorted(root.rglob("*"))):
            info = path.lstat()
            payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
            records[str(path.relative_to(root))] = (stat.S_IFMT(info.st_mode), info.st_dev, info.st_ino,
                                                   info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode), payload)
        return records

    def assert_sdk_preserved(self, sdk, before):
        after = self.tree_snapshot(sdk)
        self.assertEqual(set(after), set(before))
        for relative, original in before.items():
            actual = after[relative]
            self.assertEqual(actual[:5], original[:5], relative)
            self.assertEqual(actual[6], original[6], relative)
            expected_mode = 0o700 if relative == "." else original[5]
            if relative.startswith("node_modules") and original[0] != stat.S_IFLNK:
                expected_mode &= ~0o022
            self.assertEqual(actual[5], expected_mode, relative)

    def test_v2_sdk_permissions_migrate_without_replacing_dependency_node_or_api_data(self):
        self.legacy()
        app, cfg = self.home / migration.OLD_APP, self.home / migration.OLD_CFG
        sdk = self.sdk_tree(app, management_mode=0o775)
        dependencies = self.tree_snapshot(sdk)
        protected = {str(path.relative_to(self.home)): (path.read_bytes(), path.stat().st_ino)
                     for path in (app / "state.conf", app / "config.json", cfg / "api-key",
                                  cfg / "cloud-requests/m_one.json", cfg / "heartbeat_known_hosts")}
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assert_sdk_preserved(self.home / migration.NEW_APP / "management", dependencies)
        for relative, original in protected.items():
            moved = relative.replace(migration.OLD_APP, migration.NEW_APP, 1).replace(migration.OLD_CFG, migration.NEW_CFG, 1)
            path = self.home / moved
            self.assertEqual((path.read_bytes(), path.stat().st_ino), original, moved)
        for old, new in migration.UNIT_MAP.items():
            self.assertEqual(self.systemd.state(new), self.original_states[old])
        self.assertTrue(all(call[0] in ("bash", "systemctl") for call in self.systemd.calls))
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.assertNotIn(TOKEN, "\n".join(self.lines))

    def test_v3_sdk_repair_and_reentry_preserve_services_and_dependencies(self):
        self.legacy()
        self.installer.install(self.bundle, REF)
        app = self.home / migration.NEW_APP
        sdk = self.sdk_tree(app, management_mode=0o775)
        before = self.tree_snapshot(sdk)
        states = {name: dict(value) for name, value in self.systemd.states.items()}
        units = {path: (path.read_bytes(), path.stat().st_ino) for path in self.systemd.directory.iterdir()}
        self.systemd.calls.clear()
        for _ in range(2):
            self.assertEqual(self.installer.install(self.bundle, REF), 0)
            self.assert_sdk_preserved(sdk, before)
            self.assertEqual(self.systemd.states, states)
            for path, original in units.items():
                self.assertEqual((path.read_bytes(), path.stat().st_ino), original)
        self.assertFalse(any(call[0] == "systemctl" and call[2] in
                             ("stop", "disable", "start", "enable", "restart", "daemon-reload")
                             for call in self.systemd.calls))

    def test_earliest_sdk_without_cli_or_platform_helper_uses_owned_service_provenance(self):
        self.legacy()
        app = self.home / migration.OLD_APP
        (app / "cli").unlink()
        shutil.rmtree(app / "tool-releases")
        (self.home / ".local/bin/isb").unlink()
        unit = self.systemd.directory / "insta-sing-box.service"
        private_file(unit, unit.read_text().replace("/bin/example", "/bin/sing-box run -c %h/" + migration.OLD_APP + "/config.json"))
        sdk = self.sdk_tree(app, management_mode=0o775)
        (sdk / "platform.mjs").unlink()
        before = self.tree_snapshot(sdk)
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assert_sdk_preserved(self.home / migration.NEW_APP / "management", before)
        self.assertTrue(any(call[:3] == ["systemctl", "--user", "show"] and call[3] in migration.UNIT_MAP
                            for call in self.systemd.calls))
        for old, new in migration.UNIT_MAP.items():
            self.assertEqual(self.systemd.state(new), self.original_states[old])

    def test_sdk_repair_rejects_untrusted_tree_before_any_permission_or_service_change(self):
        cases = ("external_link", "dangling_link", "hardlink", "foreign_owner", "wrong_package", "bad_version",
                 "unmanaged", "unit_escape", "unit_custom")
        for kind in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="sdk-reject-", dir=self.root) as raw:
                home = Path(raw)
                home.chmod(0o700)
                app = home / migration.OLD_APP
                sdk = self.sdk_tree(app, management_mode=0o775)
                modules = sdk / "node_modules"
                wrapper = home / ".local/bin/isb"
                private_file(wrapper, "#!/bin/sh\n# Managed-by: Insta-Sing-box CLI\nexit 0\n", 0o700)
                outside = home / "personal-file"
                private_file(outside, "personal file must not change\n", 0o664)
                package = modules / "@insforge/instabox-sdk/package.json"
                if kind == "external_link":
                    (modules / "zz-hostile").symlink_to(outside)
                elif kind == "dangling_link":
                    (modules / "zz-hostile").symlink_to("missing-target")
                elif kind == "hardlink":
                    os.link(outside, modules / "zz-hostile")
                elif kind in ("wrong_package", "bad_version"):
                    private_file(package, json.dumps({"name": "unrelated-package" if kind == "wrong_package" else "@insforge/instabox-sdk",
                                                      "version": "0.5.3" if kind == "wrong_package" else "not-a-version"}), 0o664)
                elif kind in ("unmanaged", "unit_escape", "unit_custom"):
                    private_file(wrapper, "#!/bin/sh\n# Another application\nexit 0\n", 0o700)
                    if kind.startswith("unit_"):
                        binary = "../../unrelated" if kind == "unit_escape" else "custom-helper"
                        private_file(home / ".config/systemd/user/insta-sing-box.service",
                                     migration.OLD_MARKER + "\n[Service]\nExecStart=%h/" + migration.OLD_APP + "/bin/" + binary +
                                     "\n[Install]\nWantedBy=default.target\n")
                systemd = Systemd(home)
                systemd.states["insta-sing-box.service"] = {"active": True, "enabled": "enabled"}
                installer = migration.Installer(home, runner=systemd, output=self.lines.append)
                before = self.tree_snapshot(home)
                states = {name: dict(value) for name, value in systemd.states.items()}
                actual_fstat = os.fstat
                foreign = (modules / "@insforge/instabox-sdk/dist/index.js").stat()
                def pretend_foreign(fd):
                    info = actual_fstat(fd)
                    if (info.st_dev, info.st_ino) == (foreign.st_dev, foreign.st_ino):
                        values = list(info)
                        values[4] = os.getuid() + 1
                        return os.stat_result(values)
                    return info
                owner_check = mock.patch.object(migration.os, "fstat", side_effect=pretend_foreign) if kind == "foreign_owner" else contextlib.nullcontext()
                with owner_check, mock.patch.object(migration.os, "fchmod", wraps=os.fchmod) as changes:
                    with self.assertRaises(migration.MigrationError):
                        installer.repair_sdk_permissions(app)
                    self.assertEqual(changes.call_count, 0)
                self.assertEqual(self.tree_snapshot(home), before)
                self.assertEqual(systemd.states, states)
                self.assertFalse(any(call[0] == "systemctl" and call[2] in
                                     ("stop", "disable", "start", "enable", "restart") for call in systemd.calls))

    def test_secure_sdk_with_no_package_metadata_or_provenance_keeps_existing_preflight_behavior(self):
        app = self.home / migration.OLD_APP
        sdk = self.sdk_tree(app, writable=False, management_mode=0o755)
        app.chmod(0o755)
        (sdk / "node_modules/@insforge/instabox-sdk/package.json").unlink()
        (sdk / "platform.mjs").unlink()
        before = self.tree_snapshot(app)
        self.installer.repair_sdk_permissions(app)
        plan = self.installer.preflight(self.bundle, REF)
        self.assertTrue(plan["oldApp"])
        self.assertEqual(self.tree_snapshot(app), before)
        self.assertFalse(any(call[0] == "systemctl" and call[2] in
                             ("stop", "disable", "start", "enable", "restart") for call in self.systemd.calls))

    def test_permission_diagnostic_identifies_path_and_mode_without_exposing_tokens(self):
        app = self.home / migration.NEW_APP
        path = app / (TOKEN + ".txt")
        private_file(path, "not printed", 0o664)
        with self.assertRaises(migration.MigrationError) as raised:
            self.installer.preflight(self.bundle, REF)
        message = str(raised.exception)
        self.assertIn("0664", message)
        self.assertIn("insta-box", message)
        self.assertIn("[已隐藏]", message)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("not printed", message)

    def test_path_is_added_to_bashrc_and_the_first_login_file(self):
        names = (".bash_profile", ".bash_login", ".profile")
        for present in (names, names[1:], names[2:], ()):
            with self.subTest(present=present):
                for name in names:
                    path = self.home / name
                    if path.exists():
                        path.unlink()
                for name in present:
                    private_file(self.home / name, "# personal login settings\n")
                self.installer.install(self.bundle, REF)
                chosen = present[0] if present else ".profile"
                self.assertEqual((self.home / chosen).read_bytes().splitlines().count(migration.NEW_PATH_LINE), 1)
                self.assertEqual((self.home / ".bashrc").read_bytes().splitlines().count(migration.NEW_PATH_LINE), 1)
                for name in present[1:]:
                    self.assertEqual((self.home / name).read_text(), "# personal login settings\n")

    def test_login_file_update_is_recovered_from_the_existing_journal(self):
        self.legacy()
        login = self.home / ".bash_login"
        private_file(login, "# original login file\n")
        def crash(name):
            if name == "replace:.bash_login":
                raise AbruptExit()
        self.installer.checkpoint = crash
        with self.assertRaises(AbruptExit):
            self.installer.install(self.bundle, REF)
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with retry.installation_lock():
            try:
                retry.recover()
            finally:
                retry.release_locks()
        self.assert_original_restored()
        self.assertEqual(login.read_text(), "# original login file\n")

    def test_conflicting_new_data_or_entry_is_rejected_before_stopping_services(self):
        self.legacy()
        cases = [(self.home / migration.NEW_CFG, True), (self.home / ".local/bin/ibt", False),
                 (self.systemd.directory / "insta-box-node.service", False)]
        for path, directory in cases:
            with self.subTest(path=path.name):
                path.mkdir(mode=0o700) if directory else private_file(path, "# unrelated application\n")
                self.systemd.calls.clear()
                with self.assertRaises(migration.MigrationError):
                    self.installer.install(self.bundle, REF)
                self.assertTrue(path.exists())
                self.assertFalse(any(call[0] == "systemctl" and call[2] in ("stop", "disable", "start", "enable") for call in self.systemd.calls))
                path.rmdir() if directory else path.unlink()

    def test_global_unit_collision_and_external_dropins_are_refused(self):
        self.legacy()
        cases = [
            ("insta-box-node.service", {"LoadState": "loaded", "FragmentPath": "/usr/lib/systemd/user/insta-box-node.service", "DropInPaths": ""}),
            ("insta-sing-box.service", {"LoadState": "loaded", "FragmentPath": str(self.systemd.directory / "insta-sing-box.service"), "DropInPaths": "/etc/systemd/user/custom.conf"}),
        ]
        for name, identity in cases:
            self.systemd.identity_overrides = {name: identity}
            self.systemd.calls.clear()
            with self.assertRaises(migration.MigrationError):
                self.installer.install(self.bundle, REF)
            self.assertFalse(any(call[2] in ("stop", "disable") for call in self.systemd.calls if call[0] == "systemctl"))
        self.systemd.identity_overrides = {}
        (self.systemd.directory / "insta-sing-box.service.d").mkdir(mode=0o700)
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)

    def test_external_links_unsafe_private_permissions_and_bad_bundle_are_refused(self):
        self.legacy()
        key = self.home / migration.OLD_CFG / "api-key"
        key.chmod(0o644)
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        key.chmod(0o600)
        outside = self.home / "outside"
        outside.mkdir(mode=0o700)
        link = self.home / migration.OLD_APP / "outside-link"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        link.unlink()
        private_file(self.bundle / "cloud.py", "bad bundle")
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        self.assert_original_restored()

    def test_failure_after_cli_switch_rolls_back_absolute_symlink_and_all_states(self):
        self.legacy()
        def fail(name):
            if name == "replace:" + migration.NEW_APP + "/cli":
                raise migration.MigrationError("injected failure")
        self.installer.checkpoint = fail
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        self.assert_original_restored()
        self.assertFalse(self.installer.work.exists())

    def test_failed_old_unit_restore_can_be_recovered_by_the_next_install(self):
        self.legacy()
        self.systemd.failures[("start", "insta-box-node.service")] = 1
        self.systemd.failures[("start", "insta-sing-box.service")] = 1
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        journal = json.loads(self.installer.journal_path.read_bytes())
        self.assertEqual(journal["ops"], [], "Each completed undo must be durably removed")
        self.assertTrue((self.home / migration.OLD_CFG / "api-key").exists())
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        self.assertEqual(retry.install(self.bundle, REF), 0)
        self.assertFalse(retry.work.exists())
        self.assertEqual((self.home / migration.NEW_CFG / "api-key").read_text(), KEY + "\n")

    def test_interrupted_directory_move_is_recovered_before_retry(self):
        self.legacy()
        def crash(name):
            if name == "move:" + migration.OLD_CFG:
                raise AbruptExit()
        self.installer.checkpoint = crash
        with self.assertRaises(AbruptExit):
            self.installer.install(self.bundle, REF)
        self.assertTrue(self.installer.journal_path.exists())
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        self.assertEqual(retry.install(self.bundle, REF), 0)
        self.assertEqual((self.home / migration.NEW_CFG / "api-key").read_text(), KEY + "\n")

    def test_unstopped_timer_prevents_any_data_move_and_handles_missing_new_units(self):
        self.legacy()
        self.systemd.failures[("stop", "insta-singbox-heartbeat.timer")] = 1
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        self.assert_original_restored()
        self.assertFalse(self.installer.work.exists())

    def test_live_heartbeat_lock_blocks_migration_without_stopping_services(self):
        self.legacy()
        import heartbeat
        old = self.home / migration.OLD_CFG
        path = old / "heartbeat.lock"
        private_file(path, "")
        fd = os.open(path, os.O_RDWR)
        try:
            heartbeat.fcntl.flock(fd, heartbeat.fcntl.LOCK_EX | heartbeat.fcntl.LOCK_NB)
            with self.assertRaises(migration.MigrationError):
                self.installer.install(self.bundle, REF)
        finally:
            os.close(fd)
        self.assertFalse(any(call[0] == "systemctl" and call[2] in ("stop", "disable") for call in self.systemd.calls))

    def test_restored_oneshot_runs_real_manager_after_lock_release_and_may_finish_inactive(self):
        self.legacy(heartbeat_active=True)
        import heartbeat
        class API:
            def request(_self, method, route, key, body=None):
                self.assertEqual(method, "PUT")
                self.assertEqual(key, KEY)
                return {"id": route.rsplit("/", 1)[-1], "machineId": "m_one", "expiresAt": heartbeat.iso_time(1800000900)}
        runs = []
        def started(name):
            if name == "insta-box-heartbeat.service":
                manager = heartbeat.Manager(home=self.home, client=API(), clock=lambda: 1800000000,
                                            output=self.lines.append, env={"IB_NO_SUDO": "1"})
                result = manager.run_once()
                runs.append(result)
                return result
            return 0
        self.systemd.on_start = started
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assertEqual(runs, [0], "The new heartbeat must acquire the relocated lock")
        self.assertFalse(self.systemd.state("insta-box-heartbeat.service")["active"])
        self.assertTrue(self.systemd.state("insta-box-heartbeat.timer")["active"])

    def test_rollback_preserves_new_non_idempotent_rotation_intent(self):
        self.legacy(heartbeat_active=True)
        import heartbeat
        path = self.home / migration.OLD_CFG / "heartbeat.json"
        config = json.loads(path.read_bytes())
        config["targets"] = [{"id": "ssh_one", "kind": "ssh", "label": "SSH one", "revision": "c" * 32,
                              "ssh": {"user": TOKEN, "host": "api.instabox.sh", "port": 2222, "family": None},
                              "tokenExpiry": {"kind": "unknown"}, "rotation": {"enabled": True, "machineId": "m_one"}}]
        private_file(path, json.dumps(config))
        def rotate(current, target, api, probe, save, now=None):
            updated = {**target, "rotation": {**target["rotation"], "intent": {"status": "ambiguous", "body": {"name": "ib-rotate-new-intent"}}}}
            save(updated)
            target.clear()
            target.update(updated)
            return {"status": "ambiguous", "message": "签发结果待确认"}
        def started(name):
            if name == "insta-box-heartbeat.service":
                manager = heartbeat.Manager(home=self.home, clock=lambda: 1800000000, output=self.lines.append,
                                            runner=lambda args, **kw: subprocess.CompletedProcess(args, 0, heartbeat.SSH_MARKER + "\n", ""),
                                            rotation_hook=rotate, env={"IB_NO_SUDO": "1"})
                return manager.run_once()
            return 0
        self.systemd.on_start = started
        with self.assertRaises(migration.MigrationError):
            self.installer.install(self.bundle, REF)
        restored = json.loads(path.read_bytes())
        self.assertEqual(restored["controllerId"], config["controllerId"])
        self.assertEqual(restored["targets"][0]["rotation"]["intent"]["body"]["name"], "ib-rotate-new-intent")
        self.assertEqual(restored["targets"][0]["ssh"]["user"], TOKEN)
        self.assertFalse((self.home / migration.NEW_CFG).exists())

    def test_committed_cleanup_failure_does_not_roll_back_working_install(self):
        self.legacy()
        with mock.patch.object(self.installer, "cleanup_work", side_effect=OSError("fixture cleanup failure")):
            self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assertTrue((self.home / migration.NEW_APP / "cli/ibt.sh").exists())
        self.assertFalse((self.home / migration.OLD_APP).exists())
        self.assertEqual(json.loads(self.installer.journal_path.read_bytes())["phase"], "committed")
        self.assertFalse((self.installer.work / "busy").exists())
        self.systemd.calls.clear()
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with retry.installation_lock():
            retry.recover()
        self.assertFalse(retry.work.exists())
        self.assertFalse(self.systemd.calls, "Committed cleanup must not stop working units")

    def test_commit_save_failure_before_replace_rolls_back_without_false_success(self):
        self.legacy()
        save = self.installer.save_journal
        failed = False
        def interrupted_save():
            nonlocal failed
            if self.installer.journal["phase"] == "committed" and not failed:
                failed = True
                raise OSError("commit not written")
            save()
        self.installer.save_journal = interrupted_save
        with self.assertRaises(OSError):
            self.installer.install(self.bundle, REF)
        self.assert_original_restored()
        self.assertFalse(self.installer.work.exists())
        self.assertFalse(any("安装已完成" in line for line in self.lines))

    def test_commit_save_error_after_replace_keeps_the_recorded_install(self):
        self.legacy()
        save = self.installer.save_journal
        def interrupted_save():
            save()
            if self.installer.journal["phase"] == "committed":
                raise OSError("commit written before error")
        self.installer.save_journal = interrupted_save
        self.assertEqual(self.installer.install(self.bundle, REF), 0)
        self.assertTrue((self.home / migration.NEW_APP / "cli/ibt.sh").exists())
        self.assertFalse((self.home / migration.OLD_APP).exists())
        self.assertEqual(json.loads(self.installer.journal_path.read_bytes())["phase"], "committed")
        self.assertFalse((self.installer.work / "busy").exists())
        self.systemd.calls.clear()
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with retry.installation_lock():
            retry.recover()
        self.assertFalse(retry.work.exists())
        self.assertFalse(self.systemd.calls)

    def test_unreadable_commit_decision_preserves_the_scene_and_reports_failure(self):
        self.legacy()
        save = self.installer.save_journal
        def interrupted_save():
            if self.installer.journal["phase"] == "committed":
                private_file(self.installer.journal_path, "unreadable commit record")
                raise OSError("commit outcome unavailable")
            save()
        self.installer.save_journal = interrupted_save
        with self.assertRaisesRegex(migration.MigrationError, "提交状态未确认"):
            self.installer.install(self.bundle, REF)
        self.assertTrue((self.home / migration.NEW_APP / "cli/ibt.sh").exists())
        self.assertFalse((self.home / migration.OLD_APP).exists())
        self.assertTrue((self.installer.work / "busy").exists())
        self.assertFalse(any("安装已完成" in line for line in self.lines))

    def test_out_of_scope_recovery_journal_cannot_remove_personal_files(self):
        private_file(self.home / ".ssh/personal", "not installer data")
        self.installer.ensure_parent(self.installer.work)
        for entry in ({"kind": "tree", "path": ".ssh"},
                      {"kind": "move", "source": ".ssh", "destination": migration.NEW_APP},
                      {"kind": "mkdir", "path": ".ssh"}):
            private_file(self.installer.journal_path, json.dumps({"schema": 1, "phase": "prepared", "units": [], "ops": [entry]}))
            with self.assertRaises(migration.MigrationError):
                self.installer.install(self.bundle, REF)
            self.assertEqual((self.home / ".ssh/personal").read_text(), "not installer data")
            self.assertFalse(self.systemd.calls)

    def test_corrupt_rollback_backup_never_overwrites_current_file(self):
        self.legacy()
        def crash(name):
            if name == "replace:.local/bin/isb":
                raise AbruptExit()
        self.installer.checkpoint = crash
        with self.assertRaises(AbruptExit):
            self.installer.install(self.bundle, REF)
        journal = json.loads(self.installer.journal_path.read_bytes())
        backup = self.installer.work / journal["ops"][0]["backup"]
        private_file(backup, "damaged backup")
        before = (self.home / ".local/bin/isb").read_bytes()
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with self.assertRaises(migration.MigrationError):
            retry.install(self.bundle, REF)
        self.assertEqual((self.home / ".local/bin/isb").read_bytes(), before)
        self.assertTrue(retry.journal_path.exists())

    def test_fresh_install_orphaned_atomic_files_and_links_are_recoverable(self):
        for target in (migration.NEW_APP + "/cli", ".local/bin/ibt"):
            with self.subTest(target=target):
                installer = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
                operation = installer.operation
                def interrupted(entry):
                    result = operation(entry)
                    if entry.get("kind") == "replace" and entry["path"] == target:
                        temporary = self.home / entry["temporary"]
                        if entry["after"]["kind"] == "symlink":
                            temporary.symlink_to(entry["after"]["target"])
                        else:
                            private_file(temporary, "partial new wrapper")
                        raise AbruptExit()
                    return result
                installer.operation = interrupted
                with self.assertRaises(AbruptExit):
                    installer.install(self.bundle, REF)
                retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
                with retry.installation_lock():
                    retry.recover()
                self.assertFalse((self.home / migration.NEW_APP).exists())
                self.assertFalse((self.home / ".local/bin").exists())
                self.assertFalse(retry.work.exists())
                self.assertFalse(list(self.home.rglob(".ib-link-*")))
                self.assertFalse(list(self.home.rglob(".ib-write-*")))

    def test_recovery_refuses_a_replaced_configuration_parent_symlink(self):
        self.legacy()
        def crash(name):
            if name == "move:" + migration.OLD_CFG:
                raise AbruptExit()
        self.installer.checkpoint = crash
        with self.assertRaises(AbruptExit):
            self.installer.install(self.bundle, REF)
        cfg = self.home / migration.NEW_CFG
        cfg.rename(self.home / "preserved-private-config")
        outside = self.home / "unrelated"
        outside.mkdir(mode=0o700)
        private_file(outside / "personal", "unchanged")
        cfg.symlink_to(outside, target_is_directory=True)
        self.systemd.calls.clear()
        retry = migration.Installer(self.home, runner=self.systemd, output=self.lines.append)
        with self.assertRaises(migration.MigrationError):
            retry.install(self.bundle, REF)
        self.assertEqual((outside / "personal").read_text(), "unchanged")
        self.assertFalse((outside / "heartbeat.lock").exists())
        self.assertFalse(self.systemd.calls)


if __name__ == "__main__":
    unittest.main()
