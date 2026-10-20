"""Offline non-root bootstrap, legacy migration, and first-install authorization."""
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ROOT_FIXTURE = os.geteuid() == 0
# A demoted process cannot traverse a root-only workspace. Copy the complete
# verified runtime bundle without relaxing workspace ownership.
TEMP_PARENT = "/tmp" if ROOT_FIXTURE and Path("/tmp").is_dir() else None
TMP = Path(tempfile.mkdtemp(prefix="ibt-bootstrap-", dir=TEMP_PARENT))


def private_file(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(mode)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def legacy_sdk(app, source):
    """An npm install made under umask 0002, with a private managed parent."""
    # Even the original node installer made the application root private.
    app.chmod(0o700)
    management = app / "management"
    management.mkdir(mode=0o700)
    shutil.copy2(source / "platform.mjs", management / "platform.mjs")
    (management / "platform.mjs").chmod(0o700)
    modules = management / "node_modules"
    sdk = modules / "@insforge/instabox-sdk"
    private_file(sdk / "package.json", json_bytes({
        "name": "@insforge/instabox-sdk", "version": "0.2.0", "type": "module",
        "main": "dist/index.js", "bin": {"instabox-sdk-fixture": "bin/fixture.js"},
    }), 0o664)
    private_file(sdk / "dist/index.js", "export const fixture = 'preserve installed SDK';\n", 0o664)
    private_file(sdk / "bin/fixture.js", "#!/usr/bin/env node\nprocess.exit(97); // Never execute this fixture.\n", 0o775)
    private_file(modules / ".package-lock.json", json_bytes({
        "name": "management", "lockfileVersion": 3, "requires": True,
        "packages": {"node_modules/@insforge/instabox-sdk": {
            "version": "0.2.0", "resolved": "https://registry.npmjs.org/@insforge/instabox-sdk/-/instabox-sdk-0.2.0.tgz",
            "bin": {"instabox-sdk-fixture": "bin/fixture.js"},
        }},
    }), 0o664)
    (modules / ".bin").mkdir()
    (modules / ".bin/instabox-sdk-fixture").symlink_to("../@insforge/instabox-sdk/bin/fixture.js")
    for path in (modules, *modules.rglob("*")):
        if not path.is_symlink() and path.is_dir():
            path.chmod(0o775)
    snapshot = {}
    for path in (management, *management.rglob("*")):
        info = path.lstat()
        kind = "link" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file"
        value = os.readlink(path) if kind == "link" else path.read_bytes() if kind == "file" else None
        snapshot[str(path.relative_to(app))] = (kind, info.st_ino, stat.S_IMODE(info.st_mode), value)
    return snapshot


def preserved_sdk(app, snapshot):
    management = app / "management"
    current = {str(path.relative_to(app)) for path in (management, *management.rglob("*"))}
    assert current == set(snapshot), "SDK cache entries were removed or replaced"
    for name, (kind, inode, mode, value) in snapshot.items():
        path = app / name
        info = path.lstat()
        assert info.st_ino == inode, "SDK inode changed: " + name
        if kind == "link":
            assert stat.S_ISLNK(info.st_mode), "SDK internal link was replaced: " + name
            assert os.readlink(path) == value, "SDK internal link target changed: " + name
            assert path.resolve().is_relative_to(management / "node_modules"), "SDK link escaped its cache"
            assert path.is_file(), "SDK internal executable link became broken"
            assert stat.S_IMODE(info.st_mode) == mode, "SDK symlink permissions were changed"
        else:
            assert stat.S_ISDIR(info.st_mode) if kind == "directory" else stat.S_ISREG(info.st_mode), "SDK entry type changed: " + name
            assert stat.S_IMODE(info.st_mode) == mode & ~0o022, "SDK permissions were not narrowly repaired: " + name
            if kind == "file":
                assert path.read_bytes() == value, "SDK bytes changed: " + name


try:
    fixture_home, mock_bin, source = TMP / "home", TMP / "bin", TMP / "source"
    runtime_tmp, api_hook = TMP / "tmp", TMP / "api-hook"
    for directory in (fixture_home, mock_bin, source, runtime_tmp, api_hook):
        directory.mkdir(mode=0o700)
    # Only the transport is mocked: the downloaded cloud.py still parses,
    # validates, and persists authorization itself. Every non-fixture request
    # fails closed, including unexpected requests during an existing upgrade.
    private_file(api_hook / "sitecustomize.py", '''import io
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

class Response(io.BytesIO):
    def __init__(self, status, value):
        super().__init__(json.dumps(value).encode())
        self.status = status

class OfflineAPI:
    def open(self, request, timeout=None):
        if os.environ.get("API_FIXTURE_MODE") != "authorize":
            raise AssertionError("An existing upgrade unexpectedly requested API authorization")
        url = urllib.parse.urlsplit(request.full_url)
        if (url.scheme, url.netloc) != ("https", "api.instabox.sh") or url.query or url.fragment:
            raise AssertionError("Unexpected offline API URL")
        if request.get_method() != "GET" or url.path not in ("/v1/me", "/v1/machines") or request.data is not None:
            raise AssertionError("Authorization must use only read-only account/list requests")
        with (Path.home() / "api-actions").open("a") as log:
            log.write(request.get_method() + " " + url.path + "\\n")
        headers = {name.lower(): value for name, value in request.header_items()}
        if headers.get("x-api-key") != "ibk_FAKE_FRESH_BOOTSTRAP_KEY":
            body = {"error": {"code": "unauthorized", "message": headers.get("x-api-key", "")}}
            raise urllib.error.HTTPError(request.full_url, 401, "fixture", {}, Response(401, body))
        if url.path == "/v1/me":
            return Response(200, {"inviteRequired": False, "activated": True})
        return Response(200, {"machines": [{"id": "m_fresh", "name": "instabox-fresh", "state": "running"}]})

urllib.request.build_opener = lambda *handlers: OfflineAPI()
''')
    match = re.search(r"^FILES=\(([^\n)]*)\)$", (ROOT / "setup.sh").read_text(), re.M)
    assert match, "setup runtime file list is missing"
    runtime_files = shlex.split(match.group(1))
    assert len(runtime_files) == len(set(runtime_files)) == 15
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in (".", "..") for name in runtime_files)
    for name in (*runtime_files, "SHA256SUMS"):
        shutil.copy2(ROOT / name, source / name)

    old_app = fixture_home / ".local/share/insta-sing-box"
    old_cfg = fixture_home / ".config/insta-sing-box"
    app = fixture_home / ".local/share/insta-box"
    cfg = fixture_home / ".config/insta-box"
    local_bin = fixture_home / ".local/bin"
    old_release = old_app / "tool-releases" / ("b" * 40)
    private_file(old_release / "isb.sh", "#!/usr/bin/env bash\n# Managed-by: Insta-Sing-box CLI\nprintf '%s\\n' '2.3.0'\n", 0o700)
    (old_app / "cli").symlink_to(old_release, target_is_directory=True)
    private_file(local_bin / "isb", '''#!/usr/bin/env bash
# Managed-by: Insta-Sing-box CLI
exec bash "$HOME/.local/share/insta-sing-box/cli/isb.sh" "$@"
''', 0o700)
    shell_prefix = b"# Existing user settings\nexport EDITOR=vi\n"
    old_path = b'export PATH="$HOME/.local/bin:$PATH" # Insta-Sing-box CLI\n'
    v3_path = b'export PATH="$HOME/.local/bin:$PATH" # Insta Box CLI\n'
    new_path = b'export PATH="$HOME/.local/bin:$PATH" # InstaBox Tool CLI\n'
    private_file(fixture_home / ".bashrc", shell_prefix + old_path)

    key = "ibk_FAKE_BOOTSTRAP_KEY"
    ssh = {"user": "ibssh_FAKE_BOOTSTRAP_OLD", "host": "api.instabox.sh", "port": 2222, "family": None}
    rotation = {"enabled": True, "armed": False, "machineId": "m_one", "ttlSeconds": 86400,
                "renewBeforeSeconds": 3600, "activeExpiresAt": "2026-11-01T00:00:00Z",
                "activeTokenId": "cn_old", "activeFingerprint": hashlib.sha256(ssh["user"].encode()).hexdigest()}
    heartbeat = {"schema": 1, "controllerId": "a" * 32, "intervalSeconds": 300, "targets": [
        {"id": "api_one", "kind": "api", "label": "已选机器", "revision": "b" * 32, "machineId": "m_one"},
        {"id": "ssh_pending", "kind": "ssh", "label": "待验收凭据", "revision": "c" * 32,
         "ssh": ssh, "tokenExpiry": {"kind": "verified", "expiresAt": rotation["activeExpiresAt"]},
         "rotation": {**rotation, "pending": {"id": "cn_pending", "machineId": "m_one",
             "ssh": {**ssh, "user": "ibssh_FAKE_BOOTSTRAP_PENDING"}, "expiresAt": "2026-11-02T00:00:00Z"}}},
        {"id": "ssh_unknown", "kind": "ssh", "label": "结果未知请求", "revision": "d" * 32,
         "ssh": ssh, "tokenExpiry": {"kind": "verified", "expiresAt": rotation["activeExpiresAt"]},
         "rotation": {**rotation, "machineId": "m_two", "intent": {"state": "ambiguous",
             "localId": "e" * 32, "attempts": 1, "requestedAt": "2026-10-20T00:00:00Z",
             "body": {"name": "isb-rotate-legacy-pending", "ttlSeconds": 86400}}}},
    ]}
    cloud_request = {"schema": 1, "machineId": "m_one", "action": "start", "body": None,
                     "idempotencyKey": "isb-cloud-" + "f" * 32,
                     "authFingerprint": hashlib.sha256(key.encode()).hexdigest(),
                     "createdAt": "2026-10-20T00:00:00Z", "state": "unknown", "operationId": None}
    node_files = {"state.conf": b"mode=fixed\ndomain=proxy.example.test\nuuid=11111111-1111-4111-8111-111111111111\npath=/ws-111111111111111111111111111111111111\nport=20000\n",
                  "config.json": b'{"inbounds":[{"type":"vless","users":[{"uuid":"11111111-1111-4111-8111-111111111111"}]}]}\n'}
    config_files = {
        "api-key": (key + "\n").encode(),
        "display-timezone": b"Asia/Shanghai\n",
        "machine.json": b'{"sandboxId":"m_one","name":"original selection"}\n',
        "heartbeat-state.json": b'{"schema":1,"controllerId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","checkedAt":"2026-10-20T00:00:00Z","targets":[]}\n',
        "heartbeat_known_hosts": b"api.instabox.sh ssh-ed25519 AAAA_FAKE_BOOTSTRAP_HOST_KEY\n",
        "cloud-requests/m_one.json": json_bytes(cloud_request),
    }
    for name, value in node_files.items():
        private_file(old_app / name, value)
    for name, value in config_files.items():
        private_file(old_cfg / name, value)
    private_file(old_cfg / "heartbeat.json", json_bytes(heartbeat))
    old_cfg.chmod(0o700)
    old_sdk = legacy_sdk(old_app, source)
    old_node_inodes = {name: (old_app / name).stat().st_ino for name in node_files}
    old_config_inodes = {name: (old_cfg / name).stat().st_ino for name in config_files}

    # Version 3.0 already uses the current data paths and remote identities.
    # Give it a separate HOME so this exercises an actual old ib installation,
    # independently of the v2 migration below.
    v3_home = TMP / "v3-home"
    v3_home.mkdir(mode=0o700)
    v3_app = v3_home / ".local/share/insta-box"
    v3_cfg = v3_home / ".config/insta-box"
    v3_bin = v3_home / ".local/bin"
    v3_release = v3_app / "tool-releases" / ("c" * 40)
    private_file(v3_release / "ib.sh", "#!/usr/bin/env bash\n# Managed-by: Insta Box CLI\nprintf '%s\\n' '3.0.0'\n", 0o700)
    (v3_app / "cli").symlink_to(v3_release, target_is_directory=True)
    private_file(v3_bin / "ib", '''#!/usr/bin/env bash
# Managed-by: Insta Box CLI
exec bash "$HOME/.local/share/insta-box/cli/ib.sh" "$@"
''', 0o700)
    private_file(v3_home / ".bashrc", shell_prefix + v3_path)
    v3_heartbeat = json.loads(json_bytes(heartbeat))
    v3_heartbeat["leasePrefix"] = "ib"
    v3_heartbeat["targets"][2]["rotation"]["intent"]["body"]["name"] = "ib-rotate-existing-pending"
    v3_config_files = {**config_files,
        "heartbeat.json": json_bytes(v3_heartbeat),
        "cloud-requests/m_one.json": json_bytes({**cloud_request, "idempotencyKey": "ib-cloud-" + "f" * 32}),
    }
    for name, value in node_files.items():
        private_file(v3_app / name, value)
    for name, value in v3_config_files.items():
        private_file(v3_cfg / name, value)
    v3_sdk = legacy_sdk(v3_app, source)
    v3_roots = {path: path.stat().st_ino for path in (v3_app, v3_cfg)}
    v3_original_files = {
        **{v3_app / name: value for name, value in node_files.items()},
        **{v3_cfg / name: value for name, value in v3_config_files.items()},
    }
    v3_inodes = {path: path.stat().st_ino for path in v3_original_files}

    # A legacy SSH-only controller is a valid existing installation. It must
    # migrate without an API Key and without converting its SSH target to API.
    ssh_home = TMP / "ssh-home"
    ssh_home.mkdir(mode=0o700)
    ssh_old_app = ssh_home / ".local/share/insta-sing-box"
    ssh_old_cfg = ssh_home / ".config/insta-sing-box"
    ssh_release = ssh_old_app / "tool-releases" / ("d" * 40)
    private_file(ssh_release / "isb.sh", "#!/usr/bin/env bash\n# Managed-by: Insta-Sing-box CLI\nprintf '%s\\n' '2.3.0'\n", 0o700)
    ssh_old_app.chmod(0o700)
    (ssh_old_app / "cli").symlink_to(ssh_release, target_is_directory=True)
    private_file(ssh_home / ".local/bin/isb", '''#!/usr/bin/env bash
# Managed-by: Insta-Sing-box CLI
exec bash "$HOME/.local/share/insta-sing-box/cli/isb.sh" "$@"
''', 0o700)
    ssh_heartbeat = {"schema": 1, "controllerId": "f" * 32, "intervalSeconds": 300,
                     "targets": [{"id": "ssh_only", "kind": "ssh", "label": "已有 SSH 保活",
                                  "revision": "e" * 32, "ssh": ssh,
                                  "tokenExpiry": {"kind": "unknown", "expiresAt": None}}]}
    private_file(ssh_old_cfg / "heartbeat.json", json_bytes(ssh_heartbeat))
    private_file(ssh_home / ".bashrc", shell_prefix + old_path)

    menu_home, auto_fail_home = TMP / "menu-home", TMP / "auto-fail-home"
    auto_fail_state = TMP / "auto-fail-systemd"
    probe_fail_home, probe_fail_state = TMP / "probe-fail-home", TMP / "probe-fail-systemd"
    for directory in (menu_home, auto_fail_home, auto_fail_state, probe_fail_home, probe_fail_state):
        directory.mkdir(mode=0o700)

    # Exercise the actual full installer with a new HOME. Only the two external
    # release payloads and their pinned digests, a controlled connection probe,
    # and the auto-local side effect differ in this bundle.
    # The auto-local API/service behavior has its own offline unit tests; this
    # test verifies first-install routing and propagation of partial failure.
    # Bootstrap and artifact SHA-256 verification still run normally.
    fresh_home, fresh_bin = TMP / "fresh-home", TMP / "fresh-bin"
    fresh_state, fresh_source = TMP / "fresh-systemd", TMP / "fresh-source"
    for directory in (fresh_home, fresh_bin, fresh_state):
        directory.mkdir(mode=0o700)
    shutil.copytree(source, fresh_source)
    installer_text = (fresh_source / "install.sh").read_text()
    version = re.search(r"^SB_VERSION='([0-9.]+)'$", installer_text, re.M)
    assert version, "sing-box fixture cannot identify the pinned version"
    archive = fresh_source / ("sing-box-" + version.group(1) + "-linux-amd64.tar.gz")
    singbox_url = "https://github.com/SagerNet/sing-box/releases/download/v" + version.group(1) + "/" + archive.name
    cloudflare_version = re.search(r"^CF_VERSION='([0-9.]+)'$", installer_text, re.M)
    assert cloudflare_version, "cloudflared fixture cannot identify the pinned version"
    cloudflare_url = "https://github.com/cloudflare/cloudflared/releases/download/" + cloudflare_version.group(1) + "/cloudflared-linux-amd64"
    singbox_stub = b'#!/usr/bin/env bash\n[[ "${1:-}" == check ]] || exit 97\n'
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo(archive.name.removesuffix(".tar.gz") + "/sing-box")
        member.size, member.mode = len(singbox_stub), 0o700
        bundle.addfile(member, io.BytesIO(singbox_stub))
    archive.chmod(0o600)
    cloudflared = fresh_source / "cloudflared-linux-amd64"
    private_file(cloudflared, '''#!/usr/bin/env bash
[[ "${1:-}" == tunnel && "${2:-}" == --config && "${4:-}" == --protocol && "${5:-}" == auto && "${6:-}" == --no-autoupdate && "${7:-}" == --url ]] || exit 97
[[ "$(cat "$3")" == '{}' && "$8" == http://127.0.0.1:* ]] || exit 97
printf '%s\\n' 'https://fresh-bootstrap.trycloudflare.com' 'Registered tunnel connection'
''', 0o700)
    for variable, payload in (("SB_SHA256", archive), ("CF_SHA256", cloudflared)):
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        installer_text, count = re.subn(r"^" + variable + r"='[a-f0-9]{64}'$",
                                       variable + "='" + digest + "'", installer_text, flags=re.M)
        assert count == 1, "external fixture digest was not substituted exactly once"
    private_file(fresh_source / "install.sh", installer_text, 0o700)
    private_file(fresh_source / "node_probe.py", '''import os
import sys
code = int(os.environ.get("FRESH_PROBE_RC", "0"))
if '--quiet' not in sys.argv:
    print('  本地检查： 已通过（离线安装夹具）' if code == 0 else '  本地检查： 未通过（离线安装夹具）')
raise SystemExit(code)
''', 0o700)
    private_file(fresh_source / "heartbeat.py", '''import os
from pathlib import Path
import stat
import sys
assert sys.argv[1:] == ["auto-local"], "Unexpected heartbeat action during first installation"
key = Path.home() / ".config/insta-box/api-key"
assert key.read_text() == "ibk_FAKE_FRESH_BOOTSTRAP_KEY\\n", "Background task was configured before persistent authorization"
assert stat.S_IMODE(key.stat().st_mode) == 0o600
with (Path.home() / "auto-actions").open("a") as log:
    log.write("auto-local\\n")
code = int(os.environ.get("FRESH_AUTO_RC", "0"))
print("  本机自动保活已启用（离线夹具）。" if code == 0 else "  保活启用未完成（离线夹具）。", file=sys.stdout if code == 0 else sys.stderr)
raise SystemExit(code)
''', 0o700)
    private_file(fresh_source / "SHA256SUMS", "".join(
        hashlib.sha256((fresh_source / name).read_bytes()).hexdigest() + "  " + name + "\n"
        for name in runtime_files))
    private_file(fresh_bin / "systemctl", '''#!/usr/bin/env bash
set -eu
[[ "${1:-}" == --user ]] || exit 97
shift
case "${1:-}" in
  show-environment|daemon-reload) exit 0 ;;
  enable)
    [[ "${2:-}" == --now ]] || exit 97
    case "${3:-}" in
      insta-box-node.service) ;;
      insta-box-quick.service)
        # A user service does not inherit setup.sh's private umask.
        (umask 0002; bash "$HOME/.local/share/insta-box/bin/start-quick-tunnel") ;;
      *) exit 97 ;;
    esac
    touch "$FRESH_SYSTEMD_STATE/$3" ;;
  is-active)
    [[ "${2:-}" == --quiet ]] || exit 97
    [[ -f "$FRESH_SYSTEMD_STATE/${3:-}" ]] ;;
  *) exit 97 ;;
esac
''', 0o700)
    private_file(fresh_bin / "loginctl", '#!/bin/sh\n[ "$1" = show-user ] || exit 97\nprintf "yes\\n"\n', 0o700)
    private_file(fresh_bin / "journalctl", "#!/bin/sh\nexit 97\n", 0o700)
    private_file(fresh_bin / "ss", "#!/bin/sh\nexit 0\n", 0o700)

    private_file(mock_bin / "curl", '''#!/usr/bin/env bash
set -eu
url=; out=
while (( $# )); do
 case "$1" in -o) out="$2"; shift 2;; https:*) url="$1"; shift;; *) shift;; esac
done
[[ -n "$url" && -n "$out" ]] || exit 97
case "$url" in
 https://api.github.com/repos/Pretic/InstaBox-Tool/git/ref/heads/main)
   printf '%s\\n' "$url" >> "$HOME/download-urls"
   printf '{"object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}\\n' > "$out"
   exit 0 ;;
 https://raw.githubusercontent.com/Pretic/InstaBox-Tool/main/setup.sh)
   file=setup.sh ;;
 *)
   if [[ "$url" =~ ^https://raw[.]githubusercontent[.]com/Pretic/InstaBox-Tool/[a-f0-9]{40}/([A-Za-z0-9_.-]+)$ ]]; then
     file="${BASH_REMATCH[1]}"
   elif [[ "$url" == "$FIXTURE_SB_URL" || "$url" == "$FIXTURE_CF_URL" ]]; then
     file="${url##*/}"
   else
     printf '%s\\n' 'Unexpected download origin in offline bootstrap' >&2
     exit 97
   fi ;;
esac
printf '%s\\n' "$url" >> "$HOME/download-urls"
cp "$SOURCE_DIR/$file" "$out"
if [[ "$file" == "${CORRUPT_FILE:-}" ]]; then echo BAD >> "$out"; fi
''', 0o700)
    # Detailed service migration is covered by test_migration.py. No units are
    # preinstalled here; any accidental call must not reach the host's systemd.
    private_file(mock_bin / "systemctl", "#!/usr/bin/env bash\necho 'Unexpected systemctl in bootstrap fixture' >&2\nexit 97\n", 0o700)
    demote = None
    if ROOT_FIXTURE:
        try:
            account = pwd.getpwnam("oai")
        except KeyError:
            account = pwd.getpwnam("nobody")
        for item in [TMP, *TMP.rglob("*")]:
            os.chown(item, account.pw_uid, account.pw_gid, follow_symlinks=False)

        def demote():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

    env = {**os.environ, "HOME": str(fixture_home), "TMPDIR": str(runtime_tmp),
           "PATH": str(mock_bin) + ":" + os.environ["PATH"], "SOURCE_DIR": str(source), "IBT_REF": "a" * 40,
           "FIXTURE_SB_URL": singbox_url, "FIXTURE_CF_URL": cloudflare_url,
           "PYTHONPATH": str(api_hook), "API_FIXTURE_MODE": "forbid", "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("CORRUPT_FILE", "INSTABOX_API_KEY"):
        env.pop(name, None)

    def run(args, extra=None, *, home=fixture_home):
        return subprocess.run(args, env={**env, "HOME": str(home), **(extra or {})}, capture_output=True,
                              text=True, preexec_fn=demote, timeout=60)

    def setup(extra=None, *, home=fixture_home, mode="--menu-only", bundle_source=source):
        return run(["bash", str(bundle_source / "setup.sh"), mode],
                   {"SOURCE_DIR": str(bundle_source), **(extra or {})}, home=home)

    def no_new_install(home, state):
        assert not (home / ".local").exists(), "authorization failure installed or migrated the application"
        assert not (home / ".config/insta-box").exists(), "authorization failure persisted a credential"
        assert not (home / ".config/systemd").exists(), "authorization failure created services"
        assert not (home / "auto-actions").exists(), "authorization failure configured a background task"
        assert not list(state.iterdir()), "authorization failure started a service"

    def no_api_request(home):
        assert not (home / "api-actions").exists(), "an existing installation requested API reauthorization"

    def preserved():
        assert not old_app.exists() and not old_cfg.exists(), "old private directory remained active"
        for name, value in node_files.items():
            assert (app / name).read_bytes() == value, name
            assert (app / name).stat().st_ino == old_node_inodes[name], "v2 node state was rewritten"
        for name, value in config_files.items():
            assert (cfg / name).read_bytes() == value, name
            assert (cfg / name).stat().st_ino == old_config_inodes[name], "v2 private state was rewritten"
        assert json.loads((cfg / "heartbeat.json").read_bytes()) == {**heartbeat, "leasePrefix": "isb"}
        preserved_sdk(app, old_sdk)
        assert (fixture_home / ".bashrc").read_bytes() == shell_prefix + new_path, "PATH line duplicated or user settings changed"

    def preserved_v3():
        for path, inode in v3_roots.items():
            assert path.stat().st_ino == inode, "v3 data directory was recreated"
        for path, value in v3_original_files.items():
            assert path.read_bytes() == value, str(path.relative_to(v3_home))
            assert path.stat().st_ino == v3_inodes[path], "v3 private state was rewritten"
        assert (v3_home / ".bashrc").read_bytes() == shell_prefix + new_path, "v3 PATH line duplicated or user settings changed"
        assert not (v3_home / ".local/share/insta-sing-box").exists()
        assert not (v3_home / ".config/insta-sing-box").exists()
        preserved_sdk(v3_app, v3_sdk)

    identity = run(["id", "-u"])
    assert identity.returncode == 0 and identity.stdout.strip() != "0", "bootstrap must run as a real non-root user"
    result = setup()
    assert result.returncode == 0, result.stderr + result.stdout
    cli = app / "cli"
    assert cli.is_symlink()
    previous = cli.resolve()
    preserved()
    migrated_heartbeat = (cfg / "heartbeat.json").read_bytes()
    for name in runtime_files:
        assert (cli / name).read_bytes() == (source / name).read_bytes(), name
    bridge = local_bin / "isb"
    assert "# Managed-by: InstaBox Tool migration bridge" in bridge.read_text().splitlines()
    assert "# Managed-by: InstaBox Tool CLI" in (local_bin / "ibt").read_text().splitlines()
    result = run([str(bridge), "--version"])
    assert result.returncode == 0 and result.stdout.strip() == "0.0.1", result.stderr + result.stdout
    assert not os.path.lexists(bridge), "first old isb invocation did not remove its bridge"
    result = run([str(local_bin / "ibt"), "--version"])
    assert result.returncode == 0 and result.stdout.strip() == "0.0.1", result.stderr + result.stdout
    assert not os.path.lexists(local_bin / "ib"), "v2 migration created an unused ib command"

    for corrupt in ("ibt.sh", "heartbeat.py", "migrate.py"):
        result = setup({"CORRUPT_FILE": corrupt})
        assert result.returncode != 0 and "校验未通过" in result.stdout + result.stderr, corrupt
        assert cli.resolve() == previous, "a bad download replaced the working bundle"
        preserved()
        assert (cfg / "heartbeat.json").read_bytes() == migrated_heartbeat

    downloads_before = (fixture_home / "download-urls").read_text().splitlines()
    # Exercise the installed command, not just setup.sh: both its bootstrap URL
    # and the bootstrap's main-ref/bundle URLs must come from the new repository.
    result = run([str(local_bin / "ibt"), "update"], {"IBT_REF": "", "IB_REF": "", "ISB_REF": ""})
    assert result.returncode == 0, result.stderr + result.stdout
    downloads = (fixture_home / "download-urls").read_text().splitlines()[len(downloads_before):]
    assert downloads[:2] == ["https://raw.githubusercontent.com/Pretic/InstaBox-Tool/main/setup.sh",
                             "https://api.github.com/repos/Pretic/InstaBox-Tool/git/ref/heads/main"], downloads
    assert downloads[2:] == ["https://raw.githubusercontent.com/Pretic/InstaBox-Tool/" + "a" * 40 + "/" + name
                            for name in ("SHA256SUMS", *runtime_files)], downloads
    assert cli.is_symlink() and cli.resolve() != previous, "a successful update did not switch the versioned bundle"
    preserved()
    assert (cfg / "heartbeat.json").read_bytes() == migrated_heartbeat
    assert not os.path.lexists(bridge), "a later update recreated the obsolete command"
    result = run([str(local_bin / "ibt"), "--version"])
    assert result.returncode == 0 and result.stdout.strip() == "0.0.1", result.stderr + result.stdout
    no_api_request(fixture_home)

    # A v3.0 marker must be recognized on upgrade; a subsequent update must
    # likewise recognize the new Tool marker, without rebuilding private state.
    result = setup(home=v3_home)
    assert result.returncode == 0, result.stderr + result.stdout
    v3_cli = v3_app / "cli"
    assert v3_cli.is_symlink() and v3_cli.resolve() != v3_release
    preserved_v3()
    for name in runtime_files:
        assert (v3_cli / name).read_bytes() == (source / name).read_bytes(), name
    v3_bridge = v3_bin / "ib"
    assert "# Managed-by: InstaBox Tool migration bridge" in v3_bridge.read_text().splitlines()
    assert "# Managed-by: InstaBox Tool CLI" in (v3_bin / "ibt").read_text().splitlines()
    result = run([str(v3_bridge), "--version"], home=v3_home)
    assert result.returncode == 0 and result.stdout.strip() == "0.0.1", result.stderr + result.stdout
    assert not os.path.lexists(v3_bridge), "first old ib invocation did not remove its bridge"
    previous_v3 = v3_cli.resolve()
    result = setup(home=v3_home)
    assert result.returncode == 0, result.stderr + result.stdout
    assert v3_cli.is_symlink() and v3_cli.resolve() != previous_v3
    preserved_v3()
    assert not os.path.lexists(v3_bridge), "a later update recreated ib"
    assert not os.path.lexists(v3_bin / "isb"), "v3 update created an unused isb command"
    result = run([str(v3_bin / "ibt"), "--version"], home=v3_home)
    assert result.returncode == 0 and result.stdout.strip() == "0.0.1", result.stderr + result.stdout
    no_api_request(v3_home)

    result = setup(home=ssh_home)
    assert result.returncode == 0, result.stderr + result.stdout
    ssh_cfg = ssh_home / ".config/insta-box"
    assert json.loads((ssh_cfg / "heartbeat.json").read_bytes()) == {**ssh_heartbeat, "leasePrefix": "isb"}
    assert not (ssh_cfg / "api-key").exists(), "an existing SSH-only controller was forced to use an API Key"
    assert not ssh_old_app.exists() and not ssh_old_cfg.exists()
    no_api_request(ssh_home)

    fresh_env = {"PATH": str(fresh_bin) + ":" + str(mock_bin) + ":/usr/bin:/bin",
                 "SOURCE_DIR": str(fresh_source), "FRESH_SYSTEMD_STATE": str(fresh_state), "IBT_NO_SUDO": "1",
                 "API_FIXTURE_MODE": "authorize"}
    assert str(fresh_home / ".local/bin") not in fresh_env["PATH"].split(":")
    assert not (fresh_home / ".local").exists(), "full-install fixture must start with an empty HOME"

    # Missing and rejected credentials must stop before migrate.py can install
    # the CLI, write PATH changes, or create either node/background services.
    for mode in ("--menu-only", "install"):
        result = setup(fresh_env, home=fresh_home, mode=mode, bundle_source=fresh_source)
        assert result.returncode != 0, "first installation accepted a missing API Key: " + mode
        no_new_install(fresh_home, fresh_state)
        assert "InstaBox Tool 已就绪" not in result.stdout
    bad_key = "ibk_FAKE_REJECTED_BOOTSTRAP_KEY"
    for mode in ("--menu-only", "install"):
        result = setup({**fresh_env, "INSTABOX_API_KEY": bad_key}, home=fresh_home,
                       mode=mode, bundle_source=fresh_source)
        assert result.returncode != 0, "first installation accepted a rejected API Key: " + mode
        assert bad_key not in result.stdout + result.stderr, "the API error exposed the submitted Key"
        no_new_install(fresh_home, fresh_state)
        assert "InstaBox Tool 已就绪" not in result.stdout

    authorized = {**fresh_env, "INSTABOX_API_KEY": "ibk_FAKE_FRESH_BOOTSTRAP_KEY"}
    result = setup(authorized, home=menu_home, bundle_source=fresh_source)
    assert result.returncode == 0, result.stderr + result.stdout
    menu_app, menu_cfg = menu_home / ".local/share/insta-box", menu_home / ".config/insta-box"
    assert (menu_app / "cli/ibt.sh").is_file(), "authorized --menu-only did not install the CLI"
    assert not (menu_app / "state.conf").exists() and not (menu_home / ".config/systemd").exists()
    assert not (menu_home / "auto-actions").exists(), "--menu-only unexpectedly installed background services"
    assert (menu_cfg / "api-key").read_text() == authorized["INSTABOX_API_KEY"] + "\n"
    assert stat.S_IMODE((menu_cfg / "api-key").stat().st_mode) == 0o600
    assert (menu_home / "api-actions").read_text().splitlines() == ["GET /v1/me", "GET /v1/machines"]

    api_before_install = (fresh_home / "api-actions").read_text().splitlines()
    result = setup(authorized, home=fresh_home, mode="install", bundle_source=fresh_source)
    assert result.returncode == 0, result.stderr + result.stdout
    assert authorized["INSTABOX_API_KEY"] not in result.stdout + result.stderr
    api_after_install = (fresh_home / "api-actions").read_text().splitlines()
    assert api_after_install[len(api_before_install):] == ["GET /v1/me", "GET /v1/machines"] * 2, "setup and the direct node installer must each enforce authorization"
    assert (fresh_home / "auto-actions").read_text().splitlines() == ["auto-local"]
    fresh_cfg = fresh_home / ".config/insta-box"
    assert (fresh_cfg / "api-key").read_text() == authorized["INSTABOX_API_KEY"] + "\n"
    assert stat.S_IMODE((fresh_cfg / "api-key").stat().st_mode) == 0o600
    assert stat.S_IMODE(fresh_cfg.stat().st_mode) == 0o700
    assert 'export PATH="$HOME/.local/bin:$PATH"' in result.stdout, "current-shell PATH guidance is missing"
    assert any(path in result.stdout for path in ('~/.local/bin/ibt', '$HOME/.local/bin/ibt', str(fresh_home / '.local/bin/ibt'))), "absolute command guidance is missing"
    fresh_app = fresh_home / ".local/share/insta-box"
    quick_log = fresh_app / "quick.log"
    assert "Registered tunnel connection" in quick_log.read_text(), "the actual generated launcher did not run"
    assert stat.S_IMODE(quick_log.stat().st_mode) == 0o600, "service-created quick.log is not private"
    quick_config = fresh_app / "quick-config.yml"
    assert quick_config.read_text() == "{}\n" and stat.S_IMODE(quick_config.stat().st_mode) == 0o600
    assert '网络连接仍需排查' not in result.stderr
    assert 'WebSocket 握手通过' in result.stdout
    assert 'InstaBox Tool 已就绪' in result.stdout
    login = run(["bash", "--login", "-c", "command -v ibt && ibt --version"], fresh_env, home=fresh_home)
    assert login.returncode == 0, login.stderr + login.stdout
    assert str(fresh_home / ".local/bin/ibt") in login.stdout.splitlines(), "login shell did not discover ibt"
    assert login.stdout.splitlines()[-1] == "0.0.1", login.stdout
    preserved_paths = [fresh_app / name for name in ("state.conf", "config.json", "quick.log")]
    preserved_paths.append(fresh_home / ".config/insta-box/api-key")
    fresh_snapshot = {path: (path.read_bytes(), path.stat().st_ino) for path in preserved_paths}
    fresh_release = (fresh_app / "cli").resolve()
    result = setup({**fresh_env, "API_FIXTURE_MODE": "forbid", "INSTABOX_API_KEY": bad_key},
                   home=fresh_home, bundle_source=fresh_source)
    assert result.returncode == 0, result.stderr + result.stdout
    assert (fresh_app / "cli").resolve() != fresh_release, "fresh installation did not accept the next update"
    for path, snapshot in fresh_snapshot.items():
        assert (path.read_bytes(), path.stat().st_ino) == snapshot, "updating changed node data or private state"
    assert stat.S_IMODE(quick_log.stat().st_mode) == 0o600
    assert (fresh_home / "api-actions").read_text().splitlines() == api_after_install
    assert (fresh_home / "auto-actions").read_text().splitlines() == ["auto-local"], "updating reconfigured automatic keepalive"

    # A partial installation is useful for retrying: keep the already-created
    # node and private Key, but report failure until auto-local is enabled.
    result = setup({**authorized, "FRESH_SYSTEMD_STATE": str(auto_fail_state), "FRESH_AUTO_RC": "1"},
                   home=auto_fail_home, mode="install", bundle_source=fresh_source)
    assert result.returncode != 0, "failed automatic keepalive was reported as a successful full installation"
    assert "InstaBox Tool 已就绪" not in result.stdout
    assert "保活" in result.stderr
    assert (auto_fail_home / ".local/share/insta-box/state.conf").is_file(), "partial failure discarded the installed node"
    assert (auto_fail_home / ".config/insta-box/api-key").read_text() == authorized["INSTABOX_API_KEY"] + "\n"
    assert (auto_fail_home / "auto-actions").read_text().splitlines() == ["auto-local"]
    assert (auto_fail_state / "insta-box-quick.service").exists()
    assert authorized["INSTABOX_API_KEY"] not in result.stdout + result.stderr

    result = setup({**authorized, "FRESH_SYSTEMD_STATE": str(probe_fail_state), "FRESH_PROBE_RC": "1"},
                   home=probe_fail_home, mode="install", bundle_source=fresh_source)
    assert result.returncode != 0, "an unverified Quick connection was reported as full installation success"
    assert "InstaBox Tool 已就绪" not in result.stdout
    assert "网络连接仍需排查" in result.stderr and "ibt diagnose" in result.stderr
    assert "WebSocket 握手通过" not in result.stdout
    assert (probe_fail_home / ".local/share/insta-box/state.conf").is_file()
    assert (probe_fail_home / ".config/insta-box/api-key").read_text() == authorized["INSTABOX_API_KEY"] + "\n"
    assert (probe_fail_home / "auto-actions").read_text().splitlines() == ["auto-local"], "failed Quick connection skipped automatic keepalive"
    assert (probe_fail_state / "insta-box-quick.service").exists()
    print("Non-root legacy SDK/SSH-only migration, repeat upgrades without reauthorization, first-install API gate before side effects, private Key persistence, Quick setup, probe/auto-local failure propagation, login PATH, and corruption rejection: passed")
finally:
    shutil.rmtree(TMP, ignore_errors=True)
