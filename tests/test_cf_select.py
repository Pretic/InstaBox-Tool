"""Offline CF selection: fake public data, private fixtures, no node traffic."""

import contextlib
import errno
import io
import ipaddress
import json
import os
from pathlib import Path
import random
import select
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cf_select as cf
import node_probe as np

USER = "11111111-1111-4111-8111-111111111111"
HOST = "fixture.example.com"
QUICK = "offline-fixture.trycloudflare.com"
WS_PATH = "/ws-" + "a" * 36
INSTANCE = "c" * 32
QUERY = "encryption=none&security=tls&sni=" + HOST + "&type=ws&host=" + HOST + "&path=%2Fws-test%3Fed%3D2048"
LINK = f"vless://{USER}@{HOST}:443?{QUERY}#Fixture"
V4 = "104.16.0.0/13\n172.64.0.0/13\n"
V6 = "2606:4700::/32\n2a06:98c0::/29\n"
NETWORKS = cf.parse_networks(V4, 4) + cf.parse_networks(V6, 6)
IP4 = "104.16.1.2"
IP6 = "2606:4700::1234"


def html_row(address, label="测试线路"):
    return f'<tr><td data-label="优选地址"><span>{address}</span></td><td data-label="线路名称">{label}</td></tr>'


class FakeSources(cf.Sources):
    def __init__(self):
        self.calls = []
        self.payloads = {cf.CF_V4: V4, cf.CF_V6: V6,
                         cf.WETEST_V4: "<table>" + html_row(IP4) + html_row("104.16.2.3") + "</table>",
                         cf.WETEST_V6: "<table>" + html_row(IP6) + "</table>"}
        super().__init__(self.get)

    def get(self, url):
        self.calls.append(url)
        return self.payloads[url]


class Answers:
    def __init__(self, values):
        self.values = iter(values)
        self.prompts = []

    def __call__(self, prompt, secret=False):
        self.prompts.append((prompt, secret))
        return next(self.values)


class TemplateTests(unittest.TestCase):
    def test_only_dial_address_and_label_change_preserving_raw_query(self):
        query = QUERY + "&fp=chrome&x=a+b&x=a%20b&empty=&encoded=%2f%2F%25"
        original = f"vless://{USER}@{HOST}:8443?{query}#%E6%B5%8B%E8%AF%95"
        template = cf.parse_vless(original)
        result = template.link(IP4, "测试-CF-01")
        parsed = urllib.parse.urlsplit(result)
        self.assertEqual(parsed.hostname, IP4)
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.username, USER)
        self.assertEqual(parsed.query, query)
        self.assertEqual(urllib.parse.parse_qs(parsed.query)["path"], ["/ws-test?ed=2048"])
        self.assertEqual(urllib.parse.unquote(parsed.fragment), "测试-CF-01")
        self.assertEqual(original.split("?", 1)[1].split("#", 1)[0], query)

    def test_ipv6_is_bracketed_and_original_authority_ipv6_is_supported(self):
        original = LINK.replace(HOST + ":443", "[" + IP6 + "]:443", 1)
        result = cf.parse_vless(original).link("2a06:98c1::55", "IPv6")
        self.assertIn("@[2a06:98c1::55]:443?", result)
        self.assertEqual(urllib.parse.urlsplit(result).query, QUERY)

    def test_missing_sni_and_host_are_explicitly_pinned_to_original_domain(self):
        query = "security=tls&type=ws&path=%2Fws-a&unknown=1"
        parsed = cf.parse_vless(f"vless://{USER}@{HOST}?{query}")
        self.assertEqual(parsed.query, query + "&sni=" + HOST + "&host=" + HOST)
        self.assertEqual(parsed.completed, ("sni", "host"))
        result = cf.parse_vless(parsed.link(IP4, "test"))
        self.assertEqual(result.completed, ())
        with self.assertRaises(cf.SelectionError):
            cf.parse_vless(f"vless://{USER}@{IP4}:443?{query}")

    def test_explicit_distinct_sni_host_and_host_port_are_preserved(self):
        query = QUERY.replace("sni=" + HOST, "sni=tls.example.com").replace("host=" + HOST, "host=ws.example.com%3A443")
        parsed = cf.parse_vless(f"vless://{USER}@{HOST}:443?{query}")
        self.assertEqual(urllib.parse.urlsplit(parsed.link(IP4, "result")).query, query)

    def test_reject_unsupported_ambiguous_and_unsafe_templates_without_echo(self):
        invalid = [LINK.replace("vless://", "vmess://"), LINK.replace("security=tls", "security=none"),
                   LINK.replace("type=ws", "type=grpc"), LINK.replace(":443?", ":0?"), LINK.replace(":443?", ":80?"),
                   LINK.replace("?", "/?"), LINK.replace(USER, "PRIVATE_INVALID_UUID"),
                   LINK.replace("#Fixture", "&sni=duplicate.example.com#Fixture"),
                   LINK.replace("#Fixture", "&%73ni=duplicate.example.com#Fixture"),
                   LINK.replace("#Fixture", "&allowInsecure=1#Fixture"),
                   LINK.replace("#Fixture", "&skip-cert-verify=true#Fixture"),
                   LINK.replace("#Fixture", "&flow=xtls-rprx-vision#Fixture"),
                   LINK.replace("#Fixture", "&unknown=%0D%0APRIVATE_SECRET#Fixture"),
                   LINK.replace("#Fixture", "&unknown=%zz#Fixture"),
                   LINK + "\x1bPRIVATE_SECRET", LINK.replace("host=" + HOST, "host=127.0.0.1"),
                   LINK.replace("sni=" + HOST, "sni="), LINK.replace("host=" + HOST, "host=" + "a" * 256 + ".com")]
        for link in invalid:
            with self.subTest(link=link[:15]), self.assertRaises(cf.SelectionError) as found:
                cf.parse_vless(link)
            self.assertNotIn("PRIVATE", str(found.exception))
            self.assertNotIn(USER, str(found.exception))

    def test_disabled_insecure_flags_preserved_and_label_controls_removed(self):
        link = LINK.replace("#Fixture", "&allowInsecure=false&fp=chrome#%1B%5B31m%E6%B5%8B%E8%AF%95")
        template = cf.parse_vless(link)
        self.assertIn("allowInsecure=false&fp=chrome", template.query)
        self.assertFalse(cf.has_controls(template.label))
        self.assertNotIn("\x1b", template.link(IP4, template.label))

    def test_unicode_line_separators_and_utf8_byte_limit_are_rejected(self):
        for suffix in ("\u2028", "\u2029", "\ud800", "字" * (cf.MAX_URI // 3)):
            with self.assertRaises(cf.SelectionError):
                cf.parse_vless(LINK.replace("#Fixture", "&unknown=" + suffix + "#Fixture"))
        query = QUERY + "&extra=" + "字" * 1000
        template = cf.parse_vless(f"vless://{USER}@{HOST}:443?{query}#Fixture")
        generated = template.link(IP4, "Unicode")
        self.assertLessEqual(len(generated.encode("utf-8")), cf.MAX_URI)
        self.assertEqual(urllib.parse.urlsplit(generated).query, query)


class SourceTests(unittest.TestCase):
    def test_cloud_html_filters_non_cf_private_duplicates_scripts_and_controls(self):
        html = ("<script>" + html_row("104.16.6.6") + "</script><table>"
                + html_row(IP4, "电信&#27;[31m") + html_row(IP4, "重复")
                + html_row("1.1.1.1") + html_row("127.0.0.1") + html_row("evil.example.com")
                + html_row("104.16.7.8;id") + html_row(IP6, "IPv6") + "</table>")
        result = cf.cloud_candidates(html, NETWORKS, rng=random.Random(1))
        self.assertEqual({item.address for item in result}, {IP4, IP6})
        self.assertTrue(all(not cf.has_controls(item.label) for item in result))
        for empty in ("<html>no table</html>", html_row("1.1.1.1"), "<script>" + html_row(IP4) + "</script>"):
            with self.assertRaises(cf.SelectionError):
                cf.cloud_candidates(empty, NETWORKS)

    def test_cloud_default_ipv4_ipv6_and_dual_stack_use_correct_public_urls(self):
        for family, expected in ((4, {IP4, "104.16.2.3"}), (6, {IP6}), (0, {IP4, "104.16.2.3", IP6})):
            source = FakeSources()
            result = source.cloud(30, family)
            self.assertEqual({item.address for item in result}, expected)
            self.assertTrue(set(source.calls) <= cf.PUBLIC_URLS)
            self.assertNotIn("cloudfront", " ".join(source.calls))
            if family != 4:
                self.assertIn(cf.WETEST_V6, source.calls)
            if family == 4:
                self.assertEqual(set(source.calls), {cf.CF_V4, cf.WETEST_V4})

    def test_official_random_ips_are_unique_in_range_and_not_network_base(self):
        for family, networks in ((4, cf.parse_networks(V4, 4)), (6, cf.parse_networks(V6, 6))):
            result = cf.random_candidates(networks, 30, rng=random.Random(2))
            self.assertEqual(len(result), 30)
            self.assertEqual(len({item.address for item in result}), 30)
            for item in result:
                address = ipaddress.ip_address(item.address)
                self.assertEqual(address.version, family)
                self.assertTrue(cf.belongs_to_cloudflare(address, networks))
                self.assertNotIn(address, [network.network_address for network in networks])
                if family == 4:
                    self.assertNotIn(address, [network.broadcast_address for network in networks])
        with self.assertRaises(cf.SelectionError):
            cf.random_candidates([ipaddress.ip_network("104.16.1.1/32")], 2, rng=random.Random(2))

    def test_manual_ipv4_ipv6_deduplicate_and_reject_dangerous_or_non_cf_addresses(self):
        result = cf.manual_candidates(IP4 + ", [" + IP6 + "] " + IP4, NETWORKS)
        self.assertEqual([item.address for item in result], [IP4, IP6])
        invalid = ("", "localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1%eth0",
                   "224.0.0.1", "ff02::1", "1.1.1.1", "104.16.1.2:443", "104.16.1.2/32", "104.16.1.2;id",
                   " ".join([IP4] * 31))
        for value in invalid:
            with self.subTest(value=value[:25]), self.assertRaises(cf.SelectionError):
                cf.manual_candidates(value, NETWORKS)

    def test_invalid_manual_addresses_do_not_fetch_anything_and_networks_are_cached(self):
        source = FakeSources()
        with self.assertRaises(cf.SelectionError):
            source.manual("127.0.0.1")
        self.assertEqual(source.calls, [])
        source.manual(IP4 + " " + IP6)
        source.manual(IP4)
        self.assertEqual(source.calls, [cf.CF_V4, cf.CF_V6])

    def test_invalid_official_responses_are_rejected(self):
        for raw, family in (("<html>PRIVATE_BODY</html>", 4), ("0.0.0.0/0", 4), ("10.0.0.0/8", 4),
                            ("104.16.1.1/13", 4), (V4, 6), ("::/0", 6), ("", 4)):
            with self.subTest(raw=raw[:15]), self.assertRaises(cf.SelectionError) as found:
                cf.parse_networks(raw, family)
            self.assertNotIn("PRIVATE_BODY", str(found.exception))

    def test_download_limits_public_destinations_and_keeps_tls_verification(self):
        class Response(io.BytesIO):
            def geturl(self):
                return cf.CF_V4
        response = Response(V4.encode())
        opener = mock.Mock()
        opener.open.return_value = response
        self.assertEqual(cf.download_text(cf.CF_V4, opener=opener), V4)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, cf.CF_V4)
        self.assertNotIn(USER, str(request.headers))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 12)
        with self.assertRaises(cf.SelectionError):
            cf.download_text("http://127.0.0.1/private", opener=opener)
        opener.open.return_value = Response(b"x" * (cf.MAX_DOWNLOAD + 1))
        with self.assertRaises(cf.SelectionError):
            cf.download_text(cf.CF_V4, opener=opener)
        opener.open.return_value = Response(V4.encode())
        with mock.patch.object(cf.urllib.request, "build_opener", return_value=opener) as build:
            cf.download_text(cf.CF_V4)
            https = next(arg for arg in build.call_args.args if isinstance(arg, cf.urllib.request.HTTPSHandler))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)

    def test_redirects_and_network_error_bodies_never_echo_private_content(self):
        handler = cf.PublicRedirects()
        request = urllib.parse.urlsplit(cf.CF_V4)
        with self.assertRaises(cf.SelectionError):
            handler.redirect_request(request, None, 302, "found", {}, "https://evil.example.com/PRIVATE_BODY")
        opener = mock.Mock()
        for failure in (urllib.error.URLError("PRIVATE_BODY"),
                        urllib.error.HTTPError(cf.CF_V4, 503, "PRIVATE_BODY", {}, None)):
            opener.open.side_effect = failure
            with self.assertRaises(cf.SelectionError) as found:
                cf.download_text(cf.CF_V4, opener=opener)
            self.assertNotIn("PRIVATE_BODY", str(found.exception))


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.home.chmod(0o700)
        self.directory = self.home / ".config/insta-box"
        self.file = self.directory / cf.FILENAME
        self.store = cf.NodeStore(self.home)
        self.links = [cf.parse_vless(LINK).link(IP4, "result")]


class StoreTests(PrivateFixture):
    def test_save_read_overwrite_are_private_atomic_and_leave_other_files_unchanged(self):
        self.assertIsNone(self.store.read())
        self.store.write(self.links)
        self.assertEqual(self.store.read(), self.links)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        old_inode = self.file.stat().st_ino
        other = self.directory / "api-key"
        other.write_text("PRIVATE_API_KEY")
        other.chmod(0o600)
        replacement = [cf.parse_vless(LINK).link(IP6, "second")]
        self.store.write(replacement)
        self.assertNotEqual(self.file.stat().st_ino, old_inode)
        self.assertEqual(self.store.read(), replacement)
        self.assertEqual(other.read_text(), "PRIVATE_API_KEY")
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["api-key", cf.FILENAME])

    def test_refuses_symlinks_hardlinks_open_permissions_and_fifo(self):
        self.store.write(self.links)
        target = self.home / "outside"
        target.write_text("PRIVATE_TARGET")
        target.chmod(0o600)
        for kind in ("symlink", "hardlink", "permissions", "fifo"):
            with self.subTest(kind=kind):
                self.file.unlink()
                if kind == "symlink":
                    self.file.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, self.file)
                elif kind == "fifo":
                    os.mkfifo(self.file, 0o600)
                else:
                    self.file.write_text(self.links[0] + "\n")
                    self.file.chmod(0o644)
                with self.assertRaises(cf.SelectionError):
                    self.store.read()
                with self.assertRaises(cf.SelectionError):
                    self.store.write(self.links)
                self.assertEqual(target.read_text(), "PRIVATE_TARGET")

    def test_refuses_symlinked_config_parent_and_unowned_directory_modes(self):
        real = self.home / "real-config"
        real.mkdir(mode=0o700)
        (self.home / ".config").symlink_to(real)
        with self.assertRaises(cf.SelectionError):
            self.store.write(self.links)
        self.assertEqual(list(real.iterdir()), [])
        (self.home / ".config").unlink()
        self.store.write(self.links)
        self.directory.chmod(0o755)
        with self.assertRaises(cf.SelectionError):
            self.store.read()
        with self.assertRaises(cf.SelectionError):
            self.store.write(self.links)

    def test_failed_atomic_replace_preserves_old_file_and_removes_temp(self):
        self.store.write(self.links)
        with mock.patch.object(cf.os, "replace", side_effect=OSError("PRIVATE_ERROR")):
            with self.assertRaises(cf.SelectionError) as found:
                self.store.write([cf.parse_vless(LINK).link(IP6, "other")])
        self.assertNotIn("PRIVATE_ERROR", str(found.exception))
        self.assertEqual(self.store.read(), self.links)
        self.assertEqual([path.name for path in self.directory.iterdir()], [cf.FILENAME])

    def test_invalid_or_oversized_saved_content_is_not_printed(self):
        self.store.write(self.links)
        for raw in ("PRIVATE_BAD_CONTENT\n", "x" * (cf.MAX_SAVED + 1), "\n".join(self.links * 31)):
            self.file.write_text(raw)
            self.file.chmod(0o600)
            output = []
            result = cf.main(["--show-last"], store=self.store, output=output.append)
            self.assertEqual(result, 1)
            self.assertNotIn("PRIVATE_BAD_CONTENT", "\n".join(output))


class LocalTests(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.app = self.home / ".local/share/insta-box"
        self.app.mkdir(mode=0o700, parents=True)
        for directory in (self.home / ".local", self.home / ".local/share", self.app):
            directory.chmod(0o700)
        self.state = f"mode=quick\ndomain={HOST}\nuuid={USER}\npath={WS_PATH}\nport=20000\n"
        self.private("state.conf", self.state)
        self.private("config.json", json.dumps({"inbounds": [{"type": "vless", "tag": "vless-ws", "listen_port": 20000,
            "users": [{"uuid": USER}], "transport": {"type": "ws", "path": WS_PATH}}]}))
        self.private("quick.log", "IBT_QUICK_INVOCATION=" + INSTANCE + "\nhttps://" + QUICK + "\n")
        self.calls = []
        self.quick_active = "active"
        self.callback = None
        self.probe = np.Probe(self.home, runner=self.run_command, monotonic=lambda: 1000, clock=lambda: 1800000000)

    def private(self, name, text):
        path = self.app / name
        path.write_text(text)
        path.chmod(0o600)

    def run_command(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[:3], ["systemctl", "--user", "show"])
        if self.callback:
            self.callback(len(self.calls))
        blocks = []
        for unit in (np.NODE_SERVICE, np.QUICK_SERVICE):
            active = self.quick_active if unit == np.QUICK_SERVICE else "active"
            blocks.append("\n".join(("Id=" + unit, "LoadState=loaded", "ActiveState=" + active,
                "SubState=running", "NRestarts=0", "ExecMainStatus=0", "MainPID=100", "InvocationID=" + INSTANCE,
                "ExecMainStartTimestampMonotonic=990000000")))
        return subprocess.CompletedProcess(args, 0, "\n\n".join(blocks), "PRIVATE_STDERR")

    def test_fixed_and_quick_keep_original_configuration_and_only_read_service_state(self):
        before = {path.name: path.read_bytes() for path in self.app.iterdir()}
        fixed, _ = cf.local_template("fixed", probe=self.probe)
        self.assertEqual(fixed.host, HOST)
        self.assertEqual(self.calls, [])
        quick, identity = cf.local_template("quick", probe=self.probe)
        self.assertEqual(quick.host, QUICK)
        self.assertEqual(quick.label, "IBT-Quick")
        self.assertEqual(urllib.parse.parse_qs(quick.query)["path"], [WS_PATH])
        self.assertEqual(quick.user, USER)
        self.assertEqual(identity[2][0], INSTANCE)
        self.assertEqual(len(self.calls), 2)
        after = {path.name: path.read_bytes() for path in self.app.iterdir()}
        self.assertEqual(before, after)

    def test_quick_old_log_stopped_service_or_changed_log_is_rejected(self):
        for kind in ("stale", "stopped", "changed"):
            self.calls.clear()
            self.quick_active = "active"
            self.callback = None
            self.private("quick.log", "IBT_QUICK_INVOCATION=" + INSTANCE + "\nhttps://" + QUICK + "\n")
            if kind == "stale":
                self.private("quick.log", "IBT_QUICK_INVOCATION=" + "d" * 32 + "\nhttps://" + QUICK + "\n")
            elif kind == "stopped":
                self.quick_active = "inactive"
            else:
                def change(call):
                    if call == 2:
                        self.private("quick.log", "IBT_QUICK_INVOCATION=" + INSTANCE + "\nhttps://changed-fixture.trycloudflare.com\n")
                self.callback = change
            with self.subTest(kind=kind), self.assertRaises(cf.SelectionError) as found:
                cf.local_template("quick", probe=self.probe)
            self.assertNotIn(QUICK, str(found.exception))
            self.assertNotIn(INSTANCE, str(found.exception))

    def test_inconsistent_and_concurrently_changed_local_config_are_rejected(self):
        self.private("state.conf", self.state.replace("port=20000", "port=20001"))
        with self.assertRaises(cf.SelectionError):
            cf.local_template("fixed", probe=self.probe)
        self.private("state.conf", self.state)
        original = self.probe.configuration
        def change():
            result = original()
            self.private("state.conf", self.state.replace(HOST, "changed.example.com"))
            return result
        self.probe.configuration = change
        with self.assertRaises(cf.SelectionError):
            cf.local_template("fixed", probe=self.probe)


class InterfaceTests(PrivateFixture):
    def run_flow(self, answers, **kwargs):
        output = []
        reader = Answers(answers)
        source = kwargs.pop("sources", FakeSources())
        result = cf.main([], ask=reader, output=output.append, store=self.store, sources=source, **kwargs)
        return result, output, reader, source

    def test_manual_link_with_cloud_ipv4_default_and_private_save(self):
        result, output, reader, source = self.run_flow(["3", LINK, "1", "", "2"])
        self.assertEqual(result, 0)
        self.assertEqual(len(self.store.read()), 2)
        self.assertTrue(reader.prompts[1][1])
        self.assertEqual(set(source.calls), {cf.CF_V4, cf.WETEST_V4})
        joined = "\n".join(output)
        self.assertNotIn("候选", joined)
        self.assertNotIn("测速", joined)
        self.assertIn("优选链接", joined)
        self.assertIn("Quick 重建", joined)
        self.assertNotIn(USER, "\n".join(source.calls))

    @unittest.skipUnless(sys.platform == "linux", "requires a Linux controlling terminal")
    def test_real_terminal_selects_and_accepts_hidden_vless_with_redirected_stdin(self):
        """Exercise the real /dev/tty reader, which mock answers cannot cover."""
        import pty

        for redirected in (False, True):
            with self.subTest(redirected_stdin=redirected):
                script = (
                    "import sys\nfrom pathlib import Path\n"
                    f"sys.path[:0] = {[str(ROOT), str(ROOT / 'tests')]!r}\n"
                    "from test_cf_select import FakeSources\nimport cf_select\n"
                    f"raise SystemExit(cf_select.main([], store=cf_select.NodeStore(Path({str(self.home)!r})), sources=FakeSources()))\n"
                )
                sys.stdout.flush()
                sys.stderr.flush()
                pid, terminal = pty.fork()
                if pid == 0:
                    if redirected:
                        null = os.open(os.devnull, os.O_RDONLY)
                        os.dup2(null, 0)
                        os.close(null)
                    os.execve(sys.executable, [sys.executable, "-u", "-c", script],
                              {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                transcript, consumed, code = b"", 0, None
                answers = [("请选择：", "3"), ("粘贴 VLESS 链接（输入隐藏，0 取消）：", LINK),
                           ("请选择：", "3"), ("输入公网 IP（空格分隔，最多 30 个，0 取消）：", IP4)]
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([terminal], [], [], 0.1)
                        if ready:
                            try:
                                chunk = os.read(terminal, 8192)
                            except OSError as error:
                                if error.errno != errno.EIO:
                                    raise
                                break
                            if not chunk:
                                break
                            transcript += chunk
                            visible = transcript.decode("utf-8", errors="replace")
                            if answers and answers[0][0] in visible[consumed:]:
                                prompt, answer = answers.pop(0)
                                consumed = visible.index(prompt, consumed) + len(prompt)
                                os.write(terminal, answer.encode("utf-8") + b"\n")
                        if code is None:
                            done, status = os.waitpid(pid, os.WNOHANG)
                            if done:
                                code = os.waitstatus_to_exitcode(status)
                    if code is None:
                        done, status = os.waitpid(pid, os.WNOHANG)
                        if done:
                            code = os.waitstatus_to_exitcode(status)
                    visible = transcript.decode("utf-8", errors="replace")
                    self.assertEqual(code, 0, visible)
                    self.assertEqual(answers, [], visible)
                    self.assertNotIn("请在交互终端", visible)
                    self.assertIn("已保存 1 条优选链接", visible)
                    self.assertNotIn(USER, visible.split("节点模板：", 1)[0])
                    self.assertEqual(urllib.parse.urlsplit(self.store.read()[0]).hostname, IP4)
                finally:
                    if code is None:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(pid, 0)
                    os.close(terminal)

    def test_cloud_ipv6_official_ipv6_and_manual_dual_stack_work(self):
        cases = ((["3", LINK, "1", "2", "1"], 1), (["3", LINK, "2", "2", "3"], 3),
                 (["3", LINK, "3", IP4 + " " + IP6], 2))
        for answers, expected in cases:
            with self.subTest(answers=answers[-2:]):
                result, _, _, _ = self.run_flow(answers)
                self.assertEqual(result, 0)
                links = self.store.read()
                self.assertEqual(len(links), expected)
                self.assertTrue(any("@[" in link for link in links))

    def test_zero_cancels_each_stage_without_saving_or_network(self):
        for answers in (["0"], ["3", "0"], ["3", LINK, "0"], ["3", LINK, "1", "0"],
                        ["3", LINK, "1", "1", "0"], ["3", LINK, "3", "0"]):
            with self.subTest(stage=len(answers)):
                result, output, _, source = self.run_flow(answers)
                self.assertEqual(result, 0)
                self.assertEqual(source.calls, [])
                self.assertIsNone(self.store.read())
                self.assertIn("已取消", "\n".join(output))

    def test_local_domain_change_during_fetch_keeps_existing_export(self):
        self.store.write(self.links)
        template = cf.parse_vless(LINK)
        calls = []
        def loader(kind):
            calls.append(kind)
            return template, len(calls)
        result, output, _, _ = self.run_flow(["2", "3", IP4], local_loader=loader)
        self.assertEqual(result, 1)
        self.assertEqual(self.store.read(), self.links)
        self.assertIn("发生变化", "\n".join(output))
        self.assertEqual(calls, ["quick", "quick"])

    def test_show_last_does_not_request_network_or_rediscover_template(self):
        self.store.write(self.links)
        source, loader = mock.Mock(), mock.Mock()
        output = []
        self.assertEqual(cf.main(["--show-last"], output=output.append, store=self.store, sources=source, local_loader=loader), 0)
        self.assertEqual(source.mock_calls, [])
        self.assertEqual(loader.mock_calls, [])
        self.assertIn(self.links[0], output)
        self.assertIn("Quick 重建", "\n".join(output))

    def test_invalid_template_retry_and_huge_quantity_are_handled(self):
        result, output, _, _ = self.run_flow(["3", "PRIVATE_INVALID_LINK", "3", LINK, "2", "1", "9" * 5000, "1"])
        self.assertEqual(result, 0)
        self.assertNotIn("PRIVATE_INVALID_LINK", "\n".join(output))
        self.assertEqual(len(self.store.read()), 1)

    def test_help_needs_no_tty_network_or_home(self):
        with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as result:
            cf.main(["--help"], ask=lambda *_: self.fail("No terminal read"))
        self.assertEqual(result.exception.code, 0)
        self.assertIn("--show-last", output.getvalue())


if __name__ == "__main__":
    unittest.main()
