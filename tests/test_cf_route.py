"""Cloudflare route prompts with a real terminal and a piped API token."""

import errno
import os
from pathlib import Path
import select
import signal
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "0123456789ABCDEF0123456789ABCDEF"
TUNNEL = "01234567-89AB-CDEF-0123-456789ABCDEF"
TOKEN = "FAKE_CLOUDFLARE_TOKEN_FOR_LOCAL_TEST_ONLY"


@unittest.skipUnless(sys.platform == "linux", "requires a Linux controlling terminal")
class ManualRouteInputTests(unittest.TestCase):
    def test_manual_account_and_tunnel_with_piped_token(self):
        """Match bind-auto: stdin carries the token; IDs come from /dev/tty."""
        import pty

        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "import cf_route\n"
            "cf_route.ids_from_cloudflared_token = lambda: (None, None)\n"
            "def verify_route(domain, port, token, account, tunnel, backup):\n"
            "    assert domain == 'node.example.com' and port == 20000\n"
            f"    assert token == {TOKEN!r}\n"
            f"    assert account == {ACCOUNT.lower()!r}\n"
            f"    assert tunnel == {TUNNEL.lower()!r}\n"
            "    print('INPUT_OK', flush=True)\n"
            "cf_route.add_route = verify_route\n"
            "sys.argv = ['cf_route.py', '--domain', 'node.example.com', '--backup-dir', '/unused']\n"
            "raise SystemExit(cf_route.main())\n"
        )
        token_reader, token_writer = os.pipe()
        os.write(token_writer, (TOKEN + "\n").encode())
        os.close(token_writer)
        sys.stdout.flush()
        sys.stderr.flush()
        pid, terminal = pty.fork()
        if pid == 0:
            os.dup2(token_reader, 0)
            os.close(token_reader)
            os.execve(sys.executable, [sys.executable, "-u", "-c", script],
                      {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        os.close(token_reader)
        transcript, consumed, code = b"", 0, None
        answers = [("  输入 Account ID（32 位十六进制）： ", ACCOUNT),
                   ("  输入 Tunnel UUID（带连字符）： ", TUNNEL)]
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
                        os.write(terminal, (answer + "\n").encode())
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
            self.assertIn("INPUT_OK", visible)
            self.assertNotIn(TOKEN, visible)
        finally:
            if code is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            os.close(terminal)


if __name__ == "__main__":
    unittest.main()
