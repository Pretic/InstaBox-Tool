"""CF dependency preparation with offline package-manager and Python fixtures."""
import os
from pathlib import Path
import subprocess
import ssl
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = (ROOT / "ibt.sh").read_text().split('case "${1:-menu}" in', 1)[0]


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ibt-cf-deps-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.bin = self.home / "bin"
        self.bin.mkdir()
        self.script = self.home / "entry.sh"
        self.script.write_text(LIBRARY + '\ncf_nodes "$@"\n')
        (self.home / "cf_select.py").write_text("# fixture; never executed\n")
        self.mock("python3", '''
if [[ "${1:-}" == -c ]]; then [[ -e "$HOME/ready" ]]; exit; fi
printf '%s\\n' "$*" >> "$HOME/helper-actions"
''')
        self.mock("apt-get", '''
printf '%s\\n' "$*" >> "$HOME/package-actions"
if [[ "$*" == *' update '* ]]; then exit "${MOCK_UPDATE_RC:-0}"; fi
[[ "${MOCK_INSTALL_RC:-0}" == 0 ]] || exit "$MOCK_INSTALL_RC"
[[ "${MOCK_REMAINS_BROKEN:-0}" == 0 ]] && touch "$HOME/ready"
exit 0
''')
        self.mock("sudo", '''
[[ "${1:-}" != -n ]] || shift
[[ "${MOCK_SUDO_RC:-0}" == 0 ]] || exit "$MOCK_SUDO_RC"
exec "$@"
''')
        self.env = {**os.environ, "HOME": str(self.home), "PATH": str(self.bin) + ":" + os.environ["PATH"],
                    "IBT_NO_SUDO": "0", "PYTHONDONTWRITEBYTECODE": "1"}

    def mock(self, name, body):
        target = self.bin / name
        target.write_text("#!/usr/bin/env bash\n" + body)
        target.chmod(0o700)

    def run_cf(self, *args, **environment):
        return subprocess.run(["bash", str(self.script), *args], env={**self.env, **environment},
                              capture_output=True, text=True, timeout=5)

    def test_ready_runtime_never_calls_package_manager(self):
        (self.home / "ready").touch()
        result = self.run_cf("--show-last")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse((self.home / "package-actions").exists())
        self.assertTrue((self.home / "helper-actions").read_text().rstrip().endswith("--show-last"))

    def test_missing_runtime_installs_dependencies_then_starts_helper(self):
        result = self.run_cf()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual((self.home / "package-actions").read_text().splitlines(), [
            "-o DPkg::Lock::Timeout=30 update -qq",
            "-o DPkg::Lock::Timeout=30 install -y --no-install-recommends python3 ca-certificates"])
        self.assertTrue((self.home / "helper-actions").exists())

    def test_explicit_no_sudo_setting_prevents_installation(self):
        result = self.run_cf(IBT_NO_SUDO="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / "package-actions").exists())
        self.assertFalse((self.home / "helper-actions").exists())

    @unittest.skipIf(os.geteuid() == 0, "The non-root branch runs on the CI runner")
    def test_non_root_refused_sudo_does_not_install_or_start_helper(self):
        result = self.run_cf(MOCK_SUDO_RC="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / "package-actions").exists())
        self.assertFalse((self.home / "helper-actions").exists())

    def test_failed_preparation_does_not_start_helper(self):
        for environment in ({"MOCK_UPDATE_RC": "1"}, {"MOCK_INSTALL_RC": "1"}, {"MOCK_REMAINS_BROKEN": "1"}):
            with self.subTest(environment=environment):
                result = self.run_cf(**environment)
                self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertFalse((self.home / "helper-actions").exists())

    def test_missing_component_does_not_install_packages(self):
        (self.home / "cf_select.py").unlink()
        result = self.run_cf()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / "package-actions").exists())

    def real_readiness(self, *, populated, optimized=False):
        certificate_dir = self.home / "certificates"
        certificate_dir.mkdir(exist_ok=True)
        if populated:
            certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
            if not certificates:
                self.skipTest("No source CA certificate in this test environment")
            (certificate_dir / "01234567.0").write_text(ssl.DER_cert_to_PEM_cert(certificates[0]))
        self.script.write_text(LIBRARY + "\ncf_runtime_ready\n")
        environment = {**self.env, "PATH": os.environ["PATH"],
                       "SSL_CERT_FILE": str(self.home / "missing-ca.pem"),
                       "SSL_CERT_DIR": str(certificate_dir), "PYTHONOPTIMIZE": "1" if optimized else "0"}
        return subprocess.run(["bash", str(self.script)], env=environment, capture_output=True, text=True, timeout=5)

    def test_valid_lazy_ca_directory_is_ready_without_network_or_installation(self):
        result = self.real_readiness(populated=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse((self.home / "package-actions").exists())

    def test_empty_trust_store_is_not_ready_with_python_optimization(self):
        result = self.real_readiness(populated=False, optimized=True)
        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse((self.home / "package-actions").exists())


if __name__ == "__main__":
    unittest.main()
