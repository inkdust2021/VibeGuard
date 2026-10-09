#!/usr/bin/env python3
"""Isolated tests: all native service/keychain commands use fixture executables."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[1]


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vibeguard-uninstall-test-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.bin_dir = self.home / "custom bin"
        self.bin_dir.mkdir()
        self.bin = self.bin_dir / "vibeguard"
        shutil.copy2(BINARY, self.bin)
        self.cfg = self.home / ".vibeguard"
        self.cfg.mkdir()
        for name in ["config.yaml", "ca.crt", "ca.key", "vibeguard.log", "session.wal", "audit.db"]:
            (self.cfg / name).write_text("synthetic test data\n")
        self.rc = self.home / ".zshrc"
        self.rc.write_text('export USER_SETTING=keep\n# VibeGuard PATH\nexport PATH="test:$PATH"\nexport AFTER_PATH=keep\n# VibeGuard SHELL\nvibeguard() {\n  if true; then\n    :\n  fi\n}\nexport AFTER_HELPER=keep\n')
        self.plist = self.home / "Library/LaunchAgents/com.vibeguard.proxy.plist"
        self.plist.parent.mkdir(parents=True)
        self.plist.write_text("synthetic launch agent")
        self.stubs = self.home / "stubs"
        self.stubs.mkdir()
        self.stub("uname", "echo Darwin")
        self.stub("launchctl", 'if [ "$1" = print ]; then [ -f "$HOME/service-active" ]; else\n[ "${FAIL_SERVICE:-}" != 1 ] || exit 1\nrm -f "$HOME/service-active"\nfi')
        self.stub("lsof", "exit 0")
        self.stub("openssl", 'echo "sha256 Fingerprint=ABCDEF"')
        self.stub("sudo", '[ "$1" != -n ] || shift; exec "$@"')
        self.stub("security", '''case "$1" in
 find-certificate) [ "${FAIL_QUERY:-}" != 1 ] || exit 2
 [ ! -f "$HOME/trusted-ca" ] || echo 'SHA-256 hash: ABCDEF';;
 delete-certificate|remove-trusted-cert) [ "${FAIL_TRUST:-}" != 1 ] || exit 1
 rm -f "$HOME/trusted-ca";;
 esac''')
        (self.home / "service-active").touch()
        (self.home / "trusted-ca").touch()
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(self.stubs) + os.pathsep + os.environ["PATH"], VIBEGUARD_LANG="en")
        self.env.pop("VIBEGUARD_CONFIG", None)

    def stub(self, name, body):
        file = self.stubs / name
        file.write_text("#!/bin/sh\n" + body + "\n")
        file.chmod(0o755)

    def cli(self, *args, input=None, extra=None):
        return subprocess.run([str(self.bin), "uninstall", *args], input=input, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=dict(self.env, **(extra or {})), timeout=20)

    def assert_clean(self, purge):
        for path in [self.bin, self.plist, self.home / "trusted-ca", self.home / "service-active"]:
            self.assertFalse(path.exists(), str(path))
        self.assertEqual(self.cfg.exists(), not purge)
        self.assertEqual(self.rc.read_text(), "export USER_SETTING=keep\nexport AFTER_PATH=keep\nexport AFTER_HELPER=keep\n")

    def test_help(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0, result.stdout)
        for flag in ["--keep-config", "--purge", "--yes", "--non-interactive"]:
            self.assertIn(flag, result.stdout)
        self.assertTrue(self.bin.exists())

    def test_keep_config(self):
        result = self.cli("--keep-config", "--non-interactive")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_clean(False)
        self.assertTrue((self.cfg / "ca.key").exists())

    def test_purge(self):
        result = self.cli("--purge", "--yes", "--non-interactive")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_clean(True)

    def test_interactive_keep(self):
        result = self.cli(input="y\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_clean(False)

    def test_interactive_purge(self):
        result = self.cli(input="n\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_clean(True)

    def test_missing_choice_does_not_mutate(self):
        for flags in [("--non-interactive",), ("--yes",), ("--purge", "--non-interactive"), ("--purge", "--keep-config")]:
            with self.subTest(flags=flags):
                result = self.cli(*flags)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue(self.bin.exists())
                self.assertTrue(self.plist.exists())
                self.assertTrue((self.home / "trusted-ca").exists())

    def test_trust_failure_keeps_recovery_files(self):
        result = self.cli("--purge", "--yes", "--non-interactive", extra={"FAIL_TRUST": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.cfg / "ca.crt").exists())
        self.assertTrue(self.bin.exists())
        self.assertNotIn("Uninstall complete", result.stdout)

    def test_trust_query_failure_is_not_success(self):
        result = self.cli("--purge", "--yes", "--non-interactive", extra={"FAIL_QUERY": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.cfg / "ca.crt").exists())

    def test_failed_signal_leaves_program_and_config(self):
        self.stub("ps", 'echo vibeguard')
        (self.cfg / "vibeguard.pid").write_text("333333")
        script = (ROOT / "uninstall.sh").read_text().replace('set -euo pipefail', 'set -euo pipefail\nkill() { [ "$1" = -0 ]; }', 1)
        fixture = self.home / "uninstall-failed-signal.sh"
        fixture.write_text(script)
        result = subprocess.run(["bash", str(fixture), "--dir", str(self.bin_dir), "--purge", "--yes", "--non-interactive"],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.bin.exists())
        self.assertTrue(self.cfg.exists())

    def test_service_with_missing_plist_is_unloaded(self):
        self.plist.unlink()
        result = self.cli("--purge", "--yes", "--non-interactive")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_clean(True)

    def test_service_failure_is_not_success(self):
        result = self.cli("--purge", "--yes", "--non-interactive", extra={"FAIL_SERVICE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.plist.exists())
        self.assertTrue(self.bin.exists())

    def test_unrelated_pid_not_killed(self):
        proc = subprocess.Popen(["sleep", "30"])
        def cleanup():
            if proc.poll() is None:
                proc.terminate()
            proc.wait()
        self.addCleanup(cleanup)
        (self.cfg / "vibeguard.pid").write_text(str(proc.pid))
        result = self.cli("--purge", "--yes", "--non-interactive")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNone(proc.poll(), "Uninstaller killed an unrelated process")
        proc.terminate()
        proc.wait()

    def test_running_proxy_is_stopped(self):
        self.run_proxy_uninstall(False)

    def test_running_proxy_without_pid_or_lsof_is_stopped(self):
        self.run_proxy_uninstall(True)

    def run_proxy_uninstall(self, drop_pid):
        (self.cfg / "ca.crt").unlink()
        (self.cfg / "ca.key").unlink()
        (self.cfg / "config.yaml").write_text('proxy: {listen: "127.0.0.1:0"}\n')
        with (self.home / "proxy-output").open("w") as output:
            proc = subprocess.Popen([str(self.bin), "start", "--foreground"], env=self.env, stdout=output, stderr=output)
            waiter = threading.Thread(target=proc.wait)
            waiter.start()
            def cleanup():
                if proc.poll() is None:
                    proc.terminate()
                waiter.join(timeout=5)
            self.addCleanup(cleanup)
            pid_file = self.cfg / "vibeguard.pid"
            for _ in range(100):
                if pid_file.exists() and (self.cfg / "ca.crt").exists():
                    break
                if proc.poll() is not None:
                    self.fail((self.home / "proxy-output").read_text())
                time.sleep(0.05)
            self.assertTrue(pid_file.exists())
            if drop_pid:
                pid_file.unlink()
                self.stub("lsof", "exit 127")
            result = self.cli("--purge", "--yes", "--non-interactive")
            self.assertEqual(result.returncode, 0, result.stdout)
            waiter.join(timeout=5)
            self.assertIsNotNone(proc.poll(), "Proxy still running after uninstall")
            self.assert_clean(True)

    def test_stale_pid_cannot_stop_uninstaller_itself(self):
        proc = subprocess.Popen([str(self.bin), "uninstall"], env=self.env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (self.cfg / "vibeguard.pid").write_text(str(proc.pid))
        output, _ = proc.communicate("n\n", timeout=20)
        self.assertEqual(proc.returncode, 0, output)
        self.assert_clean(True)

    def test_binary_deletion_failure_is_reported(self):
        self.stub("rm", '''for arg in "$@"; do
case "$arg" in */vibeguard) echo "Synthetic permission failure" >&2; exit 1;; esac
done
exec /bin/rm "$@"''')
        result = self.cli("--purge", "--yes", "--non-interactive")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.bin.exists())
        self.assertTrue((self.cfg / "ca.key").exists())
        self.assertNotIn("Uninstall complete", result.stdout)

    def test_invalid_or_missing_interactive_answer_does_not_mutate(self):
        for answer in ["", "maybe\n", "\n"]:
            with self.subTest(answer=answer):
                result = self.cli(input=answer)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue(self.bin.exists())
                self.assertTrue(self.plist.exists())

    def test_linux_without_user_service_manager(self):
        self.stub("uname", "echo Linux")
        self.stub("systemctl", "exit 1")
        self.stub("ps", "exit 0")
        self.stub("update-ca-certificates", "exit 0")
        script = (ROOT / "uninstall.sh").read_text()
        for system_dir in ["/usr/local/share/ca-certificates", "/etc/ssl/certs", "/etc/pki/ca-trust/source/anchors"]:
            script = script.replace(system_dir, str(self.home / "trust"))
        fixture = self.home / "uninstall-no-user-manager.sh"
        fixture.write_text(script)
        result = subprocess.run(["bash", str(fixture), "--dir", str(self.bin_dir), "--purge", "--yes", "--non-interactive"],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.bin.exists())
        self.assertFalse(self.cfg.exists())

    def test_linux_service_and_trust_cleanup(self):
        self.stub("uname", "echo Linux")
        self.stub("systemctl", '''[ "${FAIL_SERVICE:-}" != 1 ] || exit 1
if [ "$2" = show ]; then
  if [ -f "$HOME/service-active" ]; then echo loaded; else echo not-found; fi
else rm -f "$HOME/service-active"; fi''')
        self.stub("update-ca-certificates", '[ "${FAIL_REFRESH:-}" != 1 ]')
        unit = self.home / ".config/systemd/user/vibeguard.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("synthetic unit")
        # Redirect only system trust-store paths in the script fixture, never touch host trust.
        script = (ROOT / "uninstall.sh").read_text()
        trust_path = self.home / "trust/vibeguard-ca.crt"
        trust_path.parent.mkdir()
        trust_path.write_text("synthetic installed CA")
        for system_dir in ["/usr/local/share/ca-certificates", "/etc/ssl/certs", "/etc/pki/ca-trust/source/anchors"]:
            script = script.replace(system_dir, str(trust_path.parent))
        fixture = self.home / "uninstall-linux.sh"
        fixture.write_text(script)
        command = ["bash", str(fixture), "--dir", str(self.bin_dir), "--purge", "--yes", "--non-interactive"]
        result = subprocess.run(command, env=dict(self.env, FAIL_REFRESH="1"), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.bin.exists())
        self.assertTrue(self.cfg.exists())
        # The unit file is already gone, but systemd may still cache its registration.
        (self.home / "service-active").touch()
        link = unit.parent / "default.target.wants/vibeguard.service"
        link.parent.mkdir()
        link.symlink_to(unit)
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(link.is_symlink(), "Enabled service symlink remains")
        for path in [unit, trust_path, self.bin, self.cfg, self.home / "service-active"]:
            self.assertFalse(path.exists(), str(path))

    def test_script_repeat_and_preflight(self):
        command = ["bash", str(ROOT / "uninstall.sh"), "--dir", str(self.bin_dir)]
        result = subprocess.run(command + ["--purge", "--non-interactive"], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.plist.exists(), "Destructive work occurred before validation")
        for _ in range(2):
            result = subprocess.run(command + ["--purge", "--yes", "--non-interactive"], env=self.env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
