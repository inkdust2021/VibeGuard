#!/usr/bin/env python3
"""Real Docker deployment tests. Only UUID-named test resources may be removed."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import uuid

if len(sys.argv) < 3:
    raise SystemExit("usage: test-uninstall-docker.py CLI_BINARY TEST_IMAGE")
sys.dont_write_bytecode = True
IMAGE = sys.argv.pop(2)
spec = importlib.util.spec_from_file_location("uninstall_fixtures", Path(__file__).with_name("test-uninstall.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)  # Consumes CLI_BINARY; reuses isolated HOME/trust/service fixtures.


class DockerDeploymentTests(unittest.TestCase):
    def docker(self, *args, check=True):
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def setUp(self):
        self.fixture = fixtures.UninstallTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        suffix = uuid.uuid4().hex
        self.container = "vibeguard-uninstall-test-" + suffix
        self.volume = "vibeguard-uninstall-test-data-" + suffix
        self.sentinel = "vibeguard-uninstall-test-sentinel-" + suffix
        self.docker("info")
        # Register cleanup before creation so a failed setup also leaves no test resources.
        self.addCleanup(lambda: self.docker("volume", "rm", self.volume, check=False))
        self.addCleanup(lambda: self.docker("rm", "-f", self.container, check=False))
        self.addCleanup(lambda: self.docker("rm", "-f", self.sentinel, check=False))
        self.docker("volume", "create", self.volume)
        self.docker("run", "-d", "--name", self.sentinel, "--entrypoint", "sh", IMAGE, "-c", "sleep 300")
        self.docker("run", "-d", "--name", self.container, "--restart", "unless-stopped", "-v",
                    self.volume + ":/root/.vibeguard", IMAGE)
        ready = False
        for _ in range(60):
            result = self.docker("exec", self.container, "sh", "-c", "test -s /root/.vibeguard/ca.crt", check=False)
            if result.returncode == 0:
                ready = True
                break
            time.sleep(0.25)
        self.assertTrue(ready, self.docker("logs", self.container, check=False).stdout)
        self.password_record = '{"version":1,"bcrypt_hash":"synthetic-test-hash","created_at":"2026-01-01T00:00:00Z"}'
        self.docker("exec", self.container, "sh", "-c",
                    'printf "%s" "$1" > /root/.vibeguard/admin_auth.json; printf "%s" "synthetic WAL" > /root/.vibeguard/session.wal',
                    "fixture", self.password_record)
        # Rebind ONLY the two fixed resource identifiers in this fixture copy.
        # Do not touch a developer's actual vibeguard / vibeguard-data deployment.
        script = (fixtures.ROOT / "uninstall.sh").read_text()
        for original, replacement in [
            ('local container_name="vibeguard"', 'local container_name="' + self.container + '"'),
            ('local volume_name="vibeguard-data"', 'local volume_name="' + self.volume + '"'),
        ]:
            self.assertEqual(script.count(original), 1)
            script = script.replace(original, replacement)
        self.script = self.fixture.home / "uninstall-docker-fixture.sh"
        self.script.write_text(script)
        self.env = dict(self.fixture.env)
        self.env["DOCKER_CONFIG"] = os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))

    def uninstall(self, purge):
        flags = ["--docker", "--yes", "--non-interactive"]
        flags += ["--docker-volume", "--purge"] if purge else ["--keep-config"]
        result = subprocess.run(["bash", str(self.script), "--dir", str(self.fixture.bin_dir), *flags],
                                env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.docker("inspect", self.container, check=False).returncode, 1)
        self.assertEqual(self.docker("inspect", self.sentinel).returncode, 0)
        self.assertEqual(self.fixture.cfg.exists(), not purge)
        self.assertFalse(self.fixture.bin.exists())
        self.assertFalse(self.fixture.plist.exists())
        self.assertFalse((self.fixture.home / "trusted-ca").exists())
        self.assertNotIn("# VibeGuard", self.fixture.rc.read_text())

    def test_keep_docker_configuration_and_password(self):
        self.uninstall(False)
        self.docker("volume", "inspect", self.volume)
        probe = self.docker("run", "--rm", "--entrypoint", "sh", "-v", self.volume + ":/data:ro", IMAGE, "-c",
                            'test -s /data/config.yaml && test -s /data/ca.crt && test -s /data/ca.key && test -s /data/vibeguard.log && test -s /data/session.wal && cat /data/admin_auth.json')
        self.assertEqual(probe.stdout, self.password_record)
        self.uninstall(False)  # Repeated cleanup keeps the retained data intact.

    def test_purge_docker_configuration_and_password(self):
        self.uninstall(True)
        self.assertNotEqual(self.docker("volume", "inspect", self.volume, check=False).returncode, 0)
        self.uninstall(True)  # Already-removed container and volume are benign.


if __name__ == "__main__":
    unittest.main(verbosity=2)
