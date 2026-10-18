"""Isolated deployment state-machine tests; no launchd, network or Docker changes."""
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import macos_single as ci


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jms233-macos-unit-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'owned'
        self.root.mkdir()
        self.staging = self.base / 'staging'
        self.staging.mkdir()
        self.launch = self.base / 'launch'
        self.make_artifact(self.staging, 'a' * 40)

    def make_artifact(self, directory, version):
        (directory / 'web').mkdir(exist_ok=True)
        for name in ('jms233-server', 'jms', 'web/index.html'):
            (directory / name).write_text('JumpServer233 ' + version, encoding='utf-8')
        manifest = {'schemaVersion': 1, 'version': version, 'platform': 'darwin',
                    'arch': platform.machine(), 'sha256': {p.relative_to(directory).as_posix(): ci.digest(p)
                    for p in directory.rglob('*') if p.is_file() and p.name != 'manifest.json'}}
        (directory / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        return manifest

    def activate(self, health=None):
        manifest = ci.validate_manifest(self.staging)
        with patch.object(ci, 'command') as command, patch.object(ci, 'listeners', return_value=[]), \
             patch.object(ci, 'check_health', side_effect=health) as check, \
             patch.object(os, 'getuid', return_value=123, create=True):
            result = ci.activate(self.staging, self.root, 8180, manifest, self.launch)
        return result, command, check

    def test_manifest_rejects_tamper_extra_and_path_escape(self):
        ci.validate_manifest(self.staging)
        server = self.staging / 'jms233-server'
        server.write_text('tampered')
        with self.assertRaisesRegex(RuntimeError, 'integrity'):
            ci.validate_manifest(self.staging)
        self.make_artifact(self.staging, 'a' * 40)
        (self.staging / 'unexpected').write_text('extra')
        with self.assertRaisesRegex(RuntimeError, 'file set'):
            ci.validate_manifest(self.staging)
        (self.staging / 'unexpected').unlink()
        manifest = json.loads((self.staging / 'manifest.json').read_text())
        manifest['sha256']['../escape'] = '0' * 64
        (self.staging / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(RuntimeError):
            ci.validate_manifest(self.staging)

    def test_private_runtime_key_is_stable_across_retries(self):
        first = ci.runtime_config(self.root)
        self.assertEqual(first, ci.runtime_config(self.root))
        self.assertGreaterEqual(len(first['JMS_ADMIN_TOKEN']), 32)
        if os.name != 'nt':
            self.assertEqual((self.root / 'runtime.json').stat().st_mode & 0o777, 0o600)

    def test_runtime_cannot_override_managed_paths(self):
        (self.root / 'runtime.json').write_text(json.dumps({'JMS_ADMIN_TOKEN': 'x' * 48, 'JMS_DATA_DIR': '/foreign'}))
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            ci.runtime_config(self.root)

    def test_foreign_listener_is_never_stopped(self):
        with patch.object(ci, 'listeners', return_value=['99']), patch.object(ci, 'command') as command:
            command.return_value = subprocess.CompletedProcess([], 0, 'n/foreign/server\n', '')
            with self.assertRaisesRegex(RuntimeError, 'another application'):
                ci.assert_owned_listener(8180, self.base / 'old')
            self.assertFalse(any('bootout' in c.args for c in command.call_args_list))

    def test_cleanup_is_confined_and_idempotent(self):
        child = self.root / 'owned-output'
        child.mkdir()
        ci.remove_tree(child, self.root)
        ci.remove_tree(child, self.root)
        with self.assertRaisesRegex(RuntimeError, 'Refusing'):
            ci.remove_tree(self.base / 'foreign', self.root)

    def test_activation_is_private_and_repeated_artifact_is_noop(self):
        try:
            result, _, _ = self.activate()
        except OSError as error:
            if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink privilege unavailable')
            raise
        self.assertFalse(result['idempotent'])
        key = (self.root / 'runtime.json').read_bytes()
        data = self.root / 'data/identity.json'
        data.write_text('preserve')
        result, commands, _ = self.activate()
        self.assertTrue(result['idempotent'])
        self.assertFalse(any('bootout' in call.args for call in commands.call_args_list))
        self.assertEqual(key, (self.root / 'runtime.json').read_bytes())
        self.assertEqual('preserve', data.read_text())
        plist = plistlib.loads((self.launch / (ci.LABEL + '.plist')).read_bytes())
        self.assertEqual(str(self.root / 'data'), plist['EnvironmentVariables']['JMS_DATA_DIR'])
        self.assertEqual('0.0.0.0:8180', plist['EnvironmentVariables']['JMS_ADDR'])

    def test_failed_upgrade_restores_previous_binary_data_and_health(self):
        try:
            self.activate()
        except OSError as error:
            if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink privilege unavailable')
            raise
        previous = (self.root / 'current').resolve()
        (self.root / 'data/identity.json').write_text('old-data')
        self.make_artifact(self.staging, 'b' * 40)
        checks = []

        def health(port, version, **kwargs):
            checks.append(version)
            if version == 'b' * 40:
                (self.root / 'data/identity.json').write_text('new-schema')
                raise RuntimeError('synthetic unhealthy release')

        with self.assertRaisesRegex(RuntimeError, 'synthetic unhealthy'):
            self.activate(health)
        self.assertEqual(previous, (self.root / 'current').resolve())
        self.assertEqual('old-data', (self.root / 'data/identity.json').read_text())
        self.assertEqual('new-schema', (self.root / 'failed-data/identity.json').read_text())
        self.assertEqual(['b' * 40, 'a' * 40], checks)

    def test_deploy_lock_is_released_after_invalid_manifest(self):
        repo = self.base / 'repo'
        (repo / 'dist/release').mkdir(parents=True)
        (repo / 'dist/release/manifest.json').write_text('{}')
        with patch.object(ci.platform, 'system', return_value='Darwin'), patch.object(ci, 'ROOT', repo), \
             patch.dict(os.environ, {'JMS_DEPLOY_DIR': str(self.root), 'JMS_PORT': '8180', 'DEPLOY': 'true'}):
            with self.assertRaises(RuntimeError):
                ci.deploy()
            self.assertFalse((self.root / 'deploy.lock').exists())
            with self.assertRaises(RuntimeError):
                ci.deploy()
            self.assertFalse((self.root / 'deploy.lock').exists())


if __name__ == '__main__':
    unittest.main()
