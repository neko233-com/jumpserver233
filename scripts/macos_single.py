#!/usr/bin/env python3
"""Native macOS CI and owned, persistent launchd deployment (stdlib only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import ipaddress
import socket
import plistlib
import re
import secrets
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'com.neko233.jumpserver233'
PNPM_VERSION = '12.9.1'


def environment():
    env = os.environ.copy()
    env['PATH'] = os.pathsep.join(['/opt/homebrew/bin', '/usr/local/bin', '/usr/local/go/bin', env.get('PATH', '')])
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def run(args, cwd=ROOT, capture=False, check=True, env=None):
    result = subprocess.run(args, cwd=cwd, env=env or environment(), text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if check and result.returncode:
        # Arguments and stderr may contain runtime configuration. Never echo them.
        raise RuntimeError(Path(args[0]).name + ' failed (exit ' + str(result.returncode) + ')')
    return result


def output(args, cwd=ROOT):
    return run(args, cwd, capture=True).stdout.strip()


def pnpm(*args):
    return run(['npm', 'exec', '--yes', '--package=pnpm@' + PNPM_VERSION, '--', 'pnpm', *args], ROOT / 'web')


def enabled(name):
    value = os.environ.get(name, 'true').lower()
    if value not in ('true', 'false'):
        raise RuntimeError(name + ' must be true or false')
    return value == 'true'


def preflight():
    if platform.system() != 'Darwin':
        raise RuntimeError('Jenkinsfile_mac_single requires a native macOS builtin executor')
    if __import__('sys').version_info < (3, 11):
        raise RuntimeError('Python >=3.11 is required')
    go = output(['go', 'version'])
    if not re.search(r'\bgo1\.27\.', go):
        raise RuntimeError('Go 1.27.x is required')
    node = output(['node', '--version'])
    major, minor = [int(p) for p in node.lstrip('v').split('.')[:2]]
    if major < 22 or major == 22 and minor < 12:
        raise RuntimeError('Node >=22.12 is required; Node 24 LTS is recommended')
    print(go + '; Node ' + node + '; pnpm ' + PNPM_VERSION, flush=True)
    pnpm('install', '--frozen-lockfile')
    run(['go', 'generate', './internal/agentbundle'], ROOT / 'server')


def verify():
    if not enabled('RUN_TESTS'):
        print('RUN_TESTS=false: tests omitted; production compilation still required', flush=True)
        return
    run(['python3', '-B', '-m', 'unittest', 'discover', '-s', 'scripts', '-p', 'macos_single_test.py'])
    run(['node', '--test', 'scripts/docker-qa.test.mjs', 'scripts/qa-lifecycle.test.mjs', 'scripts/qa-retention.test.mjs', 'scripts/publish-release.test.mjs', 'scripts/native-browser-logs.test.mjs', 'scripts/ci-cache.test.mjs',
         'server/testsupport/docker-qa.test.mjs', 'server/testsupport/ci-health.test.mjs'])
    run(['node', 'scripts/check-content.mjs'])
    run(['go', 'vet', './...', 'github.com/microsoft/go-mssqldb'], ROOT / 'server')
    run(['go', 'test', '-timeout', '20m', './...', 'github.com/microsoft/go-mssqldb'], ROOT / 'server')
    pnpm('lint')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def remove_tree(path, parent):
    """Remove only a real immediate child of this owned canonical parent."""
    if path.is_symlink() or path.parent.resolve() != parent.resolve():
        raise RuntimeError('Refusing cleanup outside the owned directory')
    if path.exists():
        shutil.rmtree(path)


def package():
    pnpm('build')
    staging = ROOT / 'dist/release'
    staging.parent.mkdir(exist_ok=True)
    remove_tree(staging, ROOT / 'dist')
    staging.mkdir(mode=0o700)
    env = environment()
    env['CGO_ENABLED'] = '0'
    for binary, source in [('jms233-server', './cmd/server'), ('jms', './cmd/jms')]:
        run(['go', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(staging / binary), source], ROOT / 'server', env=env)
    shutil.copytree(ROOT / 'web/dist', staging / 'web')
    version = output(['git', 'rev-parse', 'HEAD'])
    manifest = {'schemaVersion': 1, 'version': version, 'platform': 'darwin',
                'arch': platform.machine(), 'sha256': {str(p.relative_to(staging)): digest(p)
                for p in sorted(staging.rglob('*')) if p.is_file()}}
    (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    archive = ROOT / 'dist' / ('jumpserver233-darwin-' + platform.machine() + '.tar.gz')
    with tarfile.open(archive, 'w:gz') as target:
        for child in sorted(staging.iterdir()):
            target.add(child, arcname=child.name)
    archive.with_name(archive.name + '.sha256').write_text(digest(archive) + '  ' + archive.name + '\n', encoding='utf-8')
    print('Packaged commit ' + version + ': ' + archive.name, flush=True)


def validate_manifest(staging):
    if staging.is_symlink():
        raise RuntimeError('Staging must be a real directory')
    manifest = json.loads((staging / 'manifest.json').read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or manifest.get('schemaVersion') != 1 or manifest.get('platform') != 'darwin' or not isinstance(manifest.get('version'), str) or not re.fullmatch(r'[a-f0-9]{40,64}|v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', manifest['version']):
        raise RuntimeError('Unsupported deployment manifest')
    if manifest['version'].startswith('v') and not re.fullmatch(r'[a-f0-9]{40}', manifest.get('commit', '')):
        raise RuntimeError('Stable deployment requires the exact source commit')
    if manifest.get('arch') != platform.machine():
        raise RuntimeError('Artifact architecture does not match this node')
    hashes = manifest.get('sha256', {})
    if not isinstance(hashes, dict) or not {'jms233-server', 'jms', 'web/index.html'}.issubset(hashes):
        raise RuntimeError('Manifest is incomplete')
    actual = set()
    for entry in staging.rglob('*'):
        if entry.is_symlink():
            raise RuntimeError('Artifact symlinks are forbidden')
        if entry.is_file() and entry != staging / 'manifest.json':
            actual.add(entry.relative_to(staging).as_posix())
    if actual != set(hashes):
        raise RuntimeError('Artifact file set differs from manifest')
    for name, expected in hashes.items():
        source = staging / name
        if not source.resolve().is_relative_to(staging.resolve()) or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected) or digest(source) != expected:
            raise RuntimeError('Artifact integrity check failed')
    return manifest


def write_private(path, data):
    """Create private data before writing; atomically replace only our files."""
    temp = path.with_name(path.name + '.next')
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def runtime_config(root):
    path = root / 'runtime.json'
    if path.is_symlink():
        raise RuntimeError('Runtime configuration must not be a symlink')
    if not path.exists():
        write_private(path, json.dumps({'JMS_ADMIN_TOKEN': secrets.token_urlsafe(48)}).encode())
    path.chmod(0o600)
    config = json.loads(path.read_text(encoding='utf-8'))
    allowed = {'JMS_ADMIN_TOKEN', 'JMS_PUBLIC_URL', 'JMS_TRUSTED_PROXIES', 'JMS_MONITOR_INTERVAL', 'JMS_DEFAULT_ADMIN_ENABLED', 'JMS_SSH_ADDR', 'JMS_LOG_MAX_MB', 'JMS_LOG_BACKUPS', 'JMS_LOG_DAYS'}
    if not isinstance(config, dict) or set(config) - allowed or not all(isinstance(v, str) for v in config.values()):
        raise RuntimeError('Unsupported runtime configuration fields')
    if len(config.get('JMS_ADMIN_TOKEN', '')) < 32:
        raise RuntimeError('Runtime admin token must have at least 32 characters')
    return config


def native_ssh_port(config):
    address = config.get('JMS_SSH_ADDR', '')
    if not address:
        return None
    host, separator, port_text = address.rpartition(':')
    try:
        ipaddress.ip_address(host.removeprefix('[').removesuffix(']'))
        port = int(port_text)
        if not separator or not 1024 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise RuntimeError('JMS_SSH_ADDR requires a dedicated unprivileged IP listener') from None
    return port


def check_native_ssh(port):
    if port is None:
        return
    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
        connection.settimeout(5)
        banner = connection.recv(256)
        if not banner.startswith(b'SSH-2.0-JumpServer233'):
            raise RuntimeError('Native SSH listener identity differs')


def command(*args, check=True):
    return run(list(args), capture=True, check=check)


def listeners(port):
    result = command('/usr/sbin/lsof', '-t', '-nP', '-iTCP:' + str(port), '-sTCP:LISTEN', check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError('Cannot inspect listener ownership')
    return result.stdout.split()


def assert_owned_listener(port, previous):
    expected = str(previous / 'jms233-server') if previous else None
    pids = listeners(port)
    for pid in pids:
        mappings = command('/usr/sbin/lsof', '-a', '-p', pid, '-d', 'txt', '-Fn').stdout.splitlines()
        if not expected or 'n' + expected not in mappings:
            raise RuntimeError('Port is owned by another application; no service was stopped')
    return pids


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False


def wait_stopped(port, pids=()):
    deadline = time.monotonic() + 30
    while listeners(port) or any(process_alive(pid) for pid in pids):
        if time.monotonic() >= deadline:
            raise RuntimeError('Old service did not exit; refusing concurrent data writers')
        time.sleep(.25)


def check_health(port, version, timeout=45):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            base = 'http://127.0.0.1:' + str(port)
            with opener.open(base + '/api/health', timeout=2) as response:
                health = json.load(response)
            with opener.open(base + '/console/agent-audit', timeout=2) as response:
                html = response.read(1024 * 1024).decode('utf-8')
            try:
                opener.open(base + '/api/v1/users/me', timeout=2).close()
            except urllib.error.HTTPError as error:
                protected = error.code == 401
            else:
                protected = False
            if health.get('status') == 'ok' and health.get('version') == version and 'JumpServer233' in html and protected:
                return
        except (OSError, ValueError):
            pass
        time.sleep(.25)
    raise RuntimeError('Version, SPA route or authentication health check failed')


def switch_link(root, release):
    temp = root / 'current.next'
    if temp.exists() or temp.is_symlink():
        raise RuntimeError('Temporary activation path already exists')
    temp.symlink_to(release, target_is_directory=True)
    os.replace(temp, root / 'current')


def activate(staging, root, port, manifest, launch_dir=None):
    releases = root / 'releases'
    current = root / 'current'
    if (root / 'failed-data').exists():
        raise RuntimeError('Reconcile retained failed-data before another activation; running service was not stopped')
    if current.exists() and not current.is_symlink():
        raise RuntimeError('Current release must be an owned symlink')
    previous = current.resolve(strict=True) if current.is_symlink() else None
    if previous and (previous.parent != releases or previous.is_symlink()):
        raise RuntimeError('Current release is outside this deployment')
    config = runtime_config(root)
    ssh_port = native_ssh_port(config)
    if ssh_port is not None:
        if ssh_port == port:
            raise RuntimeError('Native SSH requires a port distinct from HTTP')
        assert_owned_listener(ssh_port, previous)
    domain = 'user/' + str(os.getuid())
    command('/bin/launchctl', 'print', domain)
    target = domain + '/' + LABEL
    launch_dir = launch_dir or Path.home() / 'Library/LaunchAgents'
    launch_dir.mkdir(parents=True, exist_ok=True)
    plist_path = launch_dir / (LABEL + '.plist')
    if plist_path.is_symlink():
        raise RuntimeError('LaunchAgent file must not be a symlink')
    old_plist = plist_path.read_bytes() if plist_path.exists() else None
    if old_plist:
        old = plistlib.loads(old_plist)
        if old.get('Label') != LABEL or old.get('ProgramArguments') != [str(current / 'jms233-server')]:
            raise RuntimeError('LaunchAgent belongs to another deployment')
        if old.get('EnvironmentVariables', {}).get('JMS_ADDR') != '0.0.0.0:' + str(port):
            raise RuntimeError('Changing an existing deployment port requires explicit service migration')
    old_pids = assert_owned_listener(port, previous)
    env = {**config, 'JMS_ADDR': '0.0.0.0:' + str(port), 'JMS_DATA_DIR': str(root / 'data'),
           'JMS_WEB_DIR': str(current / 'web'), 'JMS_VERSION': manifest['version'],
           'JMS_LOG_DIR': str(root / 'logs'), 'JMS_LOG_CONSOLE': 'false'}
    # Same immutable artifact + healthy process is a no-op: preserve PID, data and keys.
    if previous and old_plist and old.get('EnvironmentVariables') == env and (previous / 'manifest.json').read_bytes() == (staging / 'manifest.json').read_bytes():
        try:
            check_health(port, manifest['version'], timeout=2)
            check_native_ssh(ssh_port)
            print('Same artifact is healthy; activation is an idempotent no-op', flush=True)
            return {'version': manifest['version'], 'port': port, 'idempotent': True}
        except RuntimeError:
            pass
    release = releases / (manifest['version'][:12] + '-' + digest(staging / 'manifest.json')[:12])
    releases.mkdir(exist_ok=True)
    if release.exists():
        if validate_manifest(release) != manifest:
            raise RuntimeError('Existing immutable release differs')
    else:
        shutil.copytree(staging, release)
    for binary in ('jms233-server', 'jms'):
        (release / binary).chmod(0o755)
    for directory in ('data', 'logs', 'snapshots'):
        path = root / directory
        if path.is_symlink():
            raise RuntimeError('Persistent directories must not be symlinks')
        path.mkdir(exist_ok=True, mode=0o700)
        path.chmod(0o700)
    program = {'Label': LABEL, 'ProgramArguments': [str(current / 'jms233-server')],
               'EnvironmentVariables': env, 'WorkingDirectory': str(root),
               'LimitLoadToSessionType': 'Background', 'RunAtLoad': True,
               'KeepAlive': {'SuccessfulExit': False}, 'ThrottleInterval': 10, 'ExitTimeOut': 30,
               'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null'}
    command('/bin/launchctl', 'bootout', target, check=False)
    wait_stopped(port, old_pids)
    # Snapshot only after the old writer exits. Never mix old/new document writers.
    snapshot = root / 'snapshots' / str(time.time_ns())
    if previous:
        shutil.copytree(root / 'data', snapshot)
    try:
        switch_link(root, release)
        write_private(plist_path, plistlib.dumps(program))
        command('/usr/bin/plutil', '-lint', str(plist_path))
        command('/bin/launchctl', 'bootstrap', domain, str(plist_path))
        check_health(port, manifest['version'])
        check_native_ssh(ssh_port)
    except Exception:
        failed_pids = listeners(port)
        command('/bin/launchctl', 'bootout', target, check=False)
        wait_stopped(port, failed_pids)
        if previous and old_plist:
            # New binaries may have upgraded persisted schemas. Restore the stopped snapshot.
            failed_data = root / 'failed-data'
            if failed_data.exists():
                raise RuntimeError('Previous failed-data retained; manual recovery required')
            os.replace(root / 'data', failed_data)
            shutil.copytree(snapshot, root / 'data')
            switch_link(root, previous)
            write_private(plist_path, old_plist)
            command('/bin/launchctl', 'bootstrap', domain, str(plist_path))
            check_health(port, json.loads((previous / 'manifest.json').read_text())['version'])
            print('Activation failed; previous binary, data snapshot and health restored; failed-data retained for recovery', flush=True)
        else:
            current.unlink(missing_ok=True)
            plist_path.unlink(missing_ok=True)
        raise
    # Retain current and the preceding artifact, plus two stopped-data snapshots.
    for entry in releases.iterdir():
        if entry not in (release, previous):
            remove_tree(entry, releases)
    snapshots = sorted((root / 'snapshots').iterdir(), key=lambda p: p.name, reverse=True)
    for entry in snapshots[2:]:
        remove_tree(entry, root / 'snapshots')
    print('Deployed commit ' + manifest['version'] + ' on intranet port ' + str(port), flush=True)
    return {'version': manifest['version'], 'port': port, 'idempotent': False}


def deploy():
    if not enabled('DEPLOY'):
        print('DEPLOY=false: artifact retained without service changes', flush=True)
        return
    if platform.system() != 'Darwin':
        raise RuntimeError('Deployment requires macOS')
    port = int(os.environ.get('JMS_PORT', '8180'))
    if port < 1024 or port > 65535:
        raise RuntimeError('JMS_PORT must be an unprivileged TCP port')
    raw = Path(os.environ.get('JMS_DEPLOY_DIR', str(Path.home() / '.local/share/jumpserver233'))).expanduser()
    if not raw.is_absolute() or raw.is_symlink() or raw == Path.home() or len(raw.parts) < 4:
        raise RuntimeError('Deployment requires a dedicated absolute directory')
    root = raw.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    marker = root / '.jumpserver233'
    if not marker.exists():
        if any(root.iterdir()):
            raise RuntimeError('Refusing to adopt a non-empty unmanaged deployment directory')
        write_private(marker, b'jumpserver233-macos-single-v1\n')
    if marker.is_symlink() or marker.read_bytes() != b'jumpserver233-macos-single-v1\n':
        raise RuntimeError('Invalid deployment ownership marker')
    lock = root / 'deploy.lock'
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError('Deployment already locked; inspect the owning build before recovery') from None
    try:
        staging = ROOT / 'dist/release'
        manifest = validate_manifest(staging)
        ssh_text = os.environ.get('JMS_SSH_PORT')
        if ssh_text is not None:
            candidate = {'JMS_SSH_ADDR': '0.0.0.0:' + ssh_text}
            ssh_port = native_ssh_port(candidate)
            if ssh_port == port:
                raise RuntimeError('Native SSH and HTTP ports must differ')
            config = runtime_config(root)
            old_port = native_ssh_port(config)
            if old_port is not None and old_port != ssh_port:
                raise RuntimeError('Native SSH port migration requires an explicit service migration')
            config.update(candidate)
            write_private(root / 'runtime.json', json.dumps(config).encode())
        result = activate(staging, root, port, manifest)
        (ROOT / 'dist/deployment.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'verify', 'package', 'deploy'))
    args = parser.parse_args()
    globals()[args.action]()


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        print('macOS single-node action failed: ' + str(error), flush=True)
        raise SystemExit(1)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # No stack, command arguments, environment values or runtime secrets in CI logs.
        print('macOS single-node action failed (' + type(error).__name__ + '); check the last completed stage and owned service health', flush=True)
        raise SystemExit(1)
