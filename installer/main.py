"""Install/update only Home MCP, explicitly invoked by the local administrator.
Source commit, wheel hashes, relay digest and the previous release are recorded.
Database contents and remote effects are NEVER rolled back with source code.
"""
from __future__ import annotations
import argparse
import fcntl
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import grp
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import uuid
from .common import ROOT, ETC, STATE, SOURCE, WORKSPACE, REPOSITORY, MARKER, ENV
from .common import InstallError, need, run, no_links, root_owned, directory, write, write_json, read_json, link
from . import dependencies, proxy

CORE = ['home-mcp.service', 'home-mcp-owner.service', 'home-mcp-runner.service', 'home-mcp-broker.service']
SOCKETS = ['home-mcp-runner.socket', 'home-mcp-broker.socket']
BRIDGES = ['home-mcp-http-gateway.socket', 'home-mcp-http-owner.socket', 'home-mcp-http-gateway.service', 'home-mcp-http-owner.service']
BOOT_UNITS = SOCKETS + ['home-mcp.service', 'home-mcp-owner.service'] + [name for name in BRIDGES if name.endswith('.socket')]
CURRENT, PENDING = STATE / 'current.json', STATE / 'pending.json'
DEFAULT_ORIGIN = 'https://k9m2x7p4vq3b8z1.12190529.xyz'
WRAPPER = '#!/bin/sh\n' + MARKER + 'exec /usr/bin/python3 -B /opt/home-mcp/app/scripts/manage.py "$@"\n'


def git(*args, capture=True):
    # Never run checkout hooks, custom diff commands or configured fsmonitors as root.
    return run(['/usr/bin/git', '-c', f'safe.directory={SOURCE}', '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false', '-c', 'credential.helper=', '-c', 'http.sslVerify=true',
                '-C', SOURCE, *args], capture=capture, timeout=180)


def snapshot(release, reference):
    no_links(SOURCE)
    need((SOURCE / '.git').is_dir() and not (SOURCE / '.git').is_symlink(), 'Clone into /mnt/storage/dev/server first')
    sha = git('rev-parse', '--verify', reference + '^{commit}').strip()
    need(re.fullmatch(r'[a-f0-9]{40}', sha), 'Invalid source commit')
    command = ['/usr/bin/git', '-c', f'safe.directory={SOURCE}', '-c', 'core.hooksPath=/dev/null',
               '-c', 'core.fsmonitor=false', '-C', str(SOURCE), 'archive', '--format=tar', sha]
    result = subprocess.run(command, env=ENV, cwd='/', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    need(result.returncode == 0 and len(result.stdout) <= 64 * 1024 * 1024, 'Source archive unavailable or too large')
    app = release / 'app'; app.mkdir(mode=0o755)
    total, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and '..' not in path.parts and member.name not in seen, 'Unsafe source archive path')
            need(not any(part in {'.git', '.gitignore'} for part in path.parts), 'Git metadata/ignore file not deployed')
            seen.add(member.name)
            target = app.joinpath(*path.parts)
            need(member.isdir() or member.isfile(), 'Source links/devices are not installed')
            if member.isdir(): target.mkdir(mode=0o755, parents=True, exist_ok=True); continue
            total += member.size
            need(0 <= member.size <= 4 * 1024 * 1024 and total <= 32 * 1024 * 1024, 'Source file limit exceeded')
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with archive.extractfile(member) as data: write(target, data.read(), 0o755 if member.mode & 0o111 else 0o644)
    for name in ['homemcp/server.py', 'homemcp/broker.py', 'installer/main.py', 'scripts/manage.py', 'requirements.txt']:
        need((app / name).is_file(), 'Commit does not contain the complete phase-3 installer')
    return sha


def preflight(install_packages=False):
    need(sys.version_info >= (3, 11), 'Python 3.11+ required; installer does not replace system Python')
    need(sys.platform == 'linux' and Path('/run/systemd/system').is_dir(), 'Run on the systemd host, not inside a Coolify app container')
    for path in [ROOT, ETC, STATE]:
        if path.exists(): root_owned(path, directory=True)
    if install_packages:
        need(Path('/etc/debian_version').exists() and shutil.which('apt-get'), 'Automatic packages support Debian/Ubuntu only; use documented prerequisites and --no-packages elsewhere')
        run(['apt-get', 'update'], timeout=600)
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'python3-venv', 'git', 'bubblewrap', 'libseccomp2', 'ca-certificates', 'acl'], timeout=900)
        # Do not install a kernel or disable security settings to obtain bpftool.
        if not shutil.which('bpftool'):
            for package in ['bpftool', 'linux-tools-' + os.uname().release]:
                if not re.fullmatch(r'[A-Za-z0-9.+_-]+', package): continue
                found = run(['apt-cache', 'show', package], capture=True, check=False)
                if found.returncode == 0 and found.stdout.strip():
                    run(['apt-get', 'install', '-y', '--no-install-recommends', package], timeout=600)
                    break
    for binary in ['systemctl', 'systemd-run', 'runuser', 'git', 'bwrap', 'setfacl']:
        need(shutil.which(binary), f'Missing prerequisite: {binary}')
    help_text = run(['bwrap', '--help'], capture=True)
    need('--disable-userns' in help_text and '--assert-userns-disabled' in help_text, 'bubblewrap lacks required namespace restrictions')
    need(Path('/sys/fs/cgroup/cgroup.controllers').exists(), 'Unified cgroup v2 is required')
    if not shutil.which('bpftool'):
        print('NOTE: bpftool missing. Offline tools may run; approved network jobs remain unavailable. Install the OS-matching package.')


def accounts():
    nologin = next((name for name in ['/usr/sbin/nologin', '/sbin/nologin'] if Path(name).exists()), None)
    need(nologin, 'nologin binary missing')
    names = ['home-mcp', 'home-mcp-runner', 'home-mcp-owner', 'home-mcp-proxy']
    for name in [*names, 'home-mcp-control']:
        try: grp.getgrnam(name)
        except KeyError: run(['groupadd', '--system', name])
    for name in names:
        try: account = pwd.getpwnam(name)
        except KeyError:
            run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', nologin, '--gid', name, name])
            account = pwd.getpwnam(name)
        need(account.pw_uid != 0 and account.pw_gid == grp.getgrnam(name).gr_gid
             and account.pw_shell in {'/usr/sbin/nologin', '/sbin/nologin', '/bin/false'}, f'Unsafe existing service account: {name}')
        extra = [group.gr_name for group in grp.getgrall() if name in group.gr_mem and group.gr_gid != account.pw_gid]
        allowed = {'home-mcp-control'} if name in {'home-mcp', 'home-mcp-owner'} else set()
        need(set(extra) <= allowed, f'Unexpected groups on {name}; do not grant docker/sudo')
    need(len({pwd.getpwnam(name).pw_uid for name in names}) == len(names), 'Service UIDs must differ')
    # Only gateway/owner receive the control group, never runner/proxy.
    for name in ['home-mcp', 'home-mcp-owner']: run(['usermod', '-a', '-G', 'home-mcp-control', name])


def workspace():
    no_links(WORKSPACE); no_links(SOURCE)
    need(SOURCE.is_dir(), 'Source checkout missing')
    # Grant on this directory only. Do not recursively chown existing projects or other storage.
    run(['setfacl', '-m', 'u:home-mcp-runner:rwx', WORKSPACE])
    for parent in list(WORKSPACE.parents)[:-1]:
        if not os.stat(parent).st_mode & 0o001:
            print(f'NOTE: runner traversal may need a local ACL on {parent}; parent permissions were not broadened.')


def configurations(app, origin):
    for name in ['config.json', 'phase2.json']:
        target = ETC / name
        if target.exists(): root_owned(target); continue
        value = json.loads((app / 'config' / name.replace('.json', '.example.json')).read_text())
        if name == 'config.json': value['public_origin'] = origin
        if name == 'phase2.json': value['egress_hosts'] = []
        write_json(target, value, 0o644)
    actual = read_json(ETC / 'config.json')
    need(actual['public_origin'] == origin, 'Origin differs from saved policy; redeployment cannot silently change OAuth origin')
    code = 'from homemcp.config import load_config; from homemcp.phase2_policy import load_policy; c=load_config(); p=load_policy(); assert c.port != p["owner_port"]'
    run(['/usr/bin/python3', '-B', '-c', code], cwd=app)
    return {'gateway': actual['listen_port'], 'owner': read_json(ETC / 'phase2.json')['owner_port']}


def prepare_units(release):
    units = release / 'units'; units.mkdir(mode=0o755)
    for name in [*CORE, *SOCKETS]: write(units / name, MARKER + (release / 'app/deploy' / name).read_text(), 0o644)


def unit_files(release):
    allowed = set(CORE + SOCKETS + BRIDGES)
    for path in (Path(release) / 'units').iterdir():
        need(path.name in allowed, 'Unexpected unit in release')
        yield path


def install_units(release):
    for source in unit_files(release):
        target = Path('/etc/systemd/system') / source.name
        if target.exists() or target.is_symlink():
            root_owned(target)
            need(target.read_text().startswith(MARKER), f'Unmanaged unit exists: {target}; review it instead of overwriting')
        write(target, source.read_text(), 0o644)
    run(['systemctl', 'daemon-reload'])


def stop_services(state):
    if state: proxy.stop(state['release'], state['proxy'])
    # Stop sockets together with consumers; no new request should reactivate a worker.
    run(['systemctl', 'stop', *CORE, *SOCKETS, *BRIDGES], check=False, capture=True)
    active = run(['systemctl', 'is-active', *CORE], capture=True, check=False).stdout.decode().split()
    need(not any(value in {'active', 'activating', 'deactivating'} for value in active), 'Home MCP services did not stop; source was not swapped')


def disable_first_install():
    run(['systemctl', 'disable', *BOOT_UNITS], check=False, capture=True)


def local_verify(state):
    run(['/usr/bin/python3', '-B', '-m', 'installer.verify', '--local'], cwd=Path(state['release']) / 'app', timeout=120)


def start_services(state):
    run(['systemctl', 'enable', '--now', *SOCKETS, 'home-mcp.service', 'home-mcp-owner.service'])
    run(['systemctl', 'start', 'home-mcp-runner.service', 'home-mcp-broker.service'])
    local_verify(state)
    proxy.start(state['release'], state['proxy'])


def activate(state):
    release = Path(state['release']); root_owned(release, directory=True)
    link(ROOT / 'app', release / 'app'); link(ROOT / 'venv', release / 'venv')
    install_units(release); start_services(state)


def confirm(args, action):
    print(action)
    print('Only Home MCP services are stopped. Active Home MCP jobs may be interrupted; remote effects and databases are NOT rolled back.')
    if not args.yes:
        need(sys.stdin.isatty(), 'Use a terminal, or --yes after reading docs/PHASE3.md')
        need(input('Type yes to continue: ').strip() == 'yes', 'Cancelled without activation')


def bootstrap(app, python):
    # A restrictive installer umask can leave /var/lib/home-mcp at 0700.
    # The gateway must traverse this parent, while private/ remains 0700.
    base = Path('/var/lib/home-mcp')
    root_owned(base, directory=True)
    os.chmod(base, 0o711)
    owner = base / 'private/owner.json'
    if owner.exists(): need(not owner.is_symlink() and owner.stat().st_nlink == 1, 'Existing credentials unsafe')
    else: run([python, '-B', '-m', 'homemcp.bootstrap'], cwd=app)
    run([python, '-B', '-m', 'homemcp.bootstrap_phase2'], cwd=app)


def deploy(args):
    previous = read_json(CURRENT) if CURRENT.exists() else None
    need(not PENDING.exists(), 'Interrupted installation: run home-mcp rollback (or scripts/manage.py rollback) before retry')
    need(args.command != 'update' or previous, 'Not installed; use install')
    need(args.command != 'install' or previous is None, 'Already installed; use update or rollback')
    origin = args.origin or (previous['origin'] if previous else DEFAULT_ORIGIN)
    proxy.valid_origin(origin)
    need(not previous or previous['origin'] == origin, 'Updates preserve the public origin')
    wrapper = Path('/usr/local/sbin/home-mcp')
    if wrapper.exists() or wrapper.is_symlink():
        root_owned(wrapper); need(wrapper.read_text() == WRAPPER, 'Unmanaged /usr/local/sbin/home-mcp exists')
    confirm(args, 'Install/update Home MCP from a committed snapshot; preserve credentials, policies and workspace.')
    preflight(install_packages=not args.no_packages and previous is None)
    reference = args.ref or 'HEAD'
    if args.command == 'update' and not args.offline:
        need(not args.ref, 'Use --offline with an explicitly reviewed --ref SHA')
        # Git authentication, when needed, stays in the local terminal, not MCP parameters.
        git('fetch', '--no-tags', REPOSITORY, 'main', capture=False); reference = 'FETCH_HEAD'
    if args.ref: need(re.fullmatch(r'[a-f0-9]{40}', args.ref), '--ref requires a full commit SHA')
    directory(ROOT); directory(ROOT / 'releases'); directory(ETC)
    release = directory(ROOT / 'releases' / (time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]))
    sha = snapshot(release, reference)
    print(f'Preparing commit {sha}')
    accounts(); workspace(); directory(ROOT / 'empty')
    ports = configurations(release / 'app', origin)
    if previous is None:
        for port in ports.values():
            with socket.socket() as probe:
                try: probe.bind(('127.0.0.1', port))
                except OSError: raise InstallError(f'Loopback port {port} already in use; identify its owner first') from None
    prior_proxy = previous['proxy'] if previous else None
    mode = args.proxy or (prior_proxy['mode'] if prior_proxy else 'traefik')
    need(not previous or mode == prior_proxy['mode'], 'Updates do not switch proxy types')
    if mode == 'traefik':
        need(shutil.which('docker'), 'Existing Docker/Coolify required; installer will not replace Docker')
        run(['docker', 'compose', 'version'], capture=True)
        info = json.loads(run(['docker', 'info', '--format', '{{json .SecurityOptions}}'], capture=True))
        need(not any('rootless' in item or 'userns' in item for item in info), 'UNIX bridge requires rootful Docker without UID remapping; review host proxy integration instead')
        options = proxy.inspect_proxy(args.proxy_container or (prior_proxy or {}).get('container', 'coolify-proxy'),
            args.network or (prior_proxy or {}).get('network'), args.https_entrypoint or (prior_proxy or {}).get('entrypoint'), args.tls_resolver or (prior_proxy or {}).get('resolver'))
        proxy.check_conflicts(proxy.valid_origin(origin))
        options['image'] = proxy.resolve_image(prior_proxy, args.refresh_image)
    else: options = {'mode': 'host'}
    bundle = dependencies.build(release, release / 'app/requirements.txt', previous, args.refresh_dependencies)
    prepare_units(release); proxy.prepare(release, origin, options, ports)
    for unit in unit_files(release):
        target = Path('/etc/systemd/system') / unit.name
        if target.exists() or target.is_symlink():
            root_owned(target); need(target.read_text().startswith(MARKER), f'Unmanaged unit requires review: {target}')
    state = {'version': 1, 'commit': sha, 'release': str(release), 'origin': origin,
             'dependency_bundle': bundle, 'proxy': options, 'previous': {**previous, 'previous': None} if previous else None,
             'installed_at': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    write_json(release / 'release.json', {**state, 'previous': None}, 0o644)
    write_json(PENDING, {'previous': previous, 'candidate': state})
    write(wrapper, WRAPPER, 0o755)
    try:
        stop_services(previous)
        link(ROOT / 'app', release / 'app'); link(ROOT / 'venv', release / 'venv')
        bootstrap(release / 'app', release / 'venv/bin/python')
        install_units(release); start_services(state)
        write_json(CURRENT, state); PENDING.unlink()
    except BaseException:
        print('Activation failed; stopping only the candidate Home MCP runtime.')
        try: stop_services(state)
        except Exception: pass
        if previous:
            try:
                activate(previous); write_json(CURRENT, previous); PENDING.unlink()
                print('Previous code restored. Authentication/workspace/database contents were not restored or deleted.')
            except Exception:
                print('Code rollback also failed. Pending record retained; run rollback and inspect Home MCP journals locally.')
        else:
            disable_first_install()
            print('First install stopped and boot activation disabled. Run rollback to clear the interrupted activation, then retry. Keep generated credentials.')
        raise
    print(f'Local activation checked: {sha}. Public DNS/TLS and ChatGPT pairing are NOT yet verified.')
    print(f'MCP: {origin}/mcp\nApproval: {origin}/approval/\nNext: sudo home-mcp verify --public')
    print('Read setup-credentials.json and phase2-setup-credentials.json under /var/lib/home-mcp ONLY locally.')


def rollback(args):
    pending = read_json(PENDING) if PENDING.exists() else None
    current = read_json(CURRENT) if CURRENT.exists() else None
    old = pending['previous'] if pending else (current or {}).get('previous')
    candidate = pending['candidate'] if pending else current
    need(candidate, 'No managed deployment to roll back')
    need(pending or old, 'No earlier release retained for rollback')
    confirm(args, 'Roll back Home MCP CODE only; database contents and remote effects are not undone.')
    stop_services(candidate)
    if old: activate(old); write_json(CURRENT, old)
    else:
        disable_first_install()
        print('No previous release. Services remain stopped; credentials/policy preserved for install retry.')
    if PENDING.exists(): PENDING.unlink()


def policy_apply(args):
    current = read_json(CURRENT)
    need(not PENDING.exists(), 'Resolve interrupted installation before changing policy')
    candidate = root_owned(args.file)
    need(candidate != ETC / 'phase2.json', 'Use a separate reviewed candidate, for example /root/home-mcp-policy.json')
    need(candidate.stat().st_size <= 32768, 'Policy file too large')
    code = 'import sys; from homemcp.phase2_policy import load_policy; load_policy(sys.argv[1])'
    run(['/usr/bin/python3', '-B', '-c', code, candidate], cwd=ROOT / 'app')
    value = json.loads(candidate.read_text())
    need(value['owner_port'] == read_json(ETC / 'phase2.json')['owner_port'], 'Approval-port changes require regenerating proxy configuration')
    if value['egress_hosts']: need(shutil.which('bpftool'), 'Install OS-matching bpftool before enabling network targets')
    for container_id in value['docker_targets']:
        row = json.loads(run(['docker', 'inspect', container_id], capture=True))[0]; name = row.get('Name', '').lower()
        need(not (row.get('Config', {}).get('Labels') or {}).get(proxy.MANAGED)
             and not any(x in name for x in ['home-mcp', 'coolify', 'agent-hub']), 'Self-management/Coolify/Agent Hub targets excluded')
    confirm(args, 'Apply the reviewed policy; this command executes no target operation.')
    old = (ETC / 'phase2.json').read_bytes(); stop_services(current)
    try: write(ETC / 'phase2.json', candidate.read_bytes(), 0o644); start_services(current)
    except BaseException:
        write(ETC / 'phase2.json', old, 0o644); start_services(current); raise


def main():
    parser = argparse.ArgumentParser(description='Local Home MCP operator; not an MCP tool')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ['install', 'update']:
        child = sub.add_parser(name)
        child.add_argument('--origin'); child.add_argument('--ref'); child.add_argument('--offline', action='store_true')
        child.add_argument('--yes', action='store_true'); child.add_argument('--no-packages', action='store_true')
        child.add_argument('--proxy', choices=['traefik', 'host']); child.add_argument('--proxy-container')
        child.add_argument('--network'); child.add_argument('--https-entrypoint'); child.add_argument('--tls-resolver')
        child.add_argument('--refresh-image', action='store_true'); child.add_argument('--refresh-dependencies', action='store_true')
    child = sub.add_parser('rollback'); child.add_argument('--yes', action='store_true')
    child = sub.add_parser('policy'); child.add_argument('file'); child.add_argument('--yes', action='store_true')
    child = sub.add_parser('verify'); child.add_argument('--public', action='store_true')
    sub.add_parser('status'); sub.add_parser('preflight')
    args = parser.parse_args()
    try:
        need(os.geteuid() == 0, 'Use sudo on the home server, not inside a container')
        # Runtime source/venv must be traversable by service UIDs. All secret/state
        # files have explicit 0600/0700 modes; bootstrap processes set umask 0077.
        os.umask(0o022); os.chdir('/')
        directory(STATE, 0o700)
        descriptor = os.open(STATE / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as lock:
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise InstallError('Another Home MCP management command is running') from None
            if args.command in {'install', 'update'}: deploy(args)
            elif args.command == 'rollback': rollback(args)
            elif args.command == 'policy': policy_apply(args)
            elif args.command == 'preflight': preflight()
            elif args.command == 'status':
                if CURRENT.exists():
                    state = read_json(CURRENT); print(json.dumps({key: state[key] for key in ['commit', 'origin', 'release', 'proxy']}, indent=2))
                else: print('Not installed')
                if PENDING.exists(): print('INTERRUPTED_ACTIVATION: local rollback required')
            elif args.command == 'verify':
                from .verify import verify
                need(verify(public=args.public), 'Checks failed; installation is not verified')
    except (InstallError, OSError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f'Home MCP: {error if isinstance(error, InstallError) else type(error).__name__}.', file=sys.stderr)
        raise SystemExit(1)
