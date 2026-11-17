"""Root-only installer helpers; no shell interpolation or secret-bearing logs."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ROOT = Path('/opt/home-mcp')
ETC = Path('/etc/home-mcp')
STATE = Path('/var/lib/home-mcp-installer')
SOURCE = Path('/mnt/storage/dev/server')
WORKSPACE = SOURCE.parent
REPOSITORY = 'https://github.com/heymrkang/mcp-in-my-home-server.git'
MARKER = '# Managed by home-mcp phase-3 installer\n'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME': '/root', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
       'GIT_NO_REPLACE_OBJECTS': '1', 'DOCKER_HOST': 'unix:///var/run/docker.sock',
       'NEEDRESTART_MODE': 'l'}

class InstallError(Exception):
    pass

def need(value, message):
    if not value:
        raise InstallError(message)

def run(argv, *, capture=False, check=True, timeout=120, cwd='/', input=None):
    result = subprocess.run([str(x) for x in argv], cwd=str(cwd), env=ENV,
                            input=input, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None, timeout=timeout)
    if check and result.returncode:
        # Do not echo argv/body/stderr: Git and package tools may have credentials.
        raise InstallError(f'{Path(str(argv[0])).name} failed (exit {result.returncode}). Check its local output; do not post secrets.')
    return result.stdout.decode('utf-8') if capture and check else result

def no_links(path):
    path = Path(os.path.abspath(path))
    for item in (*reversed(path.parents), path):
        if item.exists() or item.is_symlink():
            need(not item.is_symlink(), f'Symlink rejected: {item}')
    return path

def root_owned(path, *, directory=False):
    path = no_links(path)
    for item in (path, *path.parents):
        info = item.stat()
        need(info.st_uid == 0 and not info.st_mode & 0o022, f'Administrator ownership required: {item}')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), f'Unexpected file type: {path}')
    if not directory:
        need(info.st_nlink == 1, f'Hardlink rejected: {path}')
    return path

def directory(path, mode=0o755):
    path = no_links(path)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    root_owned(path, directory=True)
    os.chmod(path, mode)
    return path

def write(path, content, mode=0o600):
    path = Path(path)
    root_owned(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        root_owned(path)
    data = content.encode() if isinstance(content, str) else content
    descriptor, temporary = tempfile.mkstemp(prefix='.home-mcp-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def write_json(path, value, mode=0o600):
    write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', mode)

def read_json(path):
    root_owned(path)
    need(Path(path).stat().st_size <= 1024 * 1024, 'Installer metadata too large')
    return json.loads(Path(path).read_text())

def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        while block := source.read(1024 * 1024): digest.update(block)
    return digest.hexdigest()

def link(path, target):
    path, target = Path(path), Path(target)
    root_owned(path.parent, directory=True)
    root_owned(target, directory=True)
    need(target.is_relative_to(ROOT / 'releases'), 'Release target outside installation')
    if path.exists() or path.is_symlink():
        need(path.is_symlink() and Path(os.path.realpath(path)).is_relative_to(ROOT / 'releases'), f'Unmanaged installation path: {path}')
    temporary = path.with_name(path.name + '.switch')
    need(not temporary.exists() and not temporary.is_symlink(), f'Stale switch file: {temporary}')
    temporary.symlink_to(target)
    os.replace(temporary, path)

def label(value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', value), 'Invalid proxy identifier')
    return value
