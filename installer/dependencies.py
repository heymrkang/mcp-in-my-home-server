"""Resolve wheels once, lock every resolved distribution/hash, reuse on update.

The initial resolve is explicitly platform-specific. This is not a pre-tested,
repository-wide lock. No source distributions or package build hooks are used.
"""
from __future__ import annotations
from email.parser import BytesParser
import json
from pathlib import Path
import platform
import re
import sys
import zipfile
from .common import need, run, sha256, write, write_json, read_json, root_owned


def platform_key():
    return {'python': list(sys.version_info[:2]), 'machine': platform.machine(), 'system': platform.system()}

def lock_wheels(folder):
    rows, names = [], set()
    for path in sorted(Path(folder).iterdir()):
        need(path.suffix == '.whl' and path.is_file() and not path.is_symlink(), 'Only wheels may enter the dependency bundle')
        with zipfile.ZipFile(path) as archive:
            candidates = [x for x in archive.infolist() if x.filename.endswith('.dist-info/METADATA')]
            need(len(candidates) == 1 and candidates[0].file_size <= 1024 * 1024, 'Invalid wheel metadata')
            metadata = BytesParser().parsebytes(archive.read(candidates[0]))
        name, version = metadata.get('Name', ''), metadata.get('Version', '')
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) and re.fullmatch(r'[A-Za-z0-9.!+_-]+', version), 'Invalid dependency name/version')
        canonical = re.sub(r'[-_.]+', '-', name).lower()
        need(canonical not in names, 'Duplicate distribution in dependency bundle')
        names.add(canonical)
        rows.append({'name': canonical, 'version': version, 'file': path.name, 'sha256': sha256(path)})
    need(rows and 'mcp' in names, 'MCP wheel missing')
    return rows

def build(release, requirements, previous=None, refresh=False):
    release, requirements = Path(release), Path(requirements)
    venv = release / 'venv'
    run(['/usr/bin/python3', '-B', '-m', 'venv', venv], timeout=120)
    python = venv / 'bin/python'
    signature = sha256(requirements)
    old = None
    if previous and not refresh:
        bundle = Path(previous['dependency_bundle'])
        root_owned(bundle, directory=True)
        old = read_json(bundle / 'manifest.json')
        need(old['platform'] == platform_key(), 'Python/platform changed; use update --refresh-dependencies after review')
        need(old['requirements_sha256'] == signature, 'Requirements changed; use update --refresh-dependencies after review')
        for row in old['wheels']:
            need(Path(row['file']).name == row['file'], 'Invalid wheel filename')
            wheel = root_owned(bundle / 'wheels' / row['file'])
            need(sha256(wheel) == row['sha256'], 'Cached wheel hash mismatch')
        need(sha256(bundle / 'requirements.lock') == old['lock_sha256'], 'Dependency lock changed')
    else:
        bundle = release / 'dependencies'; bundle.mkdir(mode=0o755)
        wheels = bundle / 'wheels'; wheels.mkdir(mode=0o755)
        run([python, '-I', '-B', '-m', 'pip', '--isolated', 'download', '--disable-pip-version-check',
             '--no-cache-dir', '--only-binary=:all:', '--index-url', 'https://pypi.org/simple',
             '--dest', wheels, '-r', requirements], timeout=900)
        rows = lock_wheels(wheels)
        lock = ''.join(f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}\n" for row in rows)
        write(bundle / 'requirements.lock', lock, 0o644)
        write_json(bundle / 'manifest.json', {'platform': platform_key(), 'requirements_sha256': signature,
                   'lock_sha256': sha256(bundle / 'requirements.lock'), 'wheels': rows}, 0o644)
    run([python, '-I', '-B', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
         '--no-cache-dir', '--no-index', '--only-binary=:all:', '--require-hashes',
         '--find-links', bundle / 'wheels', '-r', bundle / 'requirements.lock'], timeout=900)
    return str(bundle)
