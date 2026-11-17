#!/usr/bin/env bash
# Read-only prerequisites report. Does not install, open ports or change permissions.
set -euo pipefail
printf 'Home MCP phase-3 prerequisite report (not a security/integration pass)\n'
uname -srm
command -v systemctl >/dev/null || { echo 'systemd required'; exit 1; }
python3 -B - <<'PY'
import ctypes, sys
print('Python:', sys.version.split()[0])
if sys.version_info < (3, 11):
    raise SystemExit('Python 3.11+ required')
ctypes.CDLL('libseccomp.so.2')
print('libseccomp: found')
PY
command -v bwrap >/dev/null || { echo 'bubblewrap required'; exit 1; }
bwrap --version
bwrap --help | grep -- '--disable-userns' >/dev/null || { echo 'bubblewrap --disable-userns required'; exit 1; }
bwrap --help | grep -- '--assert-userns-disabled' >/dev/null || { echo 'bubblewrap --assert-userns-disabled required'; exit 1; }
test -e /sys/fs/cgroup/cgroup.controllers || { echo 'cgroup v2 required'; exit 1; }
if command -v bpftool >/dev/null; then bpftool version; else echo 'bpftool missing: approved network jobs unavailable'; fi
printf '\nCurrent TCP listeners (existing HTTPS proxy must remain):\n'
if command -v ss >/dev/null; then ss -ltn | awk 'NR==1 || $4 ~ /:(80|443|18790|18791)$/'; fi
printf '\nWorkspace: /mnt/storage/dev\nCheckout: /mnt/storage/dev/server\n'
printf 'This report does not execute a sandbox or test ChatGPT pairing.\n'
printf 'Install: sudo bash scripts/install.sh\nAfter install: sudo home-mcp verify --public\n'
