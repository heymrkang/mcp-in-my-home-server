#!/usr/bin/env bash
# Read-only prerequisites report. Does not install, open ports or change permissions.
set -euo pipefail
printf 'Home MCP prerequisite report (not a security/integration pass)\n'
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
bwrap --help | grep -q -- '--disable-userns' || { echo 'bubblewrap --disable-userns required'; exit 1; }
printf '\nCurrent TCP listeners (do not replace an existing HTTPS proxy):\n'
if command -v ss >/dev/null; then
    ss -ltn | awk 'NR==1 || $4 ~ /:(80|443|18790)$/'
fi
printf '\nExpected persistent workspace: /mnt/storage/dev\nSource checkout: /mnt/storage/dev/server\n'
printf 'Final install and actual namespace checks belong to phase 3.\n'
