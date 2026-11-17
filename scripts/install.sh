#!/bin/sh
set -eu
# Run a reviewed checkout, not curl | sudo sh. Installer modifies only Home MCP.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/python3 -B "$HERE/scripts/manage.py" install "$@"
