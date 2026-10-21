#!/bin/sh
set -eu
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
for python_runtime in python3.13 python3.12 python3.11 python3; do
    if command -v "$python_runtime" >/dev/null 2>&1 && "$python_runtime" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
        exec "$python_runtime" -B scripts/macos_single.py "$@"
    fi
done
echo 'Python >=3.11 is required; no deployment was attempted.' >&2
exit 1
