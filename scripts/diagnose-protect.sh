#!/usr/bin/env bash
set -euo pipefail
umask 077

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${project_dir}/.venv/bin/python"

if [[ ! -x "$python_bin" ]]; then
    printf '%s\n' 'Environnement absent. Depuis la racine du projet :' >&2
    printf '%s\n' 'python3 -m venv .venv' >&2
    printf '%s\n' '.venv/bin/python -m pip install -r requirements-diagnostics.txt' >&2
    exit 1
fi

cd -- "$project_dir"
exec "$python_bin" scripts/diagnose_protect.py "$@"