#!/usr/bin/env bash
# Run the intentional no-plugin RED control with Hermes' canonical test runner.
unset PYTHONPATH __HERMES_ACTIVATED
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN_ROOT="${HERMES_ROOT:-}"
usage() {
  printf 'Usage: %s --hermes-root <path>\n' "$0" >&2
  printf 'HERMES_ROOT may supply the checkout; HERMES_PYTHON may override its .venv/bin/python.\n' >&2
  exit 2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --hermes-root)
      [ "$#" -ge 2 ] && [ -n "$2" ] || usage
      MAIN_ROOT="$2"; shift 2 ;;
    --help|-h) usage ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage ;;
  esac
done
[ -n "$MAIN_ROOT" ] || usage
MAIN_ROOT="$(cd "$MAIN_ROOT" && pwd)"
PYTHON="${HERMES_PYTHON:-$MAIN_ROOT/.venv/bin/python}"
if [ ! -x "$PYTHON" ] || [ ! -f "$MAIN_ROOT/scripts/run_tests.sh" ]; then
  printf 'A Hermes checkout with scripts/run_tests.sh and an executable Python is required.\n' >&2
  exit 2
fi
if [ -n "$(git -C "$MAIN_ROOT" status --porcelain)" ]; then
  printf 'Refusing to copy tests into a dirty Hermes checkout.\n' >&2
  exit 1
fi
TARGET="$MAIN_ROOT/tests/gateway/test_zz_trusted_sender_plugin_red.py"
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
  printf 'Refusing to overwrite existing test: %s\n' "$TARGET" >&2
  exit 1
fi
cleanup() {
  local status=$?
  rm -f "$TARGET"
  local remaining
  remaining="$(git -C "$MAIN_ROOT" status --porcelain)"
  if [ -n "$remaining" ]; then
    printf 'Hermes checkout is dirty after RED-control cleanup:\n%s\n' "$remaining" >&2
    exit 1
  fi
  printf 'MAIN_CHECKOUT_CLEAN=true\n'
  exit "$status"
}
trap cleanup EXIT

cp "$PLUGIN_ROOT/tests/test_zz_trusted_sender_plugin_red.py" "$TARGET"
HERMES_PYTHON="$PYTHON" "$MAIN_ROOT/scripts/run_tests.sh" \
  tests/gateway/test_zz_trusted_sender_plugin_red.py --file-retries 0
