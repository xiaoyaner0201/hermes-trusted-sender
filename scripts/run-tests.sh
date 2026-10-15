#!/usr/bin/env bash
# Run plugin tests with a selected Hermes checkout's canonical test runner.
unset PYTHONPATH __HERMES_ACTIVATED
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ROOT="$SOURCE_ROOT"
MAIN_ROOT="${HERMES_ROOT:-}"
MODE=full
PROBE=""
usage() {
  printf 'Usage: %s --hermes-root <path> [--regressions-only|--e2e-only|--turn-context-only|--skeleton-only]\n' "$0" >&2
  printf 'HERMES_ROOT may supply the checkout; HERMES_PYTHON may override its .venv/bin/python.\n' >&2
  exit 2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --hermes-root|--plugin-root|--probe)
      [ "$#" -ge 2 ] && [ -n "$2" ] || usage
      case "$1" in
        --hermes-root) MAIN_ROOT="$2" ;;
        --plugin-root) PLUGIN_ROOT="$2" ;;
        --probe) MODE=probe; PROBE="$2" ;;
      esac
      shift 2 ;;
    --regressions-only) MODE=regressions; shift ;;
    --e2e-only) MODE=e2e; shift ;;
    --turn-context-only) MODE=turn_context; shift ;;
    --skeleton-only) MODE=skeleton; shift ;;
    --help|-h) usage ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage ;;
  esac
done
[ -n "$MAIN_ROOT" ] || usage
MAIN_ROOT="$(cd "$MAIN_ROOT" && pwd)"
PLUGIN_ROOT="$(cd "$PLUGIN_ROOT" && pwd)"
PYTHON="${HERMES_PYTHON:-$MAIN_ROOT/.venv/bin/python}"
if [ ! -x "$PYTHON" ] || [ ! -f "$MAIN_ROOT/scripts/run_tests.sh" ]; then
  printf 'A Hermes checkout with scripts/run_tests.sh and an executable Python is required.\n' >&2
  exit 2
fi
if [ -n "$(git -C "$MAIN_ROOT" status --porcelain)" ]; then
  printf 'Refusing to copy tests into a dirty Hermes checkout.\n' >&2
  exit 1
fi

NAMES=(test_zz_trusted_sender_plugin_integration.py)
SELECTED=()
case "$MODE" in
  full)
    NAMES+=(test_zz_trusted_sender_plugin_unit.py test_zz_trusted_sender_plugin_skeleton.py test_zz_trusted_sender_plugin_attribution.py test_zz_trusted_sender_plugin_turn_context.py test_zz_trusted_sender_plugin_e2e.py)
    SELECTED=("${NAMES[@]}") ;;
  regressions)
    NAMES+=(test_zz_trusted_sender_plugin_attribution.py)
    SELECTED=(test_zz_trusted_sender_plugin_attribution.py) ;;
  e2e)
    NAMES+=(test_zz_trusted_sender_plugin_e2e.py)
    SELECTED=(test_zz_trusted_sender_plugin_e2e.py) ;;
  turn_context)
    NAMES+=(test_zz_trusted_sender_plugin_turn_context.py test_zz_trusted_sender_plugin_attribution.py)
    SELECTED=(test_zz_trusted_sender_plugin_turn_context.py test_zz_trusted_sender_plugin_attribution.py) ;;
  skeleton)
    NAMES+=(test_zz_trusted_sender_plugin_skeleton.py)
    SELECTED=(test_zz_trusted_sender_plugin_skeleton.py) ;;
  probe)
    NAMES+=(test_zz_plugin_attribution_probe.py)
    SELECTED=(test_zz_plugin_attribution_probe.py) ;;
esac
TARGETS=()
for name in "${NAMES[@]}"; do
  target="$MAIN_ROOT/tests/gateway/$name"
  if [ -e "$target" ] || [ -L "$target" ]; then
    printf 'Refusing to overwrite existing test: %s\n' "$target" >&2
    exit 1
  fi
  TARGETS+=("$target")
done
cleanup() {
  local status=$?
  for target in "${TARGETS[@]}"; do rm -f "$target"; done
  local remaining
  remaining="$(git -C "$MAIN_ROOT" status --porcelain)"
  if [ -n "$remaining" ]; then
    printf 'Hermes checkout is dirty after cleanup:\n%s\n' "$remaining" >&2
    exit 1
  fi
  printf 'MAIN_CHECKOUT_CLEAN=true\n'
  exit "$status"
}
trap cleanup EXIT

for name in "${NAMES[@]}"; do
  source="$SOURCE_ROOT/tests/$name"
  if [ "$name" = test_zz_plugin_attribution_probe.py ]; then source="$PROBE"; fi
  # Core intentionally clears environment variables. Embed the selected plugin
  # path in the disposable tests instead of relying on a test-only env override.
  "$PYTHON" -c 'from pathlib import Path; import json, sys; p=Path(sys.argv[1]); Path(sys.argv[2]).write_text(p.read_text().replace(json.dumps("@TRUSTED_SENDER_PLUGIN_ROOT@"), json.dumps(sys.argv[3])))' \
    "$source" "$MAIN_ROOT/tests/gateway/$name" "$PLUGIN_ROOT"
done
PATHS=()
for name in "${SELECTED[@]}"; do PATHS+=("tests/gateway/$name"); done
HERMES_PYTHON="$PYTHON" "$MAIN_ROOT/scripts/run_tests.sh" "${PATHS[@]}" --file-retries 0 -s
