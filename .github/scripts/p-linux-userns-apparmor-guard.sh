#!/usr/bin/env bash
# Owner-review proposal only.  This wrapper is intentionally limited to the
# non-production Linux Nix lane and restores the runner setting before exit.
set -u

readonly USERNS_SYSCTL_KEY='kernel.apparmor_restrict_unprivileged_userns'

fail_closed() {
  printf 'rs9 userns admission refused: %s\n' "$1" >&2
  exit 78
}

[[ "${GITHUB_ACTIONS-}" == 'true' ]] || fail_closed 'GITHUB_ACTIONS must be true'
[[ "${RUNNER_OS-}" == 'Linux' ]] || fail_closed 'RUNNER_OS must be Linux'
[[ "${RUNNER_ENVIRONMENT-}" == 'github-hosted' ]] || \
  fail_closed 'RUNNER_ENVIRONMENT must be github-hosted'
[[ "${GITHUB_REPOSITORY-}" == 'Knowledge-Forge-AI/theme-forge-packages' ]] || \
  fail_closed 'unexpected GITHUB_REPOSITORY'
[[ "${1-}" == '--' ]] || fail_closed 'expected -- followed by the unchanged lane command'
shift
(( $# > 0 )) || fail_closed 'lane command is missing'

command -v sysctl >/dev/null 2>&1 || fail_closed 'sysctl is unavailable'
command -v sudo >/dev/null 2>&1 || fail_closed 'sudo is unavailable'

original="$(sysctl -n "$USERNS_SYSCTL_KEY" 2>/dev/null)" || \
  fail_closed 'could not read the AppArmor userns sysctl'
case "$original" in
  0|1) ;;
  *) fail_closed 'AppArmor userns sysctl was missing or not exactly 0/1' ;;
esac

restore_original() {
  local observed
  observed="$(sysctl -n "$USERNS_SYSCTL_KEY" 2>/dev/null)" || {
    printf 'rs9 userns admission: restore preflight read failed\n' >&2
    return 1
  }
  [[ "$observed" == "$original" ]] && return 0
  if ! sudo -n sysctl -w "$USERNS_SYSCTL_KEY=$original" >/dev/null 2>&1; then
    printf 'rs9 userns admission: restore command failed\n' >&2
    return 1
  fi
  observed="$(sysctl -n "$USERNS_SYSCTL_KEY" 2>/dev/null)" || {
    printf 'rs9 userns admission: restore verification read failed\n' >&2
    return 1
  }
  if [[ "$observed" != "$original" ]]; then
    printf 'rs9 userns admission: restore verification did not recover %s\n' "$original" >&2
    return 1
  fi
  return 0
}

finish() {
  local command_status=$?
  local restore_status=0
  trap - EXIT INT TERM
  restore_original || restore_status=$?
  if (( restore_status == 0 )); then
    printf 'rs9 userns admission: restored=%s\n' "$original" >&2
  fi
  if (( restore_status != 0 && command_status == 0 )); then
    command_status=1
  fi
  exit "$command_status"
}

on_signal() {
  local signal_status=$1
  trap - INT TERM
  exit "$signal_status"
}

trap finish EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

if [[ "$original" == '1' ]]; then
  if ! sudo -n sysctl -w "$USERNS_SYSCTL_KEY=0" >/dev/null 2>&1; then
    printf 'rs9 userns admission: could not set temporary 0\n' >&2
    exit 1
  fi
  admitted="$(sysctl -n "$USERNS_SYSCTL_KEY" 2>/dev/null)" || {
    printf 'rs9 userns admission: admission verification read failed\n' >&2
    exit 1
  }
  [[ "$admitted" == '0' ]] || {
    printf 'rs9 userns admission: temporary 0 was not observed\n' >&2
    exit 1
  }
  printf 'rs9 userns admission: original=1 temporary=0\n' >&2
fi

"$@"
