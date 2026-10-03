#!/usr/bin/env bash
# Static inspection only: never execute the payload or enter bubblewrap.
# Bash 3.2 and later; explicitly check producers rather than relying on errexit.
set -euo pipefail
export LC_ALL=C

fail() { echo "FHS closure check: $*" >&2; exit 1; }

installed=
fhs_root=
required=()
required_count=0
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] && [ -n "$2" ] || fail "missing option value"
  case "$1" in
    --installed) installed=$2 ;;
    --fhs-root) fhs_root=$2 ;;
    --require) required[required_count]=$2; required_count=$((required_count + 1)) ;;
    *) fail "unknown option: $1" ;;
  esac
  shift 2
done
[ -d "$installed" ] && [ -d "$fhs_root" ] || fail "installed tree and FHS root are required"
[ "$required_count" -ge 2 ] || fail "at least two mandatory ELF paths are required"
installed=${installed%/}
fhs_root=$(cd "$fhs_root" && pwd -P) || fail "cannot resolve FHS root"
case "$installed" in /*) ;; *) fail "installed tree must be absolute" ;; esac

work=$(mktemp -d) || fail "cannot create inspection scratch"
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM

# Resolve as the FHS runtime does. Absolute usrmerge links stay in the root;
# /nix/store links use the host store, which buildFHSEnv binds into the runtime.
resolve_in_root() {
  local pending=$1 resolved='' component target hops=0 candidate
  case "$pending" in /*) pending=${pending#/} ;; *) return 1 ;; esac
  while [ -n "$pending" ]; do
    case "$pending" in
      */*) component=${pending%%/*}; pending=${pending#*/} ;;
      *) component=$pending; pending= ;;
    esac
    case "$component" in
      ''|.) continue ;;
      ..) resolved=${resolved%/*}; continue ;;
    esac
    candidate="$fhs_root$resolved/$component"
    if [ -L "$candidate" ]; then
      hops=$((hops + 1))
      [ "$hops" -le 40 ] || return 1
      target=$(readlink "$candidate") || return 1
      [ -n "$target" ] || return 1
      case "$target" in
        /nix/store/*)
          # Host-side test follows any remaining store symlinks; a dangling
          # target or loop is rejected by the caller's existence/mode check.
          printf '%s\n' "$target${pending:+/$pending}" || return 1
          return 0 ;;
        /*) resolved=; pending="${target#/}${pending:+/$pending}" ;;
        *) pending="$target${pending:+/$pending}" ;;
      esac
    else
      [ -e "$candidate" ] || return 1
      resolved="$resolved/$component"
    fi
  done
  printf '%s\n' "$fhs_root$resolved" || return 1
}

for mandatory in "${required[@]}"; do
  case "$mandatory" in "$installed"/*) ;; *) fail "mandatory ELF outside installed tree: $mandatory" ;; esac
  case "/${mandatory#/}/" in */../*|*/./*) fail "non-canonical mandatory ELF path: $mandatory" ;; esac
  [ -f "$mandatory" ] && [ ! -L "$mandatory" ] || fail "mandatory ELF must be a regular non-symlink file: $mandatory"
done

find "$installed" -type f -print0 > "$work/candidates" || fail "enumeration failed"
[ -s "$work/candidates" ] || fail "no files enumerated"
inspected=0
required_seen=0
while IFS= read -r -d '' elf; do
  magic=$(od -An -N4 -tx1 "$elf" | tr -d '[:space:]') || fail "ELF magic inspection failed: $elf"
  [ "$magic" = 7f454c46 ] || continue
  readelf -h "$elf" > "$work/header" || fail "ELF header inspection failed: $elf"
  readelf -l "$elf" > "$work/program" || fail "ELF program inspection failed: $elf"
  readelf -d "$elf" > "$work/dynamic" || fail "dynamic-section inspection failed: $elf"

  dynamic_count=$(awk '$1 == "DYNAMIC" { n++ } END { print n+0 }' "$work/program") || fail "DYNAMIC parsing failed"
  interp_count=$(awk '$1 == "INTERP" { n++ } END { print n+0 }' "$work/program") || fail "INTERP parsing failed"
  section_count=$(awk '/Dynamic section/ { n++ } END { print n+0 }' "$work/dynamic") || fail "dynamic-section parsing failed"
  [ "$dynamic_count" -eq 0 ] || [ "$section_count" -gt 0 ] || fail "missing dynamic section: $elf"
  needed_records=$(awk 'index($0, "(NEEDED)") { n++ } END { print n+0 }' "$work/dynamic") || fail "DT_NEEDED counting failed"
  sed -n 's/.*(NEEDED).*Shared library: \[\([^][]*\)\][[:space:]]*$/\1/p' "$work/dynamic" > "$work/needed" || fail "DT_NEEDED parsing failed"
  needed_count=$(wc -l < "$work/needed") || fail "DT_NEEDED parsed count failed"
  [ "$needed_records" -eq "$needed_count" ] || fail "unparsed DT_NEEDED entry: $elf"
  while IFS= read -r needed; do
    case "$needed" in ''|*/*|.|..) fail "invalid DT_NEEDED entry: $elf" ;; esac
    target=$(resolve_in_root "/usr/lib64/$needed") || fail "Unresolved FHS dependency: $needed ($elf)"
    [ -f "$target" ] || fail "Unresolved FHS dependency: $needed ($elf)"
  done < "$work/needed"

  sed -n 's/^[[:space:]]*\[Requesting program interpreter: \([^][]*\)\][[:space:]]*$/\1/p' "$work/program" > "$work/interpreters" || fail "interpreter extraction failed: $elf"
  parsed_interp_count=$(wc -l < "$work/interpreters") || fail "interpreter count failed"
  [ "$interp_count" -eq "$parsed_interp_count" ] && [ "$interp_count" -le 1 ] || fail "unparsed PT_INTERP entry: $elf"
  while IFS= read -r interpreter; do
    target=$(resolve_in_root "$interpreter") || fail "Unresolved FHS interpreter: $interpreter ($elf)"
    [ -f "$target" ] && [ -x "$target" ] || fail "Unresolved FHS interpreter: $interpreter ($elf)"
  done < "$work/interpreters"

  inspected=$((inspected + 1))
  for mandatory in "${required[@]}"; do
    if [ "$elf" = "$mandatory" ]; then
      [ "$dynamic_count" -eq 1 ] && [ "$interp_count" -eq 1 ] && [ "$needed_count" -gt 0 ] || fail "mandatory ELF lacks DYNAMIC, INTERP or DT_NEEDED: $elf"
      required_seen=$((required_seen + 1))
      printf '%s\n' "$elf" >> "$work/required-seen" || fail "cannot record mandatory inspection"
    fi
  done
done < "$work/candidates"
[ "$inspected" -gt 0 ] || fail "no ELF files inspected"
for mandatory in "${required[@]}"; do
  [ -f "$work/required-seen" ] || fail "mandatory ELF not inspected: $mandatory"
  grep -qxF -- "$mandatory" "$work/required-seen" || fail "mandatory ELF not inspected: $mandatory"
done
unique_required=$(sort -u "$work/required-seen" | wc -l) || fail "mandatory inspection count failed"
[ "$unique_required" -eq "$required_count" ] && [ "$required_seen" -eq "$required_count" ] && [ "$inspected" -ge "$required_count" ] || fail "mandatory ELF set must contain distinct inspected paths"
printf 'inspected %s ELF files; verified %s mandatory paths\n' "$inspected" "$required_count"
