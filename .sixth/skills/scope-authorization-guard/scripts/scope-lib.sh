#!/usr/bin/env bash
# scope-lib.sh — single source of truth for reading scope.yaml and gating a
# target through scope-authorization-guard.
#
# This file is SOURCED by every networked harness script so the safety-critical
# scope parser exists in exactly ONE place (no copy-paste drift). It defines two
# functions and runs nothing on its own.
#
#   scope_list  <section> [scope_file]
#       Print one in/out-of-scope entry per line. <section> is in_scope or
#       out_of_scope. Collects every "- value" list item nested anywhere under
#       that top-level key (domains:, urls:, ip_ranges:, mobile_apps:, …).
#
#   scope_guard <target> [scope_file] [guard_mjs]
#       Return 0 IFF check-scope.mjs says <target> is ALLOWED. Returns non-zero
#       (and prints a reason to stderr) on block, empty in_scope, or any error.
#
# Robustness goals (it gates the protection of gitlab.com, so it must not
# silently drop entries):
#   * tolerant of TAB or SPACE indentation,
#   * case-insensitive on the section header,
#   * strips inline "# comments" and surrounding single/double quotes,
#   * default-safe: an unreadable/empty scope file yields NO allowed entries.
#
# scope_file/guard default to the caller's $SCOPE_FILE/$GUARD when omitted.

# ---------------------------------------------------------------------------
# scope_list <section> [scope_file]
# ---------------------------------------------------------------------------
scope_list() {
  local section="$1" file="${2:-${SCOPE_FILE:-}}"
  if [ -z "$section" ]; then
    printf 'scope_list: missing section argument\n' >&2; return 2
  fi
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    printf 'scope_list: scope file not found: %s\n' "${file:-<unset>}" >&2; return 2
  fi
  awk -v sec="$section" '
    # A top-level key (no leading whitespace, not a comment) ending in ":".
    # Toggling on these makes us collect list items ONLY inside the wanted block.
    /^[^[:space:]#].*:[[:space:]]*(#.*)?$/ {
      key = $0
      sub(/:.*/, "", key)
      gsub(/[[:space:]]/, "", key)
      inblk = (tolower(key) == tolower(sec)) ? 1 : 0
      next
    }
    inblk {
      line = $0
      sub(/#.*/, "", line)                       # strip trailing comment
      if (line ~ /^[[:space:]]*-[[:space:]]*/) {  # list item (tab or space ok)
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        gsub(/[\047"[:space:]]/, "", line)        # drop quotes (\047 = single) + ws
        if (line != "") print line
      }
    }
  ' "$file"
}

# ---------------------------------------------------------------------------
# scope_guard <target> [scope_file] [guard_mjs]
# ---------------------------------------------------------------------------
scope_guard() {
  local target="$1" file="${2:-${SCOPE_FILE:-}}" guard="${3:-${GUARD:-}}"
  local inlist outlist
  if [ -z "$target" ]; then
    printf 'scope_guard: missing target argument\n' >&2; return 2
  fi
  command -v node >/dev/null 2>&1 || { printf 'scope_guard: node not found\n' >&2; return 2; }
  [ -n "$file" ]  && [ -f "$file" ]  || { printf 'scope_guard: scope file not found: %s\n' "${file:-<unset>}" >&2; return 2; }
  [ -n "$guard" ] && [ -f "$guard" ] || { printf 'scope_guard: guard script not found: %s\n' "${guard:-<unset>}" >&2; return 2; }
  inlist="$(scope_list in_scope "$file" | paste -sd, -)"
  outlist="$(scope_list out_of_scope "$file" | paste -sd, -)"
  [ -n "$inlist" ] || { printf 'scope_guard: refusing — in_scope is empty in %s\n' "$file" >&2; return 2; }
  node "$guard" --target "$target" --in "$inlist" --out "$outlist"
}
