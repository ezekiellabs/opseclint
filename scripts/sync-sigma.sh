#!/usr/bin/env bash
#
# Keep the pinned SigmaHQ revision and the verification baselines in step.
#
#   sync-sigma.sh --ref          print the pinned commit id
#   sync-sigma.sh --check        offline: assert .ci/sigma-ref and the
#                                sigma_ref inside every baseline agree,
#                                exit non-zero if not
#   sync-sigma.sh --bump REF     online: check out REF ("latest" resolves
#                                upstream HEAD), show what it changes, then
#                                rewrite every baseline and the pin
#
# Why the pin exists: --verify-detections proves the knowledge base's Sigma
# claims against a real ruleset and fails CI when a verified claim regresses.
# That gate compares two things — the committed baseline and the ruleset on
# disk — so if the ruleset floats, the comparison is not reproducible and an
# unrelated pull request can go red because SigmaHQ merged a rule overnight.
# Pinning makes a green run stay green until someone deliberately moves it.
# .github/workflows/sigma-drift.yml runs the same comparison against upstream
# main on a schedule, so falling behind still surfaces — just not as a red
# build on someone else's change.
#
# Why the revision is recorded twice: .ci/sigma-ref answers "what does CI check
# out?" and has to be readable by shell before anything is built, while the
# sigma_ref inside each baseline answers "what was this data computed from?"
# and has to travel with the file when someone diffs against it locally, months
# from now, outside this repository. Duplication is safe because --check is a
# network-free string comparison, which is why it is cheap enough to require on
# every pull request — the same trade scripts/sync-packaging.sh makes across
# nine manifests.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ci="$repo_root/.ci"
pin_file="$ci/sigma-ref"
platforms="linux windows macos"
sigma_url="https://github.com/SigmaHQ/sigma.git"

die() { printf '%s\n' "error: $*" >&2; exit 1; }

# Global so the EXIT trap can still see it once bump() has returned.
scratch=""
cleanup() { [ -n "$scratch" ] && rm -rf "$scratch"; return 0; }
trap cleanup EXIT

# The pinned commit id: the first line that is not blank and not a comment.
# One parser, used by both the checker and the workflows, so they cannot
# disagree about what counts as a comment.
pinned_ref() {
  [ -f "$pin_file" ] || die "$pin_file not found"
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$pin_file" | grep -m1 . || true
}

# Fields are read out of the baselines with sed rather than jq so this stays
# dependency-free the way sync-packaging.sh is. It is safe because the files are
# written by serde_json::to_string_pretty, whose indentation (two spaces) and
# field order (declaration order) are stable: anchoring to `^  "` therefore
# matches only top-level keys, never the entries nested inside "results".
json_field() {
  sed -n "s/^  \"$2\": \"\([^\"]*\)\".*/\1/p" "$1" | head -1
}

json_number() {
  sed -n "s/^  \"$2\": \([0-9]*\).*/\1/p" "$1" | head -1
}

baseline_for() { printf '%s/verified-%s.json\n' "$ci" "$1"; }

# A 40-hex commit id, never an abbreviation, a tag, or a branch. actions/checkout
# and `git fetch` both need an unambiguous object id, a tag can be moved after
# the fact, and validating the shape here also means the value is inert by the
# time any workflow interpolates it into a shell.
require_sha() {
  case "$1" in
    *[!0-9a-f]* | "") die "not a 40-character lowercase commit id: '$1'" ;;
  esac
  [ "${#1}" -eq 40 ] || die "not a 40-character lowercase commit id: '$1'"
}

check() {
  local want rc=0
  want=$(pinned_ref)
  [ -n "$want" ] || die "$pin_file contains no commit id"
  require_sha "$want"
  printf 'pinned SigmaHQ revision: %s\n\n' "$want"

  local plat file got platform rules
  for plat in $platforms; do
    file=$(baseline_for "$plat")
    if [ ! -f "$file" ]; then
      printf '  %-28s MISSING\n' "verified-$plat.json"
      rc=1
      continue
    fi

    got=$(json_field "$file" sigma_ref)
    platform=$(json_field "$file" platform)
    rules=$(json_number "$file" rules_indexed)

    if [ "$got" != "$want" ]; then
      printf '  %-28s %s  (want %s)\n' "verified-$plat.json" "${got:-<none>}" "$want"
      rc=1
    elif [ "$platform" != "$plat" ]; then
      # The runtime check in main.rs refuses a baseline whose platform does not
      # match --platform. Hoisting it here catches a mis-filed baseline at
      # review time instead of as a confusing exit 2 in the middle of CI.
      printf '  %-28s platform is "%s"\n' "verified-$plat.json" "$platform"
      rc=1
    elif [ -z "$rules" ] || [ "$rules" -eq 0 ]; then
      # Zero rules indexed means the run never found the ruleset. Every claim
      # would read NO-RULE and the diff would show no regression, so the gate
      # would pass by having tested nothing.
      printf '  %-28s rules_indexed is 0\n' "verified-$plat.json"
      rc=1
    else
      printf '  %-28s %s  ok (%s rules)\n' "verified-$plat.json" "$got" "$rules"
    fi
  done

  if [ "$rc" -ne 0 ]; then
    cat >&2 <<EOF

The pin and the verification baselines disagree.
Regenerate both together with:

    scripts/sync-sigma.sh --bump $want
EOF
  fi
  return "$rc"
}

bump() {
  local target="$1" sha old
  command -v cargo >/dev/null 2>&1 || die "cargo not found; --bump has to build the binary"
  old=$(pinned_ref || true)

  if [ "$target" = latest ]; then
    printf 'Resolving upstream HEAD...\n'
    # Match the HEAD line exactly. SigmaHQ also publishes a stray
    # refs/remotes/origin/HEAD pointing at a different commit, so taking the
    # first field of the first line silently pins the wrong revision.
    sha=$(git ls-remote "$sigma_url" HEAD | awk '$2 == "HEAD" { print $1 }')
    [ -n "$sha" ] || die "could not resolve HEAD of $sigma_url"
  else
    sha="$target"
  fi
  require_sha "$sha"
  printf 'Target revision: %s\n' "$sha"
  [ "$sha" = "$old" ] && printf 'note: already pinned here; regenerating anyway\n'

  scratch=$(mktemp -d)
  local rules="$scratch/sigma"
  printf 'Fetching the ruleset...\n'
  # A single-commit fetch of an arbitrary object id: `clone --depth 1` cannot
  # take a SHA, and a full clone of SigmaHQ to read one revision is wasteful.
  git init -q "$rules"
  git -C "$rules" remote add origin "$sigma_url"
  git -C "$rules" fetch -q --depth 1 origin "$sha"
  git -C "$rules" checkout -q FETCH_HEAD

  printf 'Building...\n'
  (cd "$repo_root" && cargo build --release --quiet)
  local bin="$repo_root/target/release/opseclint"
  [ -x "$bin" ] || die "expected a release binary at $bin"

  # Show what the new revision does to the *existing* baselines before any of
  # them are overwritten. This is the point of the whole script: without it a
  # bump is an opaque diff of several thousand JSON lines, and the reviewer has
  # no way to tell an upstream improvement from a silently accepted regression.
  printf '\n--- what this revision changes ---\n'
  local plat file
  for plat in $platforms; do
    file=$(baseline_for "$plat")
    [ -f "$file" ] || continue
    printf '\n== %s ==\n' "$plat"
    "$bin" --verify-detections --sigma "$rules/rules" --platform "$plat" \
      --sigma-ref "$sha" --diff "$file" --no-color || true
  done

  printf '\n--- writing baselines ---\n'
  for plat in $platforms; do
    file=$(baseline_for "$plat")
    "$bin" --verify-detections --sigma "$rules/rules" --platform "$plat" \
      --sigma-ref "$sha" --json > "$file"
    printf '  wrote %s\n' "${file#"$repo_root"/}"
  done

  # Rewrite only the value line, so the explanation at the top of the pin file
  # survives a bump and does not have to be duplicated here.
  local tmp="$scratch/sigma-ref"
  grep -E '^[[:space:]]*(#|$)' "$pin_file" > "$tmp"
  printf '%s\n' "$sha" >> "$tmp"
  cp "$tmp" "$pin_file"
  printf '  wrote %s\n' "${pin_file#"$repo_root"/}"

  printf '\nPin moved to %s. Verifying...\n\n' "$sha"
  check
}

case "${1:-}" in
  --ref) pinned_ref ;;
  --check) check ;;
  --bump) bump "${2:?usage: sync-sigma.sh --bump <40-hex-sha|latest>}" ;;
  -h|--help|"") sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown argument '$1' (try --ref, --check, or --bump)" ;;
esac
