#!/usr/bin/env bash
#
# Keep packaging/ in step with the crate version.
#
#   sync-packaging.sh --check       offline: assert Cargo.lock and every
#                                   manifest agree with Cargo.toml, exit
#                                   non-zero if not
#   sync-packaging.sh --bump X.Y.Z  offline: move Cargo.toml, Cargo.lock and
#                                   every manifest to X.Y.Z, leaving hashes
#                                   stale
#   sync-packaging.sh X.Y.Z         online: version strings *and* real hashes,
#                                   fetched from the published release
#
# Release order, and why there are two write modes: the artifact hashes cannot
# exist before the release publishes, so a single mode would deadlock against
# its own gate. Instead:
#
#   1. --bump X.Y.Z, then open the release PR. Versions agree, so --check
#      passes; the hashes are knowingly stale for one release window.
#   2. Tag and let .github/workflows/release.yml publish the artifacts.
#   3. sync-packaging.sh X.Y.Z to fill in the real hashes, and push. The
#      post-publish verify job in release.yml goes green.
#
# All modes share one notion of "where the version lives", so the fixer and the
# checker cannot drift apart. --check makes no network calls, which is why it is
# safe to require on every pull request.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pkg="$repo_root/packaging"

die() { printf '%s\n' "error: $*" >&2; exit 1; }

# Global so the EXIT trap can still see it once sync() has returned.
scratch=""
cleanup() { [ -n "$scratch" ] && rm -rf "$scratch"; return 0; }
trap cleanup EXIT

crate_version() {
  # The workspace version, declared once under [workspace.package] and inherited
  # by both crates. Read from inside that table rather than taken as the first
  # `version = "..."` in the file: [workspace.dependencies] declares one too (the
  # opseclint-core requirement), and which table comes first is not a fact worth
  # depending on.
  awk '
    /^\[/ { in_pkg = ($0 == "[workspace.package]") }
    in_pkg && sub(/^version = "/, "") { sub(/".*/, ""); print; exit }
  ' "$repo_root/Cargo.toml"
}

# The version of opseclint-core that the binary declares it needs. Published
# together and pinned to each other, so this must equal crate_version(); check()
# enforces it, because the failure is invisible locally — a path dependency
# resolves fine no matter what the requirement says, and the mismatch only
# surfaces as an `opseclint` on crates.io built against one evaluator and
# requiring another.
core_dep_version() {
  sed -n 's/^opseclint-core = .*version = "\([^"]*\)".*/\1/p' "$repo_root/Cargo.toml" | head -1
}

# The workspace member crate names, read from [workspace] members rather than
# listed here, so a crate added later is covered the day it appears instead of
# the day someone remembers this file.
workspace_members() {
  awk '
    /^\[/ { in_ws = ($0 == "[workspace]") }
    in_ws && /^members[[:space:]]*=/ { collecting = 1 }
    collecting {
      buf = buf $0
      if (index($0, "]")) { collecting = 0; done = 1 }
    }
    done {
      while (match(buf, /"[^"]+"/)) {
        path = substr(buf, RSTART + 1, RLENGTH - 2)
        sub(/.*\//, "", path)          # crates/opseclint-core -> opseclint-core
        print path
        buf = substr(buf, RSTART + RLENGTH)
      }
      exit
    }
  ' "$repo_root/Cargo.toml"
}

# A workspace member's version as recorded in Cargo.lock.
#
# The lockfile matters because publish.yml runs `cargo publish --locked`, which
# refuses to build if the lock disagrees with the manifest. A bump that moved
# Cargo.toml and left the lock behind therefore passed every check here and then
# failed the release itself — after the tag was pushed, with the binaries
# already built.
#
# A package name is unique within the lockfile, so the [[package]] block is
# addressed by name and the `version` that follows it is unambiguous.
lockfile_version() {
  awk -v want="$1" '
    /^name = / { name = $3; gsub(/"/, "", name); next }
    /^version = / && name == want { v = $3; gsub(/"/, "", v); print v; exit }
  ' "$repo_root/Cargo.lock"
}

# Bring Cargo.lock's workspace-member entries up to the manifest version.
#
# `cargo update --workspace` is the real tool for this and is used when cargo is
# on PATH. `--offline` keeps --bump's promise that it makes no network calls:
# the only versions that move belong to path dependencies inside this workspace,
# so nothing has to be fetched. The awk fallback exists because a release can be
# prepared on a machine without a toolchain, and a silently un-bumped lockfile is
# the exact failure this function was added to prevent.
update_lockfile() {
  local new="$1" members
  [ -f "$repo_root/Cargo.lock" ] || return 0

  if command -v cargo >/dev/null 2>&1 \
     && (cd "$repo_root" && cargo update --workspace --offline --quiet >/dev/null 2>&1); then
    return 0
  fi

  members=$(workspace_members | tr '\n' ' ')
  scratch=${scratch:-$(mktemp -d)}
  awk -v new="$new" -v members="$members" '
    BEGIN { n = split(members, m, " "); for (i = 1; i <= n; i++) if (m[i] != "") is_member[m[i]] = 1 }
    /^name = / { name = $3; gsub(/"/, "", name) }
    /^version = / && (name in is_member) { print "version = \"" new "\""; next }
    { print }
  ' "$repo_root/Cargo.lock" > "$scratch/Cargo.lock"
  mv "$scratch/Cargo.lock" "$repo_root/Cargo.lock"
  printf 'note: cargo unavailable or offline update failed; rewrote Cargo.lock directly\n'
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# Each manifest, and the sed program that extracts the version it declares.
# Keep this list in step with packaging/README.md.
manifest_version() {
  case "$1" in
    homebrew/opseclint.rb)            sed -n 's/^  version "\(.*\)"/\1/p' "$pkg/$1" ;;
    scoop/opseclint.json)             sed -n 's/^    "version": "\(.*\)",/\1/p' "$pkg/$1" ;;
    aur/PKGBUILD)                     sed -n 's/^pkgver=\(.*\)/\1/p' "$pkg/$1" ;;
    aur/.SRCINFO)                     sed -n 's/^\tpkgver = \(.*\)/\1/p' "$pkg/$1" ;;
    winget/*.yaml)                    sed -n 's/^PackageVersion: \(.*\)/\1/p' "$pkg/$1" ;;
    README.md)                        sed -n 's/.*\*\*v\([0-9][0-9A-Za-z.+-]*\)\*\* GitHub Release.*/\1/p' "$pkg/$1" ;;
    *) die "no version rule for $1" ;;
  esac
}

MANIFESTS=(
  homebrew/opseclint.rb
  scoop/opseclint.json
  aur/PKGBUILD
  aur/.SRCINFO
  winget/EzekielLabs.opseclint.yaml
  winget/EzekielLabs.opseclint.installer.yaml
  winget/EzekielLabs.opseclint.locale.en-US.yaml
  README.md
)

check() {
  local want rc=0 got core
  want=$(crate_version)
  [ -n "$want" ] || die "could not read [workspace.package] version from Cargo.toml"
  printf 'Cargo.toml declares %s\n' "$want"

  core=$(core_dep_version)
  if [ -z "$core" ]; then
    printf '  %-46s no version found\n' "opseclint-core requirement"
    rc=1
  elif [ "$core" != "$want" ]; then
    printf '  %-46s %s  != %s\n' "opseclint-core requirement" "$core" "$want"
    rc=1
  else
    printf '  %-46s %s  ok\n' "opseclint-core requirement" "$core"
  fi

  # Checked here rather than left to the release: `cargo publish --locked` fails
  # on a stale lockfile, and by then the tag is pushed and the binaries are
  # built. This is an offline read of a file that is already in the tree.
  local member
  while read -r member; do
    [ -n "$member" ] || continue
    got=$(lockfile_version "$member")
    if [ -z "$got" ]; then
      printf '  %-46s not in Cargo.lock\n' "$member (lockfile)"
      rc=1
    elif [ "$got" != "$want" ]; then
      printf '  %-46s %s  != %s\n' "$member (lockfile)" "$got" "$want"
      rc=1
    else
      printf '  %-46s %s  ok\n' "$member (lockfile)" "$got"
    fi
  done <<EOF
$(workspace_members)
EOF

  for m in "${MANIFESTS[@]}"; do
    got=$(manifest_version "$m" | head -1)
    if [ -z "$got" ]; then
      printf '  %-46s no version found\n' "$m"
      rc=1
    elif [ "$got" != "$want" ]; then
      printf '  %-46s %s  != %s\n' "$m" "$got" "$want"
      rc=1
    else
      printf '  %-46s %s  ok\n' "$m" "$got"
    fi
  done

  if [ "$rc" -ne 0 ]; then
    cat >&2 <<EOF

packaging/ is out of step with Cargo.toml.
Once the release for $want is published, run:

    scripts/sync-packaging.sh $want
EOF
  fi
  return "$rc"
}

# Full SemVer, so `1.3.0-rc.1` is accepted (release.yml already special-cases
# pre-release tags) while `1.2.3foo` and `1x.2.3` are not. A `case` glob cannot
# express this: `*` would swallow arbitrary trailing characters, and a bad
# version silently propagates into URLs, filenames, and every manifest.
require_semver() {
  local re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
  [[ "$1" =~ $re ]] || die "expected a semver like 1.2.0 or 1.3.0-rc.1, got '$1'"
}

# The lines in each manifest that carry *opseclint's own* version.
#
# This is an allowlist, and that direction is the point. The previous approach
# replaced the version everywhere and then grew an exclusion list as each
# collision was discovered — a GNU-only address range, an ERE quantifier, the
# winget schema version, the schema version quoted in prose. Every one shipped,
# and every one was caught by review rather than by the script. Substituting
# only where we have said the version lives inverts the failure mode: instead of
# silently changing something that was not ours, we silently change too little —
# and unlike the former, that is detectable, which `assert_bumped` below does.
#
# Patterns are BRE, matching `sed` without `-E`, so `+` stays literal for
# versions carrying build metadata (`1.2.0+build.5`, which require_semver
# accepts).
version_lines() {
  case "$1" in
    homebrew/opseclint.rb)
      # URLs and the test assertion interpolate #{version}; only the declaration
      # holds a literal.
      printf '%s\n' '^  version "' ;;
    scoop/opseclint.json)
      # The autoupdate block templates $version and needs no substitution.
      printf '%s\n' '^    "version":' '"url":' '"extract_dir":' ;;
    aur/PKGBUILD)
      # source=() interpolates ${pkgver}.
      printf '%s\n' '^pkgver=' ;;
    aur/.SRCINFO)
      # Generated, so fully expanded: both lines hold literals.
      printf '%s\n' 'pkgver = ' 'source = ' ;;
    winget/*.yaml)
      # NOT ManifestVersion or the $schema URL — those track the winget schema.
      printf '%s\n' '^PackageVersion:' 'RelativeFilePath:' 'InstallerUrl:' ;;
    README.md)
      printf '%s\n' '\*\*v[0-9]' '^## v[0-9].* artifact hashes' ;;
    *) die "no version-line rule for $1" ;;
  esac
}

# Lines that legitimately carry a version belonging to something else, and so
# are expected to still mention the old version after a bump. Used only by the
# assertion — never to decide what to substitute.
FOREIGN_VERSION='ManifestVersion:|yaml-language-server:|schema [0-9]'

# After a bump, nothing outside FOREIGN_VERSION may still carry the old version.
# Catches both ways the allowlist can be wrong: a pattern that stopped matching,
# and a line nobody remembered to list. `$1` is a path relative to $pkg, or an
# absolute path (the root Cargo.toml, which is not a packaging manifest but has
# the same failure mode).
assert_bumped() {
  local m="$1" old_re="$2" new_re="$3" n line residual="" file
  case "$m" in /*) file="$m" ;; *) file="$pkg/$m" ;; esac
  # Scrub the new version out of each line before looking for the old one. When
  # `new` has `old` as a prefix — `1.3.0-rc.1` -> `1.3.0-rc.10`, or gaining a
  # `+build` suffix — a correctly rewritten line still *contains* the old
  # string, and a naive search would flag the very substitution that just
  # succeeded. Line numbering survives `s///`, so the numbers still address the
  # original file and the message quotes the real line.
  while IFS= read -r n; do
    line=$(sed -n "${n}p" "$file")
    if ! printf '%s\n' "$line" | grep -Eq "$FOREIGN_VERSION"; then
      residual+="  $n: $line"$'\n'
    fi
  done < <(sed "s/$new_re//g" "$file" | grep -n "$old_re" | cut -d: -f1)
  [ -z "$residual" ] || die "${file#"$repo_root"/} still carries the old version after the bump:
$residual  Add the line to version_lines() in $(basename "${BASH_SOURCE[0]}")."
}

bump_versions() {
  local new="$1" old m pat old_re
  for m in "${MANIFESTS[@]}"; do
    old=$(manifest_version "$m" | head -1)
    [ -n "$old" ] || die "no version found in packaging/$m"
    if [ "$old" != "$new" ]; then
      old_re=${old//./\\.}
      while IFS= read -r pat; do
        sed -i.bak "/$pat/s/$old_re/$new/g" "$pkg/$m"
        rm -f "$pkg/$m.bak"
      done < <(version_lines "$m")
      assert_bumped "$m" "$old_re" "${new//./\\.}"
    fi
  done
}

bump() {
  local new="$1" old
  require_semver "$new"
  old=$(crate_version)
  if [ "$old" != "$new" ]; then
    # Two declarations move, not one: the workspace version both crates inherit,
    # and the opseclint-core requirement the binary is published against. They
    # are pinned to each other on purpose (see core_dep_version).
    #
    # awk rather than sed: the `0,/re/` address range is a GNU extension that
    # BSD sed (macOS) rejects, and release work happens on both. The
    # [workspace.package] line is an exact string compare, so no regex escaping
    # to get wrong; the dependency line is addressed by its key, so a `version`
    # belonging to some other dependency is never in reach.
    scratch=${scratch:-$(mktemp -d)}
    awk -v old="$old" -v new="$new" '
      /^\[/ { in_pkg = ($0 == "[workspace.package]") }
      in_pkg && $0 == "version = \"" old "\"" { print "version = \"" new "\""; next }
      /^opseclint-core = / { gsub("version = \"" old "\"", "version = \"" new "\"") }
      { print }
    ' "$repo_root/Cargo.toml" > "$scratch/Cargo.toml"
    mv "$scratch/Cargo.toml" "$repo_root/Cargo.toml"
    assert_bumped "$repo_root/Cargo.toml" "${old//./\\.}" "${new//./\\.}"
    printf 'Cargo.toml %s -> %s\n' "$old" "$new"
  fi
  update_lockfile "$new"
  bump_versions "$new"
  printf '\nVersions moved to %s. Hashes are now stale until the release for\n' "$new"
  printf 'v%s publishes, after which run: scripts/sync-packaging.sh %s\n\n' "$new" "$new"
  check
}

sync() {
  local new="$1" base
  require_semver "$new"

  base="https://github.com/ezekiellabs/opseclint/releases/download/v$new"
  scratch=$(mktemp -d)

  printf 'fetching v%s release artifacts...\n' "$new"
  local h_linux h_arm64mac h_x64mac h_win
  h_linux=$(curl -fsSL "$base/opseclint-v$new-x86_64-unknown-linux-gnu.tar.gz" | sha256_of)
  h_arm64mac=$(curl -fsSL "$base/opseclint-v$new-aarch64-apple-darwin.tar.gz" | sha256_of)
  h_x64mac=$(curl -fsSL "$base/opseclint-v$new-x86_64-apple-darwin.tar.gz" | sha256_of)
  h_win=$(curl -fsSL "$base/opseclint-v$new-x86_64-pc-windows-msvc.zip" | sha256_of)

  for h in "$h_linux" "$h_arm64mac" "$h_x64mac" "$h_win"; do
    [ ${#h} -eq 64 ] || die "not a sha256: '$h'"
  done

  bump_versions "$new"

  # Then the hashes, each in its ecosystem's expected case.
  # Homebrew: three sha256 lines, in file order arm64-mac, x64-mac, linux.
  awk -v a="$h_arm64mac" -v b="$h_x64mac" -v c="$h_linux" '
    /^      sha256 "/ { n++
      if (n == 1) sub(/"[0-9a-f]*"/, "\"" a "\"")
      else if (n == 2) sub(/"[0-9a-f]*"/, "\"" b "\"")
      else if (n == 3) sub(/"[0-9a-f]*"/, "\"" c "\"")
    } { print }' "$pkg/homebrew/opseclint.rb" > "$scratch/f" && mv "$scratch/f" "$pkg/homebrew/opseclint.rb"

  sed -i.bak -E "s/(\"hash\": \")[0-9a-f]*/\1$h_win/" \
    "$pkg/scoop/opseclint.json" && rm -f "$pkg/scoop/opseclint.json.bak"
  sed -i.bak -E "s/^sha256sums=\('[0-9a-f]*'\)/sha256sums=('$h_linux')/" \
    "$pkg/aur/PKGBUILD" && rm -f "$pkg/aur/PKGBUILD.bak"
  sed -i.bak -E "s/^(\tsha256sums = )[0-9a-f]*/\1$h_linux/" \
    "$pkg/aur/.SRCINFO" && rm -f "$pkg/aur/.SRCINFO.bak"
  # winget wants the digest uppercase.
  sed -i.bak -E "s/^(    InstallerSha256: )[0-9A-Fa-f]*/\1$(printf '%s' "$h_win" | tr 'a-f' 'A-F')/" \
    "$pkg/winget/EzekielLabs.opseclint.installer.yaml" \
    && rm -f "$pkg/winget/EzekielLabs.opseclint.installer.yaml.bak"

  # The reference table in packaging/README.md, keyed by target triple.
  sed -i.bak -E \
    -e "s/(\| x86_64-unknown-linux-gnu \| \.tar\.gz \| \`)[0-9a-f]*/\1$h_linux/" \
    -e "s/(\| aarch64-apple-darwin \| \.tar\.gz \| \`)[0-9a-f]*/\1$h_arm64mac/" \
    -e "s/(\| x86_64-apple-darwin \| \.tar\.gz \| \`)[0-9a-f]*/\1$h_x64mac/" \
    -e "s/(\| x86_64-pc-windows-msvc \| \.zip \| \`)[0-9a-f]*/\1$h_win/" \
    "$pkg/README.md" && rm -f "$pkg/README.md.bak"

  if command -v makepkg >/dev/null 2>&1; then
    (cd "$pkg/aur" && makepkg --printsrcinfo > .SRCINFO)
  else
    printf 'note: makepkg not found; .SRCINFO was rewritten in place instead\n'
  fi

  printf '\npackaging/ updated to v%s. Verifying...\n' "$new"
  check
}

case "${1:-}" in
  --check) check ;;
  --bump) bump "${2:?usage: sync-packaging.sh --bump X.Y.Z}" ;;
  -h|--help|"") sed -n '3,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) sync "$1" ;;
esac
