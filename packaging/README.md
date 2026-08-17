# Packaging

Package-manager manifests for opseclint, staged here and version-controlled. Each
is copied into its real destination repo at submit time. These manifests target the
**v1.4.0** GitHub Release; the SHA256s below are filled in only once that release
publishes, so for the duration of the release pull request they still carry the
*previous* release's digests. That window is expected — see [Release order](#release-order).

The whole bump is scripted — prefer
[`scripts/sync-packaging.sh`](../scripts/sync-packaging.sh) over hand-editing.

## Release order

The artifact hashes only exist once the release publishes, so the version bump
and the hash fill-in are two steps:

```sh
scripts/sync-packaging.sh --bump X.Y.Z   # 1. offline; Cargo.toml + every manifest
                                         #    open the release PR, tag, publish
scripts/sync-packaging.sh X.Y.Z          # 2. online; real hashes from the release
```

Two gates keep this honest:

- **`--check`** runs on every pull request (`.github/workflows/ci.yml`). It is an
  offline version comparison against `Cargo.toml`, so a bump that forgets this
  directory fails before it merges.
- **`verify-packaging`** runs after a release publishes
  (`.github/workflows/release.yml`). It recomputes the four hashes from the
  published artifacts and fails if they are not present here — the reminder to
  run step 2. It never writes.

Neither gate can tell you whether a manifest was actually *submitted* to its
destination registry; those four submissions are still manual (below).

To regenerate the hashes by hand:

```sh
base="https://github.com/ezekiellabs/opseclint/releases/download/vX.Y.Z"
for a in \
  opseclint-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz \
  opseclint-vX.Y.Z-aarch64-apple-darwin.tar.gz \
  opseclint-vX.Y.Z-x86_64-apple-darwin.tar.gz \
  opseclint-vX.Y.Z-x86_64-pc-windows-msvc.zip; do
  curl -fsSL "$base/$a" | sha256sum | sed "s|-|$a|"
done
```

## v1.4.0 artifact hashes

Written by step 2 of the release order above, once the artifacts exist. Until
that step runs, the digests in this table belong to the previous release.

| target | archive | SHA256 |
|---|---|---|
| x86_64-unknown-linux-gnu | .tar.gz | `c785a675b02a481c67c1775b6e77f390e88f9d570454b79dc3cb3fd57d0f5911` |
| aarch64-apple-darwin | .tar.gz | `f190f7a4830938d0b3d28b024089255682da79c71eb7bbb31cd2ef14efa108ad` |
| x86_64-apple-darwin | .tar.gz | `c6a998d3c9468bc9467945c412b2807ffc1521c093e23225e634856efb794b42` |
| x86_64-pc-windows-msvc | .zip | `b3bf8aabded20690660cd4e866147d471a9422b9aa709a4f3696f5b2ecb86a0d` |

## Homebrew — `homebrew/opseclint.rb`

Prebuilt-binary formula (arm64 + x86_64 macOS, x86_64 Linux). Copy into a tap:

```sh
# in ezekiellabs/homebrew-tap
cp opseclint.rb Formula/opseclint.rb
brew install --build-from-source ./Formula/opseclint.rb   # local test
brew audit --new Formula/opseclint.rb
```

Install: `brew install ezekiellabs/tap/opseclint`

## Scoop — `scoop/opseclint.json`

Windows x64 bucket manifest with `checkver` + `autoupdate`. Copy into a bucket:

```sh
# in ezekiellabs/scoop-bucket
cp opseclint.json bucket/opseclint.json
```

Install: `scoop bucket add ezekiellabs https://github.com/ezekiellabs/scoop-bucket && scoop install opseclint`

## AUR — `aur/PKGBUILD` + `aur/.SRCINFO`

`opseclint-bin` (prebuilt Linux x86_64 binary).

- If you edit `PKGBUILD`, regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.

```sh
git clone ssh://aur@aur.archlinux.org/opseclint-bin.git
cp PKGBUILD .SRCINFO opseclint-bin/ && cd opseclint-bin
namcap PKGBUILD && makepkg -si   # local test
git add PKGBUILD .SRCINFO && git commit -m "opseclint-bin X.Y.Z" && git push
```

## winget — `winget/EzekielLabs.opseclint.*.yaml`

Three manifests (version + installer + locale), schema 1.12.0. The installer is the
release `.zip` treated as a `portable` nested installer aliased to `opseclint`.
Note the `InstallerSha256` is **uppercase** (winget convention).

```sh
winget validate --manifest .\winget\
winget install --manifest .\winget\   # the PR checklist asks for this too
# then PR the three files to microsoft/winget-pkgs under
# manifests/e/EzekielLabs/opseclint/X.Y.Z/
```

Submitting to `microsoft/winget-pkgs` needs three things this repo cannot
provide: a signed [Contributor License Agreement](https://cla.opensource.microsoft.com),
a Windows machine to run the two commands above, and a PR titled
`New package: EzekielLabs.opseclint version X.Y.Z` (or `Update: ... to X.Y.Z`)
touching exactly one manifest directory.

`ManifestVersion` tracks the **winget schema**, not opseclint. It moves only
when Microsoft publishes a new schema and the manifests are migrated to it —
`sync-packaging.sh` deliberately holds that line back from a version bump.

Install: `winget install EzekielLabs.opseclint`
