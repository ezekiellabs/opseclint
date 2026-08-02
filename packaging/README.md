# Packaging

Package-manager manifests for opseclint, staged here and version-controlled. Each
is copied into its real destination repo at submit time. All hashes are for the
**v1.2.0** GitHub Release artifacts.

The whole bump is scripted — prefer
[`scripts/sync-packaging.sh`](../scripts/sync-packaging.sh) over hand-editing.

## Release order

The artifact hashes only exist once the release publishes, so the version bump
and the hash fill-in are two steps:

```sh
scripts/sync-packaging.sh --bump 1.3.0   # 1. offline; Cargo.toml + every manifest
                                         #    open the release PR, tag, publish
scripts/sync-packaging.sh 1.3.0          # 2. online; real hashes from the release
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

## v1.2.0 artifact hashes

| target | archive | SHA256 |
|---|---|---|
| x86_64-unknown-linux-gnu | .tar.gz | `a2898439b8df630d49249ffa4748f821abe351f06d286d9ed8a216c582ba8179` |
| aarch64-apple-darwin | .tar.gz | `338d5abd7a80b47f8d522e6dc576ef3aa78be6580c83352ea43939bcfa59a97b` |
| x86_64-apple-darwin | .tar.gz | `362ebf63ee34d859781103b466573cf3f607f079781e6e348c7bc47104bbcdfd` |
| x86_64-pc-windows-msvc | .zip | `1edde8dcb4f2f46c70ff0089454ce5a35147ed209900e577ed463b1634c207b7` |

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

Three manifests (version + installer + locale), schema 1.6.0. The installer is the
release `.zip` treated as a `portable` nested installer aliased to `opseclint`.
Note the `InstallerSha256` is **uppercase** (winget convention).

```sh
winget validate --manifest .\winget\
# then PR the three files to microsoft/winget-pkgs under
# manifests/e/EzekielLabs/opseclint/X.Y.Z/
```

Install: `winget install EzekielLabs.opseclint`
