# Packaging

Package-manager manifests for opseclint, staged here and version-controlled. Each
is copied into its real destination repo at submit time. All hashes are for the
**v1.1.0** GitHub Release artifacts.

Regenerate hashes for a new release with:

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

## v1.1.0 artifact hashes

| target | archive | SHA256 |
|---|---|---|
| x86_64-unknown-linux-gnu | .tar.gz | `18307d5fb97a15b60e0232d650676d82e00f20bc458525f91cd286c110a997e6` |
| aarch64-apple-darwin | .tar.gz | `1f82161b5f366532ce83699ff162868e4dc3f00933aa6215e7e924606b3c05e6` |
| x86_64-apple-darwin | .tar.gz | `f1633728c91a5d68bd412d3442446be8b6fd9287a37353c1ed1b47a1e2febc66` |
| x86_64-pc-windows-msvc | .zip | `5fba423f8246ec26af4651d5f9fd7eda087d27edc6023769840bc910eb39cead` |

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

- **Set the maintainer line** in `PKGBUILD` to your real name/email before pushing
  (currently a `you@example.com` placeholder).
- If you edit `PKGBUILD`, regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.

```sh
git clone ssh://aur@aur.archlinux.org/opseclint-bin.git
cp PKGBUILD .SRCINFO opseclint-bin/ && cd opseclint-bin
namcap PKGBUILD && makepkg -si   # local test
git add PKGBUILD .SRCINFO && git commit -m "opseclint-bin 1.1.0" && git push
```

## winget — `winget/EzekielLabs.opseclint.*.yaml`

Three manifests (version + installer + locale), schema 1.6.0. The installer is the
release `.zip` treated as a `portable` nested installer aliased to `opseclint`.
Note the `InstallerSha256` is **uppercase** (winget convention).

```sh
winget validate --manifest .\winget\
# then PR the three files to microsoft/winget-pkgs under
# manifests/e/EzekielLabs/opseclint/1.1.0/
```

Install: `winget install EzekielLabs.opseclint`
