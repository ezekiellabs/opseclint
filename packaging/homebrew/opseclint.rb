# Homebrew formula for opseclint (prebuilt binaries).
# Destination: ezekiellabs/homebrew-tap -> Formula/opseclint.rb
#   brew install ezekiellabs/tap/opseclint
class Opseclint < Formula
  desc "Analyze shell commands for ATT&CK techniques and detection coverage"
  homepage "https://github.com/ezekiellabs/opseclint"
  version "1.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v1.1.0/opseclint-v1.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "1f82161b5f366532ce83699ff162868e4dc3f00933aa6215e7e924606b3c05e6"
    end
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v1.1.0/opseclint-v1.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "f1633728c91a5d68bd412d3442446be8b6fd9287a37353c1ed1b47a1e2febc66"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v1.1.0/opseclint-v1.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "18307d5fb97a15b60e0232d650676d82e00f20bc458525f91cd286c110a997e6"
    end
  end

  def install
    # The archive nests the binary in a single opseclint-v<version>-<target>/
    # directory; locate it explicitly so install works regardless of whether
    # Homebrew has descended into that sole top-level directory.
    bin.install Dir["**/opseclint"].first
  end

  test do
    assert_match "opseclint 1.1.0", shell_output("#{bin}/opseclint --version")
  end
end
