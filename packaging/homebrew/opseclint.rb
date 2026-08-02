# Homebrew formula for opseclint (prebuilt binaries).
# Destination: ezekiellabs/homebrew-tap -> Formula/opseclint.rb
#   brew install ezekiellabs/tap/opseclint
class Opseclint < Formula
  desc "Analyze shell commands for ATT&CK techniques and detection coverage"
  homepage "https://github.com/ezekiellabs/opseclint"
  version "1.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "338d5abd7a80b47f8d522e6dc576ef3aa78be6580c83352ea43939bcfa59a97b"
    end
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "362ebf63ee34d859781103b466573cf3f607f079781e6e348c7bc47104bbcdfd"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "a2898439b8df630d49249ffa4748f821abe351f06d286d9ed8a216c582ba8179"
    end
  end

  def install
    # The archive nests the binary in a single opseclint-v<version>-<target>/
    # directory; locate it explicitly so install works regardless of whether
    # Homebrew has descended into that sole top-level directory.
    bin.install Dir["**/opseclint"].first
  end

  test do
    assert_match "opseclint #{version}", shell_output("#{bin}/opseclint --version")
  end
end
