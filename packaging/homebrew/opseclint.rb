# Homebrew formula for opseclint (prebuilt binaries).
# Destination: ezekiellabs/homebrew-tap -> Formula/opseclint.rb
#   brew install ezekiellabs/tap/opseclint
class Opseclint < Formula
  desc "Analyze shell commands for ATT&CK techniques and detection coverage"
  homepage "https://github.com/ezekiellabs/opseclint"
  version "1.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "f05e946da8ee617daaddee6b7676995c43bf8d3020d2faa64d4dc10523e8daf8"
    end
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "aabf38598f4954bb2e6e035df206bcf40aa79f57ff53dfed229e035fcb9f7227"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3e0ab1cb476d331c01c41a189f5daf3de7b87e5fd3e25bf9b5b015be86f44bae"
    end
  end

  def install
    # The archive nests the binaries in a single opseclint-v<version>-<target>/
    # directory; locate them explicitly so install works regardless of whether
    # Homebrew has descended into that sole top-level directory. The globs are
    # exact, so "**/opseclint" never picks up opseclint-mcp.
    bin.install Dir["**/opseclint"].first
    bin.install Dir["**/opseclint-mcp"].first
  end

  test do
    assert_match "opseclint #{version}", shell_output("#{bin}/opseclint --version")
    # opseclint-mcp speaks MCP on stdio and has no --version; an empty stdin
    # gives it a clean EOF, which is a successful session rather than an error.
    assert_predicate bin/"opseclint-mcp", :executable?
  end
end
