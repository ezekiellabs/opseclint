# Homebrew formula for opseclint (prebuilt binaries).
# Destination: ezekiellabs/homebrew-tap -> Formula/opseclint.rb
#   brew install ezekiellabs/tap/opseclint
class Opseclint < Formula
  desc "Analyze shell commands for ATT&CK techniques and detection coverage"
  homepage "https://github.com/ezekiellabs/opseclint"
  version "1.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "f190f7a4830938d0b3d28b024089255682da79c71eb7bbb31cd2ef14efa108ad"
    end
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "c6a998d3c9468bc9467945c412b2807ffc1521c093e23225e634856efb794b42"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/ezekiellabs/opseclint/releases/download/v#{version}/opseclint-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c785a675b02a481c67c1775b6e77f390e88f9d570454b79dc3cb3fd57d0f5911"
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
