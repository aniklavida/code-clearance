# Code Clearance Homebrew formula template.
#
# This is a TEMPLATE and is not published to any tap. Before use, cut a tagged
# release, then replace VERSION and each SHA256 placeholder with real values:
#
#   version="1.0.0"
#   sha256sum dist/code-clearance_v${version}_darwin_arm64
#   ...
#
# Then host it in a tap (for example aniklavida/homebrew-tap) as
# Formula/code-clearance.rb. Nothing in this repository publishes it for you.
class CodeClearance < Formula
  desc "Evidence-based clearance for AI-generated code"
  homepage "https://github.com/aniklavida/code-clearance"
  version "VERSION"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/aniklavida/code-clearance/releases/download/v#{version}/code-clearance_v#{version}_darwin_arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    else
      url "https://github.com/aniklavida/code-clearance/releases/download/v#{version}/code-clearance_v#{version}_darwin_amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/aniklavida/code-clearance/releases/download/v#{version}/code-clearance_v#{version}_linux_arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    else
      url "https://github.com/aniklavida/code-clearance/releases/download/v#{version}/code-clearance_v#{version}_linux_amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    bin.install Dir["code-clearance_*"].first => "code-clearance"
  end

  test do
    assert_match "code-clearance", shell_output("#{bin}/code-clearance version")
  end
end
