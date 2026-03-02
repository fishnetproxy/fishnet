#!/usr/bin/env sh
set -eu

if [ "$#" -lt 7 ]; then
  echo "Usage: $0 <version> <mac_arm_url> <mac_arm_sha256> <mac_x64_url> <mac_x64_sha256> <linux_x64_url> <linux_x64_sha256> [homepage]" >&2
  exit 1
fi

VERSION="$1"
MAC_ARM_URL="$2"
MAC_ARM_SHA="$3"
MAC_X64_URL="$4"
MAC_X64_SHA="$5"
LINUX_X64_URL="$6"
LINUX_X64_SHA="$7"
HOMEPAGE="${8:-https://github.com/iamyxsh/fishnet}"

cat <<EOF
class Fishnet < Formula
  desc "Local-first security proxy for AI agents"
  homepage "${HOMEPAGE}"
  version "${VERSION}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "${MAC_ARM_URL}"
      sha256 "${MAC_ARM_SHA}"
    else
      url "${MAC_X64_URL}"
      sha256 "${MAC_X64_SHA}"
    end
  end

  on_linux do
    url "${LINUX_X64_URL}"
    sha256 "${LINUX_X64_SHA}"
  end

  def install
    bin.install "fishnet"
  end

  test do
    assert_match "Fishnet", shell_output("#{bin}/fishnet --help")
  end
end
EOF
