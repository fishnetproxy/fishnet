#!/usr/bin/env sh
set -eu

REPO="${FISHNET_REPO:-iamyxsh/fishnet}"
VERSION_ARG="${1:-}"
VERSION="${FISHNET_VERSION:-$VERSION_ARG}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

detect_latest_tag() {
  curl -fsSL -o /dev/null -w '%{url_effective}' -L "https://github.com/${REPO}/releases/latest" \
    | sed 's:.*/::'
}

normalize_tag() {
  case "$1" in
    v*) printf '%s\n' "$1" ;;
    *) printf 'v%s\n' "$1" ;;
  esac
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) target_os="apple-darwin" ;;
    Linux) target_os="unknown-linux-gnu" ;;
    *)
      echo "Unsupported operating system: $os" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64) target_arch="x86_64" ;;
    arm64|aarch64) target_arch="aarch64" ;;
    *)
      echo "Unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  printf '%s-%s\n' "$target_arch" "$target_os"
}

verify_checksum() {
  file="$1"
  expected="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    echo "No SHA256 tool found (need sha256sum or shasum)." >&2
    exit 1
  fi

  if [ "$actual" != "$expected" ]; then
    echo "Checksum verification failed." >&2
    echo "Expected: $expected" >&2
    echo "Actual:   $actual" >&2
    exit 1
  fi
}

if [ -z "$VERSION" ]; then
  VERSION="$(detect_latest_tag)"
fi
TAG="$(normalize_tag "$VERSION")"
TARGET="$(detect_target)"

ARCHIVE="fishnet-${TARGET}.tar.gz"
CHECKSUM_FILE="${ARCHIVE}.sha256"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

TMPDIR="$(mktemp -d 2>/dev/null || mktemp -d -t fishnet-install)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT HUP TERM

echo "Installing Fishnet ${TAG} for ${TARGET}..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMPDIR}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/${CHECKSUM_FILE}" -o "${TMPDIR}/${CHECKSUM_FILE}"

EXPECTED_SHA="$(awk '{print $1; exit}' "${TMPDIR}/${CHECKSUM_FILE}")"
if [ -z "$EXPECTED_SHA" ]; then
  echo "Failed to parse checksum file ${CHECKSUM_FILE}." >&2
  exit 1
fi

verify_checksum "${TMPDIR}/${ARCHIVE}" "$EXPECTED_SHA"

mkdir -p "$INSTALL_DIR"
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"
install -m 0755 "${TMPDIR}/fishnet" "${INSTALL_DIR}/fishnet"

echo "Fishnet installed at ${INSTALL_DIR}/fishnet"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "Add ${INSTALL_DIR} to your PATH, for example:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
