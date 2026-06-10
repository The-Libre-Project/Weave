#!/usr/bin/env bash
# Fetch IrfanView 64-bit OptiPNG plugin into tests/fixtures/irfanview/Plugins/.
# PNG Save-As under Weave requires this DLL — the portable i_view64.exe alone
# only has built-in JPEG encode; OptiPNG_W lives in the Plugins pack.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/tests/fixtures/irfanview/Plugins"
MARKER="${DEST}/OptiPNG.dll"

if [[ -f "${MARKER}" ]]; then
  echo "fetch-irfanview-optipng-plugin: already present at ${MARKER}"
  exit 0
fi

mkdir -p "${DEST}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

UA="Mozilla/5.0 (compatible; Weave-CI/1.0)"
REF="https://www.irfanview.com/"

try_zip() {
  local url="$1"
  local zip="${TMP}/plugins.zip"
  echo "fetch-irfanview-optipng-plugin: trying ${url}"
  if ! curl -fsSL -A "${UA}" -H "Referer: ${REF}" --retry 3 --retry-delay 2 \
    -o "${zip}" "${url}"; then
    return 1
  fi
  if ! file "${zip}" | grep -qi 'zip archive'; then
    echo "fetch-irfanview-optipng-plugin: not a zip (${url})" >&2
    return 1
  fi
  unzip -q -o "${zip}" -d "${TMP}/extract" '*/OptiPNG.dll' '*/optipng.dll' 2>/dev/null || true
  local found
  found="$(find "${TMP}/extract" -iname 'OptiPNG.dll' -print -quit 2>/dev/null || true)"
  if [[ -z "${found}" ]]; then
    echo "fetch-irfanview-optipng-plugin: OptiPNG.dll not in archive (${url})" >&2
    return 1
  fi
  cp "${found}" "${MARKER}"
  echo "fetch-irfanview-optipng-plugin: installed ${MARKER}"
  return 0
}

URLS=(
  "https://www.irfanview.info/files/iview475_plugins_x64.zip"
  "https://dappcdn.com/download/graphic-apps/irfanview?get=iview475_plugins_x64.zip"
  "https://www.irfanview.info/files/iv_formats.zip"
)

for url in "${URLS[@]}"; do
  if try_zip "${url}"; then
    exit 0
  fi
done

echo "fetch-irfanview-optipng-plugin: FAILED — download OptiPNG 64-bit plugin manually:" >&2
echo "  1. Install iview475_plugins_x64 from https://www.irfanview.com/64bit.htm" >&2
echo "  2. Copy Plugins/OptiPNG.dll beside tests/fixtures/irfanview/i_view64.exe" >&2
exit 1