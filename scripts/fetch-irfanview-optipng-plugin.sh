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

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# irfanview.info serves an HTML interstitial on the first GET; the second GET
# (same URL, session cookie + Referer) returns the real zip. See FAQ "second click".
fetch_zip() {
  local url="$1"
  local zip="${TMP}/plugins.zip"
  local cj="${TMP}/cookies.txt"
  curl -fsSL -c "${cj}" -A "${UA}" -o /dev/null "${url}"
  curl -fsSL -b "${cj}" -A "${UA}" -H "Referer: ${url}" -o "${zip}" "${url}"
  if ! file "${zip}" | grep -qi 'zip archive'; then
    echo "fetch-irfanview-optipng-plugin: not a zip (${url})" >&2
    return 1
  fi
  echo "${zip}"
}

extract_optipng() {
  local zip="$1"
  if unzip -p "${zip}" OptiPNG.dll > "${MARKER}" 2>/dev/null; then
    return 0
  fi
  unzip -q -o "${zip}" -d "${TMP}/extract" '*/OptiPNG.dll' 'OptiPNG.dll' 2>/dev/null || true
  local found
  found="$(find "${TMP}/extract" -iname 'OptiPNG.dll' -print -quit 2>/dev/null || true)"
  if [[ -z "${found}" ]]; then
    return 1
  fi
  cp "${found}" "${MARKER}"
}

URLS=(
  "https://www.irfanview.info/files/iview475_plugins_x64.zip"
  "https://www.irfanview.info/files/iv_formats.zip"
)

for url in "${URLS[@]}"; do
  echo "fetch-irfanview-optipng-plugin: trying ${url}"
  if zip="$(fetch_zip "${url}" 2>/dev/null)" && extract_optipng "${zip}"; then
    echo "fetch-irfanview-optipng-plugin: installed ${MARKER}"
    exit 0
  fi
done

echo "fetch-irfanview-optipng-plugin: FAILED — download OptiPNG 64-bit plugin manually:" >&2
echo "  1. Install iview475_plugins_x64 from https://www.irfanview.com/64bit.htm" >&2
echo "  2. Copy Plugins/OptiPNG.dll beside tests/fixtures/irfanview/i_view64.exe" >&2
exit 1