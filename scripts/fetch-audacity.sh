#!/usr/bin/env bash
# Fetch Audacity portable 64-bit for Phase A probe.
set -euo pipefail

DEST_DIR="tests/fixtures/audacity"
DEST_EXE="$DEST_DIR/audacity.exe"

# Check for a representative DLL rather than the exe — the exe is committed
# to git but the DLLs must be downloaded. If the DLLs are already present
# (e.g. from a prior CI run), skip.
if [ -f "$DEST_DIR/wxmsw313u_core_vc_x64_custom.dll" ]; then
    echo "Audacity DLLs already present at $DEST_DIR"
    exit 0
fi

python3 << 'PYEOF'
import json, urllib.request, zipfile, os, shutil

req = urllib.request.urlopen('https://api.github.com/repos/audacity/audacity/releases/latest')
release = json.load(req)
tag = release['tag_name']
print(f'Audacity latest: {tag}')

for asset in release['assets']:
    name = asset['name']
    if name.endswith('-64bit.zip') and 'win-' in name.lower():
        print(f'Downloading {name}...')
        urllib.request.urlretrieve(asset['browser_download_url'], '/tmp/audacity.zip')
        with zipfile.ZipFile('/tmp/audacity.zip', 'r') as zf:
            zf.extractall('/tmp/audacity_extracted')
        extract_dir = '/tmp/audacity_extracted'
        with zipfile.ZipFile('/tmp/audacity.zip', 'r') as zf:
            zf.extractall(extract_dir)
        # Find the extracted directory (contains a versioned subfolder).
        items = os.listdir(extract_dir)
        # Copy all DLLs and the exe into the fixture dir.
        for item in items:
            item_path = os.path.join(extract_dir, item)
            if os.path.isdir(item_path):
                # Versioned subfolder — copy contents.
                for root, dirs, files in os.walk(item_path):
                    for f in files:
                        if f.lower().endswith('.exe') or f.lower().endswith('.dll'):
                            src = os.path.join(root, f)
                            shutil.copy2(src, os.path.join('tests/fixtures/audacity/', f))
                        if f.lower().endswith('.xml') or f.lower() == 'license.txt':
                            src = os.path.join(root, f)
                            shutil.copy2(src, os.path.join('tests/fixtures/audacity/', f))
        print(f'Copied Audacity bundle to tests/fixtures/audacity/')
        break
else:
    print('ERROR: no portable zip found for', tag)
    exit(1)
PYEOF

ls -la tests/fixtures/audacity/
