#!/usr/bin/env bash
cd /weave
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq xvfb libpipewire-0.3-dev libclang-dev >/dev/null 2>&1

Xvfb :99 -screen 0 1280x720x24 &
sleep 1

DISPLAY=:99 ./docker-target/x86_64-unknown-linux-gnu/debug/weave --no-sandbox tests/fixtures/spss/stats.exe 2>/tmp/spss.log
echo "EXIT CODE: $?"

echo "=== Lines after wWinMain ==="
grep -A9999 'PHASE: wWinMain_entered' /tmp/spss.log | head -60

echo "=== Exit-related lines ==="
grep -i 'exit\|quit\|return\|cleanup\|shutdown' /tmp/spss.log | head -10

echo "=== CreateWindow lines ==="
grep -i 'create.*window\|CreateWindow' /tmp/spss.log | head -10

echo "=== Total lines ==="
wc -l /tmp/spss.log
