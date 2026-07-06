#!/usr/bin/env bash
set -e

cd /weave
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq xvfb libpipewire-0.3-dev libclang-dev gdb strace >/dev/null 2>&1

Xvfb :99 -screen 0 1280x720x24 &
sleep 1

DISPLAY=:99 ./docker-target/x86_64-unknown-linux-gnu/debug/weave --no-sandbox tests/fixtures/spss/stats.exe 2>/dev/null &
WPID=$!
sleep 4

if kill -0 $WPID 2>/dev/null; then
    echo "=== Process RUNNING (PID $WPID) ==="
    echo "=== Threads ==="
    ps -T -p $WPID -o spid,comm 2>&1 || true
    
    echo "=== /proc/<pid>/status ==="
    grep -E 'State|SigBlk|SigCgt' /proc/$WPID/status 2>/dev/null || true
    
    echo "=== /proc/<pid>/wchan ==="
    cat /proc/$WPID/wchan 2>/dev/null || echo "no wchan"
    
    echo "=== Quick strace summary (0.5s) ==="
    timeout 0.5 strace -p $WPID -e trace=all -c 2>&1 || true
else
    echo "=== Process EXITED ==="
fi

kill $WPID 2>/dev/null
wait $WPID 2>/dev/null
