#!/bin/sh
# End-to-end test of host adb against a booted device: boots (ephemeral), then uses the
# real adb tool. The device appears in the running adb server as emulator-NNNN for
# the length of the test. Needs ANDROID_HOME or the SDK in its usual place, and the image
# in IMG. A private adb server, on its own port and with its own key, checks that a key
# adbd doesn't know is refused.
set -u
cd "$(dirname "$0")/.."
SDK=${ANDROID_HOME:-$HOME/Library/Android/sdk}
ADB=$SDK/platform-tools/adb
IMG=${IMG:-$SDK/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img}
TMP=$(mktemp -d)
bad=0
check() { # name, then the command that must succeed
    name=$1; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; bad=$((bad + 1)); fi
}
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }

DROIDRT_BACKGROUND=1 target/release/droidrt --system "$IMG" --boot --ephemeral > "$TMP/boot.log" 2>&1 &
pid=$!
stop() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "${TMP:?}"; }
trap stop EXIT

# This boot's device: the first emulator port in the log's listener, as adb lists it.
serial=
n=0
while [ $n -lt 120 ]; do
    port=$(lsof -nP -a -p "$pid" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {split($9, a, ":"); print a[2]}' | sort -n | head -1)
    if [ -n "$port" ] && [ "$($ADB -s "emulator-$port" get-state 2>/dev/null)" = device ]; then
        serial=emulator-$port
        break
    fi
    sleep 1
    n=$((n + 1))
done
[ -n "$serial" ] || { echo "FAIL no device after ${n}s"; exit 1; }
echo "ok   $serial is a device after ${n}s"
A() { limit 120 "$ADB" -s "$serial" "$@"; }
until [ "$(A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || [ $n -gt 240 ]; do sleep 1; n=$((n + 1)); done
echo "ok   booted after ${n}s"

shell_is_shell() { A shell id | grep -q 'uid=2000(shell)'; }
check "adb shell runs as shell" shell_is_shell
props() { [ "$(A shell getprop service.adb.listen_addrs | tr -d '\r')" = vsock:5555 ]; }
check "adbd listens on vsock only" props
logs() { A logcat -d -t 1 | grep -q .; }
check "logcat" logs

head -c 104857600 /dev/urandom > "$TMP/big"
want=$(shasum -a 256 "$TMP/big" | cut -d' ' -f1)
pushes() { A push "$TMP/big" /data/local/tmp/big >/dev/null && [ "$(A shell sha256sum /data/local/tmp/big | cut -d' ' -f1)" = "$want" ]; }
check "100 MB push arrives intact" pushes
pulls() { A pull /data/local/tmp/big "$TMP/back" >/dev/null && [ "$(shasum -a 256 "$TMP/back" | cut -d' ' -f1)" = "$want" ]; }
check "100 MB pull comes back intact" pulls
A shell rm /data/local/tmp/big

screenshot() { A exec-out screencap -p > "$TMP/shot.png" && [ "$(head -c 4 "$TMP/shot.png" | tail -c 3)" = PNG ]; }
check "screencap" screenshot
key() { A shell input keyevent 3; }
check "input" key
apk=$(A shell 'ls -S /system/app/*/*.apk 2>/dev/null | tail -1' | tr -d '\r')
A pull "$apk" "$TMP/t.apk" >/dev/null
installs() { A install -r "$TMP/t.apk" | grep -q Success; }
check "install" installs
again() { A reconnect >/dev/null; sleep 4; A shell true; }
check "reconnect" again

# A key it doesn't know: the same device, as another user's adb server would see it.
mkdir -p "$TMP/home/.android"
refused() {
    out=$(HOME=$TMP/home ANDROID_ADB_SERVER_PORT=5099 ANDROID_USER_HOME=$TMP/home/.android limit 30 "$ADB" devices 2>/dev/null)
    sleep 3
    out=$(HOME=$TMP/home ANDROID_ADB_SERVER_PORT=5099 ANDROID_USER_HOME=$TMP/home/.android limit 30 "$ADB" devices 2>/dev/null)
    HOME=$TMP/home ANDROID_ADB_SERVER_PORT=5099 "$ADB" kill-server 2>/dev/null
    echo "$out" | grep -q "$serial.*unauthorized"
}
check "a key adbd doesn't know is refused" refused

[ "$bad" -eq 0 ] && echo "all adb checks passed" || { echo "$bad adb checks failed"; exit 1; }
