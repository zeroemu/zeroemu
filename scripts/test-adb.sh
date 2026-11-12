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

# Shared storage: vold mounts the emulated volume on /dev/fuse, which droidrt serves
# from /data/media, and MediaProvider makes the standard directories on it.
until A shell ls /sdcard/Download >/dev/null 2>&1 || [ $n -gt 300 ]; do sleep 1; n=$((n + 1)); done
mounted() { A shell sm list-volumes | grep -q "emulated;0 mounted"; }
check "vold mounts the emulated volume" mounted
standard() { out=$(A shell ls -la /sdcard/); for d in Android DCIM Download Music Pictures; do echo "$out" | grep -q " $d" || return 1; done; }
check "ls -la /sdcard/ lists the standard directories" standard
echoes() { [ "$(A shell 'echo hi > /sdcard/Download/t.txt && cat /sdcard/Download/t.txt' | tr -d '\r')" = hi ]; }
check "write and read a file in /sdcard/Download" echoes
round_trip() { # MB
    head -c $(($1 << 20)) /dev/urandom > "$TMP/sd$1"
    A push "$TMP/sd$1" /sdcard/Download/ >/dev/null && A pull /sdcard/Download/sd$1 "$TMP/sdback$1" >/dev/null && cmp -s "$TMP/sd$1" "$TMP/sdback$1"
}
check "1 MB push and pull through /sdcard" round_trip 1
check "50 MB push and pull through /sdcard" round_trip 50
A shell rm /sdcard/Download/sd1 /sdcard/Download/sd50 /sdcard/Download/t.txt

# An app's external files directory: scripts/sdtest writes one file there on start, as
# its own uid, through vold's setupAppDir. Built here when the SDK's build tools and a
# JDK are installed.
BT=$(ls -d "$SDK"/build-tools/* 2>/dev/null | tail -1)
PLAT=$(ls -d "$SDK"/platforms/android-* 2>/dev/null | head -1)/android.jar
build_sdtest() {
    S=scripts/sdtest O=$TMP/sdtest
    mkdir -p "$O/classes" "$O/dex" &&
    javac --release 8 -nowarn -cp "$PLAT" -d "$O/classes" "$S/src/org/droidrt/sdtest/Main.java" 2>/dev/null &&
    "$BT/d8" --min-api 30 --lib "$PLAT" --output "$O/dex" "$O"/classes/org/droidrt/sdtest/*.class &&
    "$BT/aapt2" link -o "$O/base.apk" -I "$PLAT" --manifest "$S/AndroidManifest.xml" &&
    (cd "$O/dex" && zip -q ../base.apk classes.dex) &&
    "$BT/zipalign" -f 4 "$O/base.apk" "$O/aligned.apk" &&
    keytool -genkeypair -keystore "$O/key" -storepass android -keypass android -alias k -keyalg RSA -keysize 2048 -validity 1 -dname CN=droidrt >/dev/null 2>&1 &&
    "$BT/apksigner" sign --ks "$O/key" --ks-pass pass:android --out "$TMP/sdtest.apk" "$O/aligned.apk"
}
external_files() {
    A install -r "$TMP/sdtest.apk" | grep -q Success && A shell am start -W -n org.droidrt.sdtest/.Main >/dev/null || return 1
    uid=$(A shell pm list packages -U org.droidrt.sdtest | sed -n 's/.*uid://p' | tr -d '\r')
    f=/sdcard/Android/data/org.droidrt.sdtest/files/hello.txt
    m=0
    until A shell ls -ln $f 2>/dev/null | grep -q " $uid "; do sleep 1; m=$((m + 1)); [ $m -gt 20 ] && return 1; done
}
if [ -n "$BT" ] && [ -f "$PLAT" ] && command -v javac >/dev/null && build_sdtest; then
    check "an app writes its external files directory as its own uid" external_files
else
    echo "skip an app's external files directory: no build tools, platform or JDK"
fi

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
