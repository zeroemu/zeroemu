#!/bin/sh
# End-to-end checks against a real Android SDK system image: runs bionic's
# dynamic linker, toybox, and mksh from the image under droidrt.
#
#   scripts/test-android.sh [path/to/system.img]
#
# Defaults to the newest arm64 image in the Android SDK.
set -u
cd "$(dirname "$0")/.."

IMG="${1:-$(ls -d "$HOME"/Library/Android/sdk/system-images/android-*/*/arm64-v8a/system.img 2>/dev/null | sort -V | tail -1)}"
if [ ! -f "$IMG" ]; then
    echo "skip: no Android system image found (pass one as an argument)"
    exit 0
fi
echo "image: $IMG"

cargo build -q --release || exit 1
BIN=target/release/droidrt
case "$(uname -s)" in
    Darwin) codesign -s - -f --entitlements entitlements.plist "$BIN" 2>/dev/null ;;
esac

pass=0
fail=0
# check <name> <expected substring> <droidrt args...>
check() {
    name="$1"
    want="$2"
    shift 2
    got="$(perl -e 'alarm 60; exec @ARGV' "$BIN" --system "$IMG" "$@" 2>&1 < /dev/null)"
    if printf '%s' "$got" | grep -qF -- "$want"; then
        pass=$((pass + 1))
        echo "ok   $name"
    else
        fail=$((fail + 1))
        echo "FAIL $name: expected '$want', got:"
        printf '%s\n' "$got" | sed 's/^/       /' | tail -5
    fi
}

check "toybox echo"         "hello droidrt"       /system/bin/toybox echo hello droidrt
check "uname"               "Linux"               /system/bin/toybox uname -s
check "id"                  "uid=0(root)"         /system/bin/toybox id
check "symlink into APEX"   "-> /apex/com.android.runtime/bin/linker64" /system/bin/toybox ls -l /system/bin/linker64
check "compressed APEX"     "dalvikvm64"          /system/bin/toybox ls /apex/com.android.art/bin
check "file read"           "ro.build.version.sdk" /system/bin/toybox grep -m1 ro.build.version.sdk /system/build.prop
check "mksh arithmetic"     "42"                  /system/bin/sh -c 'x=6; echo $((x * 7))'
check "mksh glob + cwd"     "/system/bin"         /system/bin/sh -c 'cd /system/bin && set -- t*; echo "$PWD $#"'

# Exit status needs its own path: the program's code must become droidrt's.
perl -e 'alarm 60; exec @ARGV' "$BIN" --system "$IMG" /system/bin/sh -c 'exit 3' >/dev/null 2>&1
if [ $? -eq 3 ]; then pass=$((pass + 1)); echo "ok   exit code propagates"; else fail=$((fail + 1)); echo "FAIL exit code propagates"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
