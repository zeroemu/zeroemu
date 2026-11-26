#!/bin/sh
# End-to-end test of devices' /data (src/devices.rs, kernel::Persist): boots named
# devices with --device, writes a file under /data with adb, stops them with SIGTERM
# (which saves /data), and boots them again to see what Android finds:
#   - a device's /data is there at its next boot;
#   - a second device of the same image has a /data of its own, both ways;
#   - --wipe-data starts it over, and what that boot saves is what the next one finds;
#   - with its data.img gone, as zeroemu.app's Wipe Data leaves it, it starts over;
#   - a place chosen with its window's Location button is saved in device.ini, one
#     saved there while it runs, as Edit… saves it, moves it at once, and it starts
#     there next time;
#   - a device that isn't there doesn't boot, and nothing is made for it.
# Eight boots, each behind your other windows, one at a time. zeroemu runs with HOME in a
# scratch folder, so your own devices are neither used nor listed; its .android is
# yours, for adbd to know your adb's key. The devices are made as zeroemu.app makes
# them: a folder in devices/ holding device.ini. One has an id as made now (its name,
# a dot and 16 hex digits), one as made before ids had that part. Finds the SDK as
# zeroemu does, and boots the image in IMG, by default the tested one, which must be
# in that SDK.
set -u
cd "$(dirname "$0")/.."
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
ADB=$SDK/platform-tools/adb
IMG=${IMG:-$SDK/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img}
ZEROEMU=$PWD/target/release/zeroemu
TMP=$(mktemp -d)
bad=0
check() { # name, then the command that must succeed
    name=$1; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; bad=$((bad + 1)); fi
}
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
settle() { t=$1; shift; while ! "$@"; do [ "$t" -gt 0 ] || return 1; sleep 1; t=$((t - 1)); done; }
pid=
stop_all() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null; rm -rf "${TMP:?}"; }
trap stop_all EXIT
trap 'exit 1' HUP INT TERM

[ -x "$ZEROEMU" ] || { echo "FAIL no $ZEROEMU: cargo build --release, then sign it"; exit 1; }
[ -x "$ADB" ] || { echo "FAIL no adb in $SDK/platform-tools"; exit 1; }
[ -f "$IMG" ] || { echo "FAIL no image $IMG"; exit 1; }
# Its SDK package, from where it is in the SDK: system-images;<level>;<tag>;<abi>.
package=$(echo "${IMG#"$SDK"/}" | awk -F/ '$1 == "system-images" && NF == 5 {print $1 ";" $2 ";" $3 ";" $4}')
[ -n "$package" ] || { echo "FAIL $IMG isn't an image in $SDK"; exit 1; }

home=$TMP/home
devices="$home/Library/Application Support/zeroemu/devices"
mkdir -p "$devices"
ln -s "$HOME/.android" "$home/.android"
make_device() { # id, name
    mkdir "$devices/$1" && printf 'name=%s\nimage=%s\n' "$2" "$package" > "$devices/$1/device.ini"
}
A_ID=phone-a.$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
B_ID=phone-b
make_device "$A_ID" "Phone A"
make_device "$B_ID" "Phone B"
z() { HOME=$home ANDROID_HOME=$SDK ZEROEMU_BACKGROUND=1 "$ZEROEMU" "$@"; }
listed() { out=$(z devices 2>&1) && echo "$out" | grep -q "^Phone A " && echo "$out" | grep -q "^Phone B "; }
check "zeroemu devices lists both" listed

# Boots a device (its --device value, then more options) and waits for Android.
boots=0
boot() {
    boots=$((boots + 1))
    log=$TMP/boot$boots.log
    # With FIFO set, it takes ZEROEMU_INPUT_FIFO lines from there (send).
    (HOME=$home ANDROID_HOME=$SDK ZEROEMU_BACKGROUND=1 exec env ${FIFO:+ZEROEMU_INPUT_FIFO="$FIFO"} "$ZEROEMU" --no-net --device "$@") > "$log" 2>&1 &
    pid=$!
    serial=
    n=0
    while [ $n -lt 120 ] && kill -0 "$pid" 2>/dev/null; do
        port=$(sed -n 's/^zeroemu: adb serial emulator-\([0-9]*\)$/\1/p' "$log" | head -1)
        if [ -n "$port" ] && [ "$(limit 10 "$ADB" -s "emulator-$port" get-state 2>/dev/null)" = device ]; then
            serial=emulator-$port
            break
        fi
        sleep 1
        n=$((n + 1))
    done
    [ -n "$serial" ] || { echo "FAIL boot $boots ($1): no device after ${n}s"; sed 's/^/     /' "$log" | tail -20; exit 1; }
    until [ "$(A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || [ $n -gt 400 ]; do sleep 1; n=$((n + 1)); done
    [ $n -le 400 ] || { echo "FAIL boot $boots ($1): Android didn't finish booting in ${n}s"; exit 1; }
    echo "ok   boot $boots: $1 booted after ${n}s"
}
A() { limit 60 "$ADB" -s "$serial" "$@"; }
# SIGTERM asks zeroemu to save /data, then exit.
halt() { # what it must have saved /data to
    kill -TERM "$pid"
    n=0
    while kill -0 "$pid" 2>/dev/null && [ $n -lt 120 ]; do sleep 1; n=$((n + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
        echo "FAIL boot $boots didn't stop in ${n}s"; kill -KILL "$pid"; wait "$pid" 2>/dev/null; pid=; exit 1
    fi
    wait "$pid" 2>/dev/null
    pid=
    check "boot $boots saved /data to its device's file" grep -qF "zeroemu: $1: saved" "$log"
}
MARK=/data/local/tmp/zeroemu-device-test
put() { A shell "echo $1 > $MARK" >/dev/null && [ "$(A shell cat $MARK | tr -d '\r')" = "$1" ]; }
has() { [ "$(A shell cat $MARK 2>/dev/null | tr -d '\r')" = "$1" ]; }
none() { ! A shell ls $MARK >/dev/null 2>&1 && A shell ls /data/local/tmp >/dev/null 2>&1; }
TOKEN_A=a-$$-$(date +%s)
TOKEN_B=b-$$-$(date +%s)
TOKEN_C=c-$$-$(date +%s)

# By name, as a user types it.
boot "Phone A"
check "a new device's /data has no mark" none
check "Phone A: a mark is written in /data" put "$TOKEN_A"
halt "$devices/$A_ID/data.img"

# By id, as zeroemu.app's list starts one.
boot "id:$B_ID"
check "Phone B, of the same image, doesn't have Phone A's mark" none
check "Phone B: its own mark is written" put "$TOKEN_B"
halt "$devices/$B_ID/data.img"

boot "Phone A"
check "Phone A's mark is there at its next boot" has "$TOKEN_A"
halt "$devices/$A_ID/data.img"

boot "Phone A" --wipe-data
check "--wipe-data: Phone A's mark is gone" none
check "Phone A: a new mark after the wipe" put "$TOKEN_C"
halt "$devices/$A_ID/data.img"

boot "id:$A_ID"
check "after the wipe, the next boot has what the wiped one saved, and not what was wiped" has "$TOKEN_C"
halt "$devices/$A_ID/data.img"

# zeroemu.app's Wipe Data (devices::Store::wipe) deletes data.img, under the lock.
rm "$devices/$B_ID/data.img"
boot "Phone B"
check "Phone B with its data.img gone starts over" none
halt "$devices/$B_ID/data.img"

# Its location. Android's GPS reports a fix only while an app asks for one: Maps, with
# the permission. Edit… in zeroemu.app's list saves device.ini as a new file put in
# place, as this does.
mkfifo "$TMP/in"
# One line to the FIFO: zeroemu reads until the writer closes, then opens it again.
send() { limit 10 sh -c 'printf "%s\n" "$1" > "$2"' - "$*" "$TMP/in"; }
ini=$devices/$A_ID/device.ini
saved_location() { grep -qx "location=$1" "$ini"; }
gps_at() { A shell dumpsys location | grep -q "last location=Location\[gps $1"; }
FIFO=$TMP/in boot "Phone A"
# The toolbar's Location button; but a toolbar customized before it was one of the
# defaults keeps the items it had (View > Customize Toolbar adds it), and then
# Device > Location, which does the same, is chosen instead.
send toolbar "location/Times Square, New York"
via="the toolbar's Location button"
if ! settle 5 saved_location times-square && grep -q 'no toolbar item "location/' "$log"; then
    echo "note no Location in your customized toolbar: Device > Location instead"
    send menu "Device/Location/Times Square, New York"
    via="Device > Location"
fi
check "$via saves the place chosen in device.ini" settle 10 saved_location times-square
A shell pm grant com.google.android.apps.maps android.permission.ACCESS_FINE_LOCATION
A shell am start -n com.google.android.apps.maps/com.google.android.maps.MapsActivity >/dev/null
check "and Android's GPS reports it" settle 60 gps_at 40.758000,-73.985500
sed 's/^location=.*/location=shibuya-crossing/' "$ini" > "$ini.new" && mv "$ini.new" "$ini"
check "a location saved in device.ini while it runs moves it at once" settle 15 gps_at 35.659500,139.700500
halt "$devices/$A_ID/data.img"
boot "Phone A"
check "it starts at the location saved last" grep -q "location Shibuya Crossing, Tokyo" "$log"
halt "$devices/$A_ID/data.img"

check "each device's /data is in its own folder" test -s "$devices/$A_ID/data.img" -a -s "$devices/$B_ID/data.img"
# An unknown id must be refused without creating a device folder.
gone=phone-c.0000000000000000
z --no-net --device "id:$gone" > "$TMP/gone.log" 2>&1
check "a device that isn't there doesn't boot" grep -q "there is no device" "$TMP/gone.log"
check "and nothing is made for it" test ! -e "$devices/$gone"

errors=$(cat "$TMP"/boot*.log | grep -E "panicked|^\[zeroemu\] internal error|won't be kept|starting with an empty /data|no toolbar item|location wasn't saved" | grep -v 'no toolbar item "location/' | head -5)
[ -z "$errors" ] || { echo "$errors" | sed 's/^/FAIL zeroemu: /'; bad=$((bad + 1)); }
[ "$bad" -eq 0 ] && echo "all device checks passed" || { echo "$bad device checks failed"; exit 1; }
