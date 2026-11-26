#!/bin/sh
# End-to-end test of the window's device controls (src/gpu/controls.rs): boots behind
# your other windows, with /data in a scratch file, does each control through
# ZEROEMU_INPUT_FIFO's `action` lines, and many the ways a user would too, through its
# `menu`, `toolbar`, `keyeq` and `click` lines: Device menu items, toolbar items,
# shortcuts and a click on a turned screen. adb checks what Android did; screenshots
# are compared with Android's own screencap. Ends with Quit from the menu bar, which
# must save /data and exit 0. Finds the SDK as zeroemu does, and boots the image in
# IMG, by default the tested one; the launcher checks know the tested image's
# launcher. The toolbar check expects Back in the toolbar, where it is unless you
# took it out (View > Customize Toolbar).
set -u
cd "$(dirname "$0")/.."
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
ADB=$SDK/platform-tools/adb
IMG=${IMG:-$SDK/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img}
LAUNCHER=com.google.android.apps.nexuslauncher/.NexusLauncherActivity
TMP=$(mktemp -d)
bad=0
check() { # name, then the command that must succeed
    name=$1; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name (focus: $(focused))"; bad=$((bad + 1)); fi
}
# What has the focus, for a failure's message: nothing before adb is up.
focused() { [ -n "${serial:-}" ] && limit 30 "$ADB" -s "$serial" shell dumpsys window 2>/dev/null | grep -m1 mCurrentFocus | sed 's/^ *mCurrentFocus=//'; }
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
# Tries a check for up to that many seconds: Android takes its time over some.
settle() { t=$1; shift; while ! "$@"; do [ "$t" -gt 0 ] || return 1; sleep 1; t=$((t - 1)); done; }

mkfifo "$TMP/in"
mkdir "$TMP/shots"
ZEROEMU_BACKGROUND=1 ZEROEMU_INPUT_FIFO="$TMP/in" ZEROEMU_SCREENSHOTS="$TMP/shots" \
    target/release/zeroemu --system "$IMG" --boot --data "$TMP/data.img" > "$TMP/boot.log" 2>&1 &
pid=$!
stop() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "${TMP:?}"; }
trap stop EXIT
# One line to the FIFO: zeroemu reads until the writer closes, then opens it again.
send() { limit 10 sh -c 'printf "%s\n" "$1" > "$2"' - "$*" "$TMP/in"; }

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
A() { limit 60 "$ADB" -s "$serial" "$@"; }
until [ "$(A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || [ $n -gt 240 ]; do sleep 1; n=$((n + 1)); done
echo "ok   booted after ${n}s"

focus_is() { A shell dumpsys window | grep -m1 mCurrentFocus | grep -q "$1"; }
# Something else has the focus: only once adb has said what does.
not_focus() { f=$(A shell dumpsys window | grep -m1 mCurrentFocus) && [ -n "$f" ] && ! echo "$f" | grep -q "$1"; }
launcher_in() { A shell dumpsys activity "$LAUNCHER" | grep -m1 -q "mState:$1"; }
wakefulness() { A shell dumpsys power | grep -m1 -q "mWakefulness=$1"; }
rotation() { A shell dumpsys window displays | grep -m1 -q "mRotation=$1"; }
music() { A shell cmd media_session volume --stream 3 --get | grep -o 'volume is [0-9]*' | grep -o '[0-9]*$'; }
music_muted() { A shell dumpsys audio | awk '/^- STREAM_MUSIC:/ {f = 1} f && /Muted:/ {print $2; exit}' | tr -d '\r'; }
is_muted() { [ "$(music_muted)" = "$1" ]; }
louder_than() { [ "$(music)" -gt "$1" ]; }
quieter_than() { [ "$(music)" -lt "$1" ]; }
# The newest screenshot shows what Android's own screencap does: the same size and, but
# for a few pixels (the clock may tick between them), the same picture, the same way up.
same_picture() { # two images sips can read
    sips -s format bmp "$1" --out "$TMP/a.bmp" >/dev/null 2>&1 && sips -s format bmp "$2" --out "$TMP/b.bmp" >/dev/null 2>&1 &&
        python3 -I - "$TMP/a.bmp" "$TMP/b.bmp" <<'PY'
import struct, sys
def load(p):
    b = open(p, 'rb').read()
    off, = struct.unpack_from('<I', b, 10)
    w, h = struct.unpack_from('<ii', b, 18)
    bpp, = struct.unpack_from('<H', b, 28)
    row = ((w * bpp + 31) // 32) * 4
    return w, abs(h), b, off, row, bpp // 8, h > 0
a, c = load(sys.argv[1]), load(sys.argv[2])
if a[:2] != c[:2]:
    sys.exit(1)
w, h = a[:2]
def px(img, x, y):
    _, h, b, off, row, step, up = img
    i = off + (h - 1 - y if up else y) * row + x * step
    return b[i:i + 3]
far = sum(1 for y in range(0, h, 4) for x in range(0, w, 4) if max(abs(p - q) for p, q in zip(px(a, x, y), px(c, x, y))) > 24)
sys.exit(0 if far * 16 < w * h * 0.02 else 1)
PY
}
matches_screencap() {
    shot=$(ls -t "$TMP"/shots/*.png 2>/dev/null | head -1)
    [ -n "$shot" ] && A exec-out screencap -p > "$TMP/android.png" && same_picture "$shot" "$TMP/android.png"
}
landscape() { sips -g pixelWidth -g pixelHeight "$(ls -t "$TMP"/shots/*.png 2>/dev/null | head -1)" 2>/dev/null | awk '/Width/ {w = $2} /Height/ {h = $2} END {exit !(w > h)}'; }
landscape_as_shown() { landscape && matches_screencap; }
android_shots() { A shell ls /sdcard/Pictures/Screenshots 2>/dev/null | grep -c png; }
more_android_shots() { [ "$(android_shots)" -gt "$1" ]; }
go_home() { send action home; settle 5 focus_is nexuslauncher; }
settle 60 focus_is nexuslauncher || echo "     (the launcher isn't up yet)"
# Settings' first start on a new /data took 75 s once, while Android did its own
# first-boot work. Started once here, so that the checks time the controls.
A shell am start -a android.settings.SETTINGS >/dev/null 2>&1
settle 180 focus_is com.android.settings || echo "     (Settings took over 180 s to start)"
go_home

generic() { A shell dumpsys input | grep -A10 'zeroemu_buttons' | grep -q 'KeyLayoutFile: /system/usr/keylayout/Generic.kl'; }
check "the buttons device has Android's Generic.kl" generic

# The Device menu's actions, by name.
send action settings
check "Android Settings opens Settings" settle 30 focus_is com.android.settings
send action back
check "Back leaves it" settle 10 focus_is nexuslauncher
send action settings; settle 30 focus_is com.android.settings
send action home
check "Home goes to the launcher" settle 10 focus_is nexuslauncher
send action settings; settle 10 focus_is com.android.settings
send action recents
check "Recent Apps shows Overview" settle 10 launcher_in Overview
go_home
send action notifications
check "Notifications opens the shade" settle 10 focus_is NotificationShade
send action notifications
check "and closes it" settle 10 focus_is nexuslauncher

before=$(music)
send action volume-up; sleep 1; send action volume-up
check "Volume Up turns the media volume up" settle 10 louder_than "$before"
before=$(music)
send action volume-down
check "Volume Down turns it down" settle 10 quieter_than "$before"
send action mute
check "Mute mutes it" settle 10 is_muted true
send action mute
check "and unmutes it" settle 10 is_muted false

send action power-menu
check "Power Menu shows the power menu" settle 10 focus_is GlobalActions
# Closed, and given time to go: a Power press while it's still on its way out is its.
send action back; settle 10 focus_is nexuslauncher; sleep 3
send action power
check "Power puts the device to sleep" settle 10 wakefulness Asleep
send action home
sleep 2
check "Home doesn't wake it, as on a phone" wakefulness Asleep
send action power
check "Power wakes it" settle 10 wakefulness Awake
A shell wm dismiss-keyguard; go_home
send action lock
check "Lock Screen puts it to sleep" settle 10 wakefulness Asleep
send action power; settle 10 wakefulness Awake; A shell wm dismiss-keyguard; go_home

shots=$(android_shots)
send action android-screenshot
check "Take Screenshot in Android saves one on the device" settle 15 more_android_shots "$shots"
go_home

# Turning: the launcher stays upright on a phone, so Settings shows it.
send action settings; settle 10 focus_is com.android.settings
sleep 2
send action screenshot
check "Save Screenshot saves what Android shows" settle 10 matches_screencap
send action rotate-left
check "Rotate Left turns Android to 90 degrees" settle 10 rotation 1
sleep 2
rm -f "$TMP"/shots/*.png
send action screenshot
check "and the screenshot is landscape, the right way up" settle 10 landscape_as_shown
# A click where the user sees the top left part of the turned screen lands on the
# panel where that is: turned left, the shown picture's (0.25, 0.1) is the panel's
# (0.9, 0.25), its top edge now on the left.
touch_at() { # the shown U and V, then the panel's X and Y it must land on, as fractions
    range=$(A shell getevent -lp /dev/input/event0 | tr -d '\r' | awk '/ABS_MT_POSITION_[XY]/ {for (i = 1; i <= NF; i++) if ($i == "max") printf "%d ", $(i + 1)}')
    limit 15 "$ADB" -s "$serial" shell getevent -l -c 8 /dev/input/event0 > "$TMP/touch" 2>/dev/null &
    reader=$!
    sleep 2
    send click "$1" "$2"
    sleep 3
    kill $reader 2>/dev/null; wait $reader 2>/dev/null
    x=$(awk '/ABS_MT_POSITION_X/ {print $3; exit}' "$TMP/touch" | tr -d '\r')
    y=$(awk '/ABS_MT_POSITION_Y/ {print $3; exit}' "$TMP/touch" | tr -d '\r')
    [ -n "$x" ] && [ -n "$y" ] && [ -n "$range" ] || return 1
    awk -v x="$(printf %d "0x$x")" -v y="$(printf %d "0x$y")" -v range="$range" -v want_x="$3" -v want_y="$4" \
        'BEGIN { split(range, m, " "); dx = x / m[1] - want_x; dy = y / m[2] - want_y; exit !(m[1] > 0 && dx * dx < 0.0004 && dy * dy < 0.0004) }'
}
check "a click on the turned screen lands where it's shown" touch_at 0.25 0.1 0.9 0.25
# It may have opened something (Settings' search bar is there): back to Settings.
# Search opens with the keyboard up, and the first Back only closes the keyboard; left
# open, the search comes back on top of Settings for the menu bar's checks below.
for _ in 1 2 3; do
    focus_is com.android.settings/ && break
    send action back; settle 5 focus_is com.android.settings/
done
send action rotate-right
check "Rotate Right turns it back" settle 10 rotation 0
send action rotate-right
check "and on to 270 degrees" settle 10 rotation 3
send action rotate-left
settle 10 rotation 0
send shot "$TMP/raw.bmp"
check "the FIFO's shot saves the frame on show" settle 10 test -s "$TMP/raw.bmp"

# The same actions through the menu bar, the toolbar and their shortcuts.
go_home
send menu "Device/Android Settings"
check "the Device menu's Android Settings" settle 10 focus_is com.android.settings
send toolbar back
check "the toolbar's Back" settle 10 focus_is nexuslauncher
send keyeq cmd 34 i
check "Command-I opens Settings" settle 10 focus_is com.android.settings
send keyeq cmd 33 '['
check "Command-[ goes back" settle 10 focus_is nexuslauncher
send action settings; settle 10 focus_is com.android.settings
send keyeq cmd+shift 4 H
check "Shift-Command-H goes home" settle 10 focus_is nexuslauncher
send action settings; settle 10 focus_is com.android.settings
send keyeq cmd+shift 15 R
check "Shift-Command-R shows Overview" settle 10 launcher_in Overview
go_home
send keyeq cmd 45 n
check "Command-N opens the notifications" settle 10 focus_is NotificationShade
send keyeq cmd 45 n
settle 10 focus_is nexuslauncher
send action settings; settle 10 focus_is com.android.settings
send keyeq cmd 123 left
check "Command-Left turns it left" settle 10 rotation 1
send keyeq cmd 124 right
check "Command-Right turns it back" settle 10 rotation 0
send toolbar rotate-right
check "the toolbar's Rotate turns it right" settle 10 rotation 3
send menu "Device/Rotate Left"
check "the Device menu's Rotate Left" settle 10 rotation 0
send menu "Device/Rotate Right"
check "the Device menu's Rotate Right" settle 10 rotation 3
send action rotate-left
settle 10 rotation 0
rm -f "$TMP"/shots/*.png
send menu "File/Save Screenshot"
check "File > Save Screenshot" settle 10 matches_screencap
send action settings; settle 10 focus_is com.android.settings
send keyeq none 53 x
check "Escape, without Command, still reaches Android as Back" settle 10 focus_is nexuslauncher

# Quit saves /data, as closing the window does, and zeroemu exits by itself.
send menu "zeroemu/Quit zeroemu"
n=0
while kill -0 "$pid" 2>/dev/null && [ $n -lt 90 ]; do sleep 1; n=$((n + 1)); done
# Still running is a failure, which the EXIT trap then stops.
if kill -0 "$pid" 2>/dev/null; then status=running; else wait "$pid"; status=$?; fi
quit_saves() { [ "$status" = 0 ] && grep -q "saved [0-9]* MB" "$TMP/boot.log"; }
check "Quit saves /data and exits 0 (after ${n}s)" quit_saves

errors=$(grep -E "panicked|^\[zeroemu\] internal error|^zeroemu: (couldn't save a screenshot|no menu item|no toolbar item|no action|click wants|keyeq wants)" "$TMP/boot.log" | head -5)
[ -z "$errors" ] || { echo "$errors" | sed 's/^/FAIL zeroemu: /'; bad=$((bad + 1)); }
[ "$bad" -eq 0 ] && echo "all control checks passed" || { echo "$bad control checks failed"; exit 1; }
