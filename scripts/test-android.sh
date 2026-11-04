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
# M2: processes, pipes, signals
check "command substitution" "[nested]"           /system/bin/sh -c 'echo "[$(echo nested)]"'
check "pipeline"            "404"                 /system/bin/sh -c 'ls /system/bin | wc -l'
check "4-stage pipeline"    "ro.build.date="      /system/bin/sh -c 'cat /system/build.prop | grep ro.build | sort | head -3'
check "subshell status"     "status 3"            /system/bin/sh -c '(exit 3); echo "status $?"'
check "background + wait"   "bg exited 0"         /system/bin/sh -c 'sleep 0.2 & wait $!; echo "bg exited $?"'
check "trap handler"        "caught USR1"         /system/bin/sh -c 'trap "echo caught USR1" USR1; kill -USR1 $$; echo after'
check "SIGTERM a child"     "status 143"          /system/bin/sh -c 'sleep 5 & p=$!; sleep 0.3; kill $p; wait $p; echo "status $?"'
check "while read pipe"     "apex: com.android.adbd" /system/bin/sh -c 'ls /apex | head -1 | while read a; do echo "apex: $a"; done'
# writable filesystems, /proc, /sys
check "write /data"         "hello tmpfs"         /system/bin/sh -c 'echo "hello tmpfs" > /data/local/tmp/a && cat /data/local/tmp/a'
check "mkdir/cp/mv/rm"      "moved"               /system/bin/sh -c 'cd /data/local/tmp && mkdir -p d/e && echo x > f && cp f d/e/g && mv d/e/g d/h && rm f && ls d && echo moved'
check "/system read-only"   "ro"                  /system/bin/sh -c 'test -w /system || echo ro'
check "/dev/null node"      "crw-rw-rw-"          /system/bin/toybox ls -l /dev/null
check "ps"                  "toybox"              /system/bin/toybox ps -A -o NAME
check "/proc/self/maps"     "/system/bin/toybox"  /system/bin/toybox cat /proc/self/maps
check "/proc/self/fd"       "/dev/pts/0"          /system/bin/toybox ls -l /proc/self/fd
check "mount"               "on /data type tmpfs" /system/bin/toybox mount
check "nproc via /sys"      "0-"                  /system/bin/toybox cat /sys/devices/system/cpu/possible
# mount(2), namespaces, kernel tunables
check "mount tmpfs + umount" "in=x after=."       /system/bin/sh -c 'mount -t tmpfs -o size=1m tmpfs /mnt && touch /mnt/x && echo "in=$(ls /mnt) after=$(umount /mnt; ls /mnt)."'
check "bind mount a dir"    "bound:hi"            /system/bin/sh -c 'cd /data/local/tmp && mkdir a b && echo hi > a/f && mount --bind /data/local/tmp/a /data/local/tmp/b && echo "bound:$(cat b/f)"'
check "bind mount a file"   "file:one"            /system/bin/sh -c 'cd /data/local/tmp && echo one > f1 && touch f2 && mount --bind /data/local/tmp/f1 /data/local/tmp/f2 && echo "file:$(cat f2)"'
check "remount ro: EROFS"   "/mnt/x': Read-only file system" /system/bin/sh -c 'mount -t tmpfs tmpfs /mnt && mount -o remount,ro /mnt && touch /mnt/x'
check "open fd sees remount ro" "ro-fd:1"       /system/bin/sh -c 'mount -t tmpfs tmpfs /mnt && echo x > /mnt/f && exec 3>/mnt/f && mount -o remount,ro /mnt && echo y >&3; echo ro-fd:$?'
check "touch on ro tmpfs"    "touch-ro:1"        /system/bin/sh -c 'mount -t tmpfs tmpfs /mnt && echo x > /mnt/f && mount -o remount,ro /mnt && touch /mnt/f; echo touch-ro:$?'
check "touch image file"     "touch-img:0"       /system/bin/sh -c 'touch /system/build.prop; echo touch-img:$?'
check "mountinfo"           " / /data/local/tmp rw,nosuid,relatime - tmpfs tmpfs rw,seclabel,mode=700" /system/bin/sh -c 'mount -t tmpfs -o nosuid,mode=0700 tmpfs /data/local/tmp && cat /proc/self/mountinfo'
check "mkdir -p over mounts" "made"               /system/bin/sh -c 'mkdir -p /data/local/tmp/x/y && echo made'
check "sysctl write"        "panic=7 host=droid"  /system/bin/sh -c 'echo 7 > /proc/sys/kernel/panic; echo droid > /proc/sys/kernel/hostname; echo "panic=$(cat /proc/sys/kernel/panic) host=$(uname -n)"'
check "oom_score_adj"       "adj=-500 legacy=-8"  /system/bin/sh -c 'echo -500 > /proc/self/oom_score_adj; echo "adj=$(cat /proc/$$/oom_score_adj) legacy=$(cat /proc/$$/oom_adj)"'
check "cgroup v1"           "1:cpu:/fg"           /system/bin/sh -c 'mkdir /dev/cpuctl && mount -t cgroup -o cpu none /dev/cpuctl && mkdir /dev/cpuctl/fg && echo $$ > /dev/cpuctl/fg/cgroup.procs && cat /proc/self/cgroup'
check "unshare + nsenter"   "mnt:[4026531841]"    /system/bin/sh -c 'unshare -m nsenter -t 1 -m readlink /proc/self/ns/mnt'
# A loop device over an APEX's ext4 payload (a stored zip entry), mounted like apexd does.
SHIM=/system/apex/com.android.apex.cts.shim.apex
OFF=$("$BIN" --system "$IMG" --cat $SHIM | perl -0777 -ne '$h = index($_, "apex_payload.img") - 30; ($n, $e) = unpack("v v", substr($_, $h + 26, 4)); print $h + 30 + $n + $e')
check "block device mount"  "mounted apex_manifest.pb, detached" /system/bin/sh -c "losetup -r -o $OFF /dev/block/loop0 $SHIM && mkdir /data/local/tmp/m && mount -t ext4 -o ro /dev/block/loop0 /data/local/tmp/m && l=\$(ls /data/local/tmp/m | head -1) && umount -D /data/local/tmp/m && losetup -d /dev/block/loop0 && echo \"mounted \$l, detached\""
check "apexd --bootstrap"   "/apex/com.android.runtime/bin/linker64" /system/bin/sh -c 'mount -t tmpfs tmpfs /apex && apexd --bootstrap 2>/dev/null && ls /apex/com.android.runtime/bin/linker64'
# properties and binder
check "getprop"             "16"                  /system/bin/getprop ro.build.version.release
check "derived fingerprint" "release-keys"        /system/bin/getprop ro.build.fingerprint
check "setprop round trip"  "value=world"         /system/bin/sh -c 'setprop debug.droidrt.t world && echo "value=$(getprop debug.droidrt.t)"'
check "ro.* is read-only"   "still 36"            /system/bin/sh -c 'setprop ro.build.version.sdk 1 2>/dev/null; echo "still $(getprop ro.build.version.sdk)"'
check "servicemanager"      "manager: [android.os.IServiceManager]" /system/bin/sh -c 'servicemanager 2>/dev/null & sleep 0.5; service list; kill %1'
check "service check"       "Service manager: found" /system/bin/sh -c 'servicemanager 2>/dev/null & sleep 0.5; service check manager; kill %1'
# logd (kernel-side): records print to stderr and read back through logcat
check "log to stderr"       "I droidrt-test: hello log" /system/bin/log -t droidrt-test "hello log"
check "logcat -d"           "W/t2      (    3): two"  /system/bin/sh -c 'log -t t1 one; log -p w -t t2 two; logcat -d -v brief -s t2 2>&1'
check "logcat stream"       "I/t3      (    4): live" /system/bin/sh -c 'logcat -v brief -s t3 > /data/local/tmp/o & sleep 0.3; log -t t3 live; sleep 0.3; kill %1; cat /data/local/tmp/o'
check "logcat -c"           "one=0 two=1"         /system/bin/sh -c 'log -t t one; logcat -c; log -t t two; d=$(logcat -d -s t); echo "one=$(echo "$d" | grep -c one) two=$(echo "$d" | grep -c two)"'

# Exit status needs its own path: the program's code must become droidrt's.
perl -e 'alarm 60; exec @ARGV' "$BIN" --system "$IMG" /system/bin/sh -c 'exit 3' >/dev/null 2>&1
if [ $? -eq 3 ]; then pass=$((pass + 1)); echo "ok   exit code propagates"; else fail=$((fail + 1)); echo "FAIL exit code propagates"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
