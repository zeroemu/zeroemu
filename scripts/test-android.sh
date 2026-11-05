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
check "/proc/config.gz"     "CONFIG_VMAP_STACK=y" /system/bin/sh -c 'zcat /proc/config.gz'
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
check "unshare + nsenter"   "mnt:[4026531841]"    /system/bin/sh -c 'unshare -m nsenter -t 1 -m readlink /proc/self/ns/mnt; true'
check "mount namespaces"    "inner:4026532001 outer:a" /system/bin/sh -c 'mount -t tmpfs tmpfs /mnt; echo a > /mnt/x; echo "$(unshare -m sh -c "umount /mnt; echo inner:\$(readlink /proc/self/ns/mnt | tr -dc 0-9)") outer:$(cat /mnt/x)"'
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
check "kmsg keeps digits"   "[kmsg] 12 apples"    /system/bin/sh -c 'echo "<6>12 apples" > /dev/kmsg' 
check "iptables tables keep rules" "-A oem_in -p tcp -m tcp --dport 22 -j DROP" /system/bin/sh -c 'printf "*filter\n:oem_in -\n-A INPUT -j oem_in\n-A oem_in -p tcp --dport 22 -j DROP\nCOMMIT\n" | iptables-restore && iptables -S'
check "ip6tables has the mangle hooks" "-P POSTROUTING ACCEPT" /system/bin/ip6tables -t mangle -S
check "loopback is up with its addresses" "inet 127.0.0.1/8 scope host lo" /system/bin/ip addr
check "PSI triggers are accepted" "trigger-ok" /system/bin/sh -c 'echo "some 70000 1000000" > /proc/pressure/memory && echo trigger-ok'
check "umask is per process" "drwxrwxrwx" /system/bin/sh -c 'umask 0 && mkdir /tmp/um && ls -ld /tmp/um'
check "logcat -d"           "W/t2      (    3): two"  /system/bin/sh -c 'log -t t1 one; log -p w -t t2 two; logcat -d -v brief -s t2 2>&1'
check "logcat stream"       "I/t3      (    4): live" /system/bin/sh -c 'logcat -v brief -s t3 > /data/local/tmp/o & sleep 0.3; log -t t3 live; sleep 0.3; kill %1; cat /data/local/tmp/o'
check "logcat -c"           "one=0 two=1"         /system/bin/sh -c 'log -t t one; logcat -c; log -t t two; d=$(logcat -d -s t); echo "one=$(echo "$d" | grep -c one) two=$(echo "$d" | grep -c two)"'
# extended attributes: SELinux labels from the image, tmpfs labels and xattrs
check "EROFS label"         "u:object_r:init_exec:s0 /system/bin/init" /system/bin/toybox ls -Z /system/bin/init
check "ext4 APEX label"     "u:object_r:adbd_exec:s0 /apex/com.android.adbd/bin/adbd" /system/bin/toybox ls -Z /apex/com.android.adbd/bin/adbd
check "tmpfs mount labels"  "/dev=u:object_r:device:s0 /dev/socket=u:object_r:socket_device:s0" /system/bin/sh -c 'echo $(ls -Zd /dev /dev/socket | while read c p; do echo "$p=$c"; done)'
check "chcon on tmpfs"      "u:object_r:system_file:s0 f" /system/bin/sh -c 'cd /data/local/tmp && echo x > f && chcon u:object_r:system_file:s0 f && ls -Z f'
check "setfattr/getfattr"   'user.droidrt="hello"' /system/bin/sh -c 'touch /tmp/f && setfattr -n user.droidrt -v hello /tmp/f && getfattr -d -n user.droidrt /tmp/f'
check "image is read-only"  "Read-only file system" /system/bin/toybox chcon u:object_r:shell_exec:s0 /system/bin/sh
check "restorecon relabels" "from u:object_r:system_file:s0 to u:object_r:shell_data_file:s0" /system/bin/sh -c 'touch /data/local/tmp/f && chcon u:object_r:system_file:s0 /data/local/tmp/f && restorecon -v /data/local/tmp/f 2>&1'
# credentials, limits, scheduling, process tree
check "CapEff in status"    "000001ffffffffff"    /system/bin/toybox grep CapEff /proc/self/status
check "ulimit -n"           "soft=256 hard=4096"  /system/bin/sh -c 'ulimit -Sn 256; echo "soft=$(ulimit -Sn) hard=$(ulimit -Hn)"'
check "renice"              "nice=4"              /system/bin/sh -c 'renice -n 4 -p $$ >/dev/null; echo "nice=$(cut -d" " -f19 /proc/$$/stat)"'
check "nice"                " 26 6 1 "            /system/bin/toybox nice -n 6 cat /proc/self/stat
check "chrt"                "policy: SCHED_FIFO"  /system/bin/sh -c 'chrt -f -p $$ 10; chrt -p $$'
check "ionice"              "Best-effort: prio 3" /system/bin/sh -c 'ionice -c 2 -n 3 -p $$; ionice -p $$'
check "hostname"            "droidrt-host"        /system/bin/sh -c 'hostname droidrt-host; uname -n'
check "setsid"              "own session"         /system/bin/toybox setsid /system/bin/sh -c '[ "$(cut -d" " -f6 /proc/$$/stat)" = $$ ] && echo "own session"'
check "orphan adopted by 1" "ppid=1 ok"           /system/bin/sh -c '(sh -c "sleep 0.3; echo ppid=\$(cut -d\" \" -f4 /proc/\$\$/stat) ok" &); sleep 0.6'
# Unix sockets are filesystem nodes; netlink answers
check "/dev/socket nodes"   "s-w--w--w- logd /dev/socket/logdw" /system/bin/toybox stat -c '%A %U %n' /dev/socket/logdw
check "nc -U round trip"    "server got: over a path" /system/bin/sh -c 'cd /data/local/tmp && nc -U -l -s srv > out & sleep 0.3; echo "over a path" | nc -U /data/local/tmp/srv; wait; echo "server got: $(cat /data/local/tmp/out)"'
check "socket node"         "socket 755"          /system/bin/sh -c 'nc -U -l -s /data/local/tmp/s & sleep 0.3; stat -c "%F %a" /data/local/tmp/s; kill %1'
check "unlinked socket"     "connect: No such file or directory" /system/bin/sh -c 'nc -U -l -s /data/local/tmp/s & sleep 0.3; rm /data/local/tmp/s; echo x | nc -U /data/local/tmp/s; kill %1'
# A process's socket takes over logdw (as the real logd's does); the kernel prints what it receives.
check "logd takeover tap"   "I taptest: printed by the tap" /system/bin/sh -c '(sleep 0.6; echo "printed by the tap") | log -t taptest & sleep 0.2; rm /dev/socket/logdw; nc -U -u -l -s /dev/socket/logdw 2>/dev/null & sleep 0.8'
check "logd takeover"       "kernel logd got 0"   /system/bin/sh -c '(sleep 0.6; echo "printed by the tap") | log -t taptest & sleep 0.2; rm /dev/socket/logdw; nc -U -u -l -s /dev/socket/logdw 2>/dev/null & sleep 0.8; echo "kernel logd got $(logcat -d -s taptest | grep -c tap)"'
check "netlink dumps"       "link=0 addr=0 route=0 ss=0" /system/bin/sh -c 'ip link; l=$?; ip addr; a=$?; ip route; r=$?; ss -a >/dev/null; echo "link=$l addr=$a route=$r ss=$?"'
# SELinux: selinuxfs from the image's CIL policy, process contexts
check "selinuxfs class"     "index=99 set=1"      /system/bin/sh -c 'cd /sys/fs/selinux/class/property_service; echo "index=$(cat index) set=$(cat perms/set)"'
check "attr/current"        "u:r:shell:s0"        /system/bin/toybox cat /proc/self/attr/current
check "id -Z"               "u:r:shell:s0"        /system/bin/toybox id -Z
check "compute_create"      "u:r:logd:s0"         /system/bin/sh -c 'i=$(cat /sys/fs/selinux/class/process/index); exec 3<>/sys/fs/selinux/create; echo -n "u:r:init:s0 u:object_r:logd_exec:s0 $i" >&3; cat <&3'
check "runcon"              "now u:r:logd:s0 was u:r:shell:s0" /system/bin/runcon u:r:logd:s0 /system/bin/sh -c 'echo "now $(id -Z) was $(cat /proc/$$/attr/prev)"'
check "ps -Z"               "u:r:shell:s0  "      /system/bin/toybox ps -Z
check "setenforce"          "Permissive Enforcing" /system/bin/sh -c 'a=$(getenforce); setenforce 1; echo "$a $(getenforce)"'

# Exit status needs its own path: the program's code must become droidrt's.
perl -e 'alarm 60; exec @ARGV' "$BIN" --system "$IMG" /system/bin/sh -c 'exit 3' >/dev/null 2>&1
if [ $? -eq 3 ]; then pass=$((pass + 1)); echo "ok   exit code propagates"; else fail=$((fail + 1)); echo "FAIL exit code propagates"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
