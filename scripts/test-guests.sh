#!/bin/sh
# Builds the freestanding test guests and runs every one under droidrt.
set -u
cd "$(dirname "$0")/.."
cargo build --release 2>&1 | grep -E "^(warning|error)" -A6
case "$(uname -s)" in
    Darwin) codesign -s - -f --entitlements entitlements.plist target/release/droidrt 2>/dev/null ;;
esac
scripts/build-guests.sh >/dev/null 2>&1 || { echo "guest build failed"; exit 1; }
bad=0
for t in m2 m3 shm binder binder_nested binder_refs binder_unwind mounts creds sock selinux pty threads bpf drm locks ashmem inotify tun openrace xattr smoke clonefiles timers misc_syscalls cow uffd inet loop ifcfg mapfile regress perm fuse; do
    bin="target/guest/${t}_aarch64"
    [ -x "$bin" ] || continue
    # Only this one sees the network interface, which the others don't expect.
    net=0; [ "$t" = ifcfg ] && net=1
    out=$(DROIDRT_NET=$net DROIDRT_GPU=fake perl -e 'alarm 90; exec @ARGV' target/release/droidrt "$bin" alpha beta 2>&1)
    if printf '%s\n' "$out" | grep -q "all checks passed" && ! printf '%s\n' "$out" | grep -qE "^FAIL|panicked|internal error"; then
        printf '%-16s ok\n' "$t"
    else
        printf '%-16s FAILED\n' "$t"
        printf '%s\n' "$out" | grep -E "^FAIL|internal error|panicked" | head -5
        bad=$((bad + 1))
    fi
done
[ "$bad" -eq 0 ] && echo "all guests passed" || { echo "$bad guests failed"; exit 1; }
