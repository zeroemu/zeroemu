#!/bin/sh
# Cargo runner: Hypervisor.framework refuses to create VMs unless the binary
# carries the com.apple.security.hypervisor entitlement, so sign before running.
set -e
bin="$1"; shift
codesign -s - -f --entitlements "$(dirname "$0")/../entitlements.plist" "$bin" 2>/dev/null
exec "$bin" "$@"
