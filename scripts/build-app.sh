#!/bin/sh
# Builds zeroemu.app: the release binary in a Mac app bundle with its icon and
# Info.plist (packaging/macos), signed ad hoc with the hypervisor entitlement, as
# target/release/zeroemu.app. Opened from Finder, the Dock or Launchpad, it boots the
# tested image as `zeroemu` does; its output goes to ~/Library/Logs/zeroemu/zeroemu.log.
# With --install, it is copied to /Applications, or to ~/Applications when
# /Applications can't be written.
set -eu
cd "$(dirname "$0")/.."
install=
case "${1:-}" in
    --install) install=1 ;;
    "") ;;
    *) echo "usage: scripts/build-app.sh [--install]" >&2; exit 2 ;;
esac
[ "$(uname -s)" = Darwin ] || { echo "zeroemu.app is for macOS" >&2; exit 1; }

cargo build --release
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
rm -rf target/release/zeroemu.app
app=target/release/zeroemu.app
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp target/release/zeroemu "$app/Contents/MacOS/zeroemu"
cp packaging/macos/zeroemu.icns "$app/Contents/Resources/zeroemu.icns"
sed "s/@VERSION@/$version/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"
# The bundle's signature covers the binary inside, which the entitlement is for:
# macOS refuses a VM to a process without it.
codesign -s - -f --entitlements entitlements.plist "$app"
codesign --verify --strict "$app"
echo "built $app ($version)"

if [ -n "$install" ]; then
    dest=/Applications
    [ -w "$dest" ] || { dest=$HOME/Applications; mkdir -p "$dest"; }
    rm -rf "$dest/zeroemu.app"
    ditto "$app" "$dest/zeroemu.app"
    echo "installed $dest/zeroemu.app"
fi
