#!/bin/sh
# Redraws packaging/macos/zeroemu.icns from packaging/macos/icon.swift: the 1024 px
# drawing, scaled to the ten sizes an .icns holds (16 to 512, each also at 2x), which
# Finder and the Dock pick from. Only needed after icon.swift changes; the .icns is
# committed so building zeroemu needs no Swift.
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Darwin ] || { echo "the icon is drawn with macOS's CoreGraphics" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
swift packaging/macos/icon.swift "$tmp/icon-1024.png"
set=$tmp/zeroemu.iconset
mkdir "$set"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$tmp/icon-1024.png" --out "$set/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$tmp/icon-1024.png" --out "$set/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$set" -o packaging/macos/zeroemu.icns
echo "wrote packaging/macos/zeroemu.icns"
