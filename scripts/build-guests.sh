#!/bin/sh
# Builds the static Linux test guests in guest/ for arm64 and x86_64 using the
# host clang plus the rust-lld that ships with rustup (no Linux toolchain needed).
set -e
cd "$(dirname "$0")/.."
LLD="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
OUT=target/guest
mkdir -p "$OUT"

for arch in aarch64 x86_64; do
    triple="$arch-linux-gnu"
    clang -target "$triple" -c "guest/hello_$arch.S" -o "$OUT/hello_$arch.o"
    "$LLD" -flavor gnu -static -o "$OUT/hello_$arch" "$OUT/hello_$arch.o"

    clang -target "$triple" -O2 -ffreestanding -fno-stack-protector -fno-pic \
        -fno-builtin -nostdlib -c guest/smoke.c -o "$OUT/smoke_$arch.o"
    "$LLD" -flavor gnu -static -o "$OUT/smoke_$arch" "$OUT/smoke_$arch.o"
done

for t in m2 m3; do
    clang -target aarch64-linux-gnu -O2 -ffreestanding -fno-stack-protector -fno-pic \
        -fno-builtin -nostdlib -c "guest/$t.c" -o "$OUT/${t}_aarch64.o"
    "$LLD" -flavor gnu -static -o "$OUT/${t}_aarch64" "$OUT/${t}_aarch64.o"
done

for t in fault bench; do
    clang -target aarch64-linux-gnu -c "guest/${t}_aarch64.S" -o "$OUT/${t}_aarch64.o"
    "$LLD" -flavor gnu -static -o "$OUT/${t}_aarch64" "$OUT/${t}_aarch64.o"
done
ls -l "$OUT" | grep -v '\.o$'
