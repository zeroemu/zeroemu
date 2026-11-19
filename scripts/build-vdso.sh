#!/bin/sh
# Builds src/kernel/vdso/vdso.so, the vDSO zeroemu maps into arm64 guests, from
# vdso.S and vdso.lds, with the host clang and the rust-lld that ships with rustup
# (no Linux toolchain needed). The result is checked in, so building zeroemu needs
# neither: run this after changing either file, and commit what it writes.
set -e
cd "$(dirname "$0")/.."
LLD="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
OBJCOPY="$(dirname "$LLD")/rust-objcopy"
DIR=src/kernel/vdso
OUT=target/vdso
mkdir -p "$OUT"

clang -target aarch64-linux-gnu -c "$DIR/vdso.S" -o "$OUT/vdso.o"
"$LLD" -flavor gnu -shared -Bsymbolic -nostdlib --no-undefined \
    -soname linux-vdso.so.1 --hash-style=both --eh-frame-hdr --build-id=none \
    -z max-page-size=4096 -z noexecstack -T "$DIR/vdso.lds" \
    -o "$OUT/vdso.full.so" "$OUT/vdso.o"
# The static symbol table isn't wanted at run time; the dynamic one stays.
"$OBJCOPY" --strip-all "$OUT/vdso.full.so" "$DIR/vdso.so"
ls -l "$DIR/vdso.so"
