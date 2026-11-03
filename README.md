# droidrt

Run Android's userspace natively on macOS and Windows, with no emulated
hardware and no guest kernel.

The Android Emulator boots a complete virtual phone: a Linux kernel, virtual
devices, and a GPU command stream forwarded to the host. droidrt instead runs
Android's unmodified Linux binaries directly on the host CPU inside a minimal
hardware VM, and implements the Linux kernel ABI in Rust on the host side. It
is the same idea as Fuchsia's Starnix, aimed at desktop OSes.

```
 guest (EL0 / ring 3)        Android binaries: init, servicemanager, ART, apps…
 ─────────────────────────── syscall / fault = VM exit, no guest kernel
 kernel (src/kernel.rs)      Linux personality in Rust: syscalls, fds, memory,
                             (later) binder, signals, processes. Host-OS independent.
 vfs (src/vfs.rs, android.rs) Android's mount namespace, built from the SDK image
 image (src/image/)          GPT → super (LP) → EROFS/ext4, APEX zips, LZ4, inflate
 hv backend (src/hv/)        hvf.rs: Hypervisor.framework (macOS, arm64)
                             whp.rs: Windows Hypervisor Platform (x86_64)
 host                        macOS / Windows
```

The guest ISA always matches the host CPU, so guest code runs at native speed:
arm64 Android on Apple Silicon and Windows on ARM, x86_64 Android on x86_64 PCs.

## Status

| Milestone | State |
|---|---|
| M0: kernel-less VM, static ELF, basic syscalls (macOS) | done |
| M0: Windows Hypervisor Platform backend (x86_64) | written, type-checks; untested on Windows |
| M1: Android's own `linker64`, `toybox`, and `mksh` straight from an SDK `system.img` | done (macOS, Android 16 image) |
| M2: demand paging, threads (`clone`), futex, epoll, signals, pipes, `fork`/`exec` | next |
| M3: binder, `servicemanager`, property service, `logd` | |
| M4: SurfaceFlinger with a composer HAL that renders to Metal / D3D12 | |
| M5: zygote, ART, `system_server`, launcher, apps | |

M1 reads the image directly; nothing is extracted to disk. The chain is
`system.img` (GPT) → `super` (dynamic partitions) → EROFS with LZ4 → `.apex`
zip (CRC-checked) → `original_apex` (deflate, for compressed APEXes) → ext4
payload, mounted at `/apex/<name>` on first use. A program launch takes ~50 ms.

Known gaps after M1:

- No `fork`, pipes, or threads yet, so shell pipelines and `$(...)` fail.
- Guest memory is identity mapped: 16 GiB on macOS (bionic's allocator reserves
  ~8.25 GiB up front), only 1 GiB on Windows. Demand-paged per-process page
  tables (M2) replace this on both.
- Images older than Android 10 (no `super` partition) aren't supported.
- APEX mount names come from file names (`com.android.tzdata6` should be
  `com.android.tzdata`); reading `apex_manifest.pb` lazily would fix it.
- `/linkerconfig/ld.config.txt` is not generated, so the linker warns and uses
  its default search paths.

## Build and run

Requires Rust 1.85+ and, on macOS, Xcode's clang (to build the test guests).

```sh
./scripts/build-guests.sh                 # static Linux test binaries (arm64 + x86_64)
cargo run -- target/guest/smoke_aarch64 alpha beta
cargo run -- --strace target/guest/hello_aarch64

IMG=~/Library/Android/sdk/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img
cargo run --release -- --system $IMG /system/bin/toybox ls -l /apex/com.android.art/bin
cargo run --release -- --system $IMG /system/bin/sh      # Android's mksh, reading stdin
cargo run --release -- --system $IMG --ls /system/bin    # inspect the image without running anything
./scripts/test-android.sh                                # end-to-end checks against the image
```

`DROIDRT_STRACE=1` (or `--strace`) logs every syscall; `DROIDRT_WATCHDOG=<secs>`
forces a stuck guest out of the VM and dumps its registers.

On macOS, `cargo run` signs the binary with the `com.apple.security.hypervisor`
entitlement (see `scripts/macos-runner.sh`); without it the VM cannot be created.
On Windows, enable the "Windows Hypervisor Platform" optional feature.

## Design rules

- `src/kernel.rs`, `src/elf.rs`, and `src/arch.rs` must not use POSIX APIs. Windows
  has no `fork`, `mmap`, or signals, so processes, address spaces, and file
  descriptors are implemented inside the runtime and never delegated to the host.
- Syscalls are decoded through `arch::Sysno`, so one implementation serves both
  the arm64 (generic) and x86_64 syscall tables.
- Each backend owns `KERNEL_BASE..MEM_SIZE` of guest memory for its page tables
  and trap stubs. Everything below it belongs to the guest.

## Performance notes

A syscall round trip (guest → host → guest) is ~1.0 µs on an M1 Pro (1M
`getpid` calls in 1.0 s), about 10x a native syscall. Planned mitigations:

- a vDSO page so `clock_gettime` / `gettimeofday` never exit the VM;
- fewer register accesses per exit;
- implementing binder transactions and futex wakeups without extra round trips.

Smoothness is expected to come from what disappears: there is no virtual GPU
pipe, no second compositor, no guest kernel scheduler, and no virtual device
emulation.
