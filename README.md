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
 kernel (src/kernel/)        Linux personality in Rust: processes, threads, fds,
                             pipes, futexes, signals. Host-OS independent.
 mm (src/mm.rs, paging.rs)   per-process page tables we own, filled on page faults
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
| M0: Windows Hypervisor Platform backend (x86_64) | ported to paged memory; builds clean, **not yet run on Windows** |
| M1: Android's own `linker64`, `toybox`, and `mksh` straight from an SDK `system.img` | done (macOS, Android 16 image) |
| M2: demand paging, threads, futex, `fork`/`execve`/`wait4`, pipes, signals | done on macOS; x86_64 written (signal frames, TLB shootdown), untested |
| M3: binder, `servicemanager`, property service, `logd`, `init` | done (macOS) |
| M4: SurfaceFlinger, with Android's graphics stack unmodified on a virtio-gpu device backed by the Android Emulator's gfxstream renderer | done (macOS) |
| M5: zygote, ART, `system_server`, launcher, apps | done (macOS): Android 16's Pixel launcher in the window about 35 s after start, `boot_completed` by about 50 s on a quiet host |
| M6: input from the window | done (macOS): mouse as touch, scroll as a finger drag, keyboard; Chrome and Play Store open and draw from a tap |
| Smoothness | in progress: see below |
| Windows | no window and never run; compiles (`cargo check --target x86_64-pc-windows-msvc`) |

M1 reads the image directly; nothing is extracted to disk. The chain is
`system.img` (GPT) → `super` (dynamic partitions) → EROFS with LZ4 → `.apex`
zip (CRC-checked) → `original_apex` (deflate, for compressed APEXes) → ext4
payload, mounted at `/apex/<name>` on first use. A program launch takes ~50 ms.

M2 gives each process its own page tables (39-bit VA on arm64, 48-bit on
x86_64), built by `mm` and populated on page faults, so bionic's 8 GiB
allocator reservation costs nothing until touched. Each guest thread runs on
its own host thread with its own vCPU; `fork` copies the address space, and
signals use Linux-compatible frames, so mksh pipelines, `$(...)`, background
jobs, `trap`, and `kill` all work. 40 rounds of `$(ls /system/bin | wc -l)`
(120 processes) take ~1 s.

Known gaps:

- No network: AF_INET sockets exist, for netd's iptables, but connecting fails as
  on a device with no route. Netlink answers like a machine with no interfaces.
- `/data` lives in memory, so every boot is a first boot: ART compiles its boot
  image and dex2oat runs over the installed apps, for minutes, in the background.
- Display frames are read back from the renderer into host memory, which limits
  the frame rate.
- SELinux is permissive: selinuxfs, process and socket contexts, and exec
  domain transitions follow the image's CIL policy (with file labels from
  the images' xattrs), but no access is ever denied.
- Images older than Android 10 (no `super` partition) aren't supported.
- APEX mount names come from file names (`com.android.tzdata6` should be
  `com.android.tzdata`); reading `apex_manifest.pb` lazily would fix it.
- `/linkerconfig/ld.config.txt` is not generated, so the linker warns and uses
  its default search paths.

M3 so far adds the IPC Android's system services stand on: `eventfd`,
`epoll`, `timerfd`, `signalfd`, Unix sockets with `SCM_RIGHTS`, tmpfs
(`/dev`, `/data`, `/tmp`, …) with `MAP_SHARED` and `memfd`, `/proc`, `/sys`,
a permissive selinuxfs built from the image's CIL policy, the property area
and property service (as init provides them), a binder driver, and logd's
sockets. Android's own
`servicemanager` runs, and `service list` / `service check` talk to it over
binder. Every process's liblog output is printed to stderr, and Android's
`logcat` (dump, stream, `-c`, `-g`) reads it back from the kernel's buffer.
Path-bound Unix sockets are `S_IFSOCK` nodes, as on Linux (`ls -l
/dev/socket` lists the kernel's own services), so init can unlink them and
bind its own; once the real logd owns `/dev/socket/logdw`, the kernel still
prints what it receives.

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

Android log records (`liblog`, i.e. `ALOGI` and friends) print to stderr as
`<secs since start> <pid> <tid> <prio> <tag>: <message>`; `DROIDRT_LOG=<V|D|I|W|E|F|S>`
sets the lowest priority shown (default `I`; `S` silences them).

`--boot` runs Android's own `init` in a window (`--headless` for none,
`DROIDRT_BACKGROUND=1` to open it without taking focus). It needs the Android
Emulator installed: droidrt loads its GPU renderer, `libgfxstream_backend`,
from the SDK (or `DROIDRT_GFXSTREAM=<path>`), with the SDK's ANGLE on Metal
underneath (`ANGLE_DEFAULT_PLATFORM` overrides). For development, `--push
<host file>:<guest path>` copies a file into the booted device (e.g. into
`/data/local/tmp`) and `--run "<cmd>"` runs a shell command once SurfaceFlinger
is up, its output on stderr. `droidrt --gpu-selftest` checks the renderer and
window alone.

In the window, the mouse is a finger and scrolling drags one (a person's flick
becomes a fling). F1 is Home, Escape is Back, F2 is recent apps.

Guest threads take their host priority from what Android says about them: real-time
policies and nice -4 or better count as display work, the `top-app` cgroup as
foreground, nice 10 or worse and the `background` and `dex2oat` cgroups as
background. Background threads take turns on half the host's cores, as a phone
would keep them to its little ones.

`DROIDRT_STRACE=1` (or `--strace`) logs every syscall (`DROIDRT_STRACE=<name>`:
only of programs whose path contains it); `DROIDRT_BINDER_TRACE=1`
logs every binder transaction; `DROIDRT_WATCHDOG=<secs>` forces a stuck guest
out of the VM and dumps its registers. Fatal faults print a backtrace as
library+offset, and writes to `/dev/kmsg` (where `servicemanager` and `init`
log) appear on stderr. `DROIDRT_DUMP=<secs>` prints, every that many seconds,
each guest thread with the syscall it is in, for how long, and its backtrace;
`kill -USR1` on droidrt prints one such dump at any time (without backtraces
unless `DROIDRT_DUMP` is set). `DROIDRT_FD_TRACE=<name>` logs every descriptor
added to or removed from the tables of programs whose path contains it.
`DROIDRT_INPUT_FIFO=<path>` takes lines from a host FIFO as if from the window,
for tests that must not touch the host's mouse: `down X Y`, `move X Y`, `up X Y`,
`wheel X Y DX DY` (0 to 1 across the display), `key CODE 1|0` (Linux key codes), and
`shot PATH`, which writes the frame on show as a BMP. `DROIDRT_GPU_STATS=1` prints
the display's frame rate and black frames every five seconds, and
`DROIDRT_SCHED_TRACE=1` each change in a thread's host priority.
`DROIDRT_DRM_TRACE=1` logs GPU ioctls, transfers and fences;
`DROIDRT_GPU_LOG=<E|W|I|D>` shows the renderer's own log; `DROIDRT_SAVE_FRAMES=<dir>`
and `DROIDRT_DUMP_RES=<dir>` save displayed frames and GPU buffers as raw pixels.

On macOS, `cargo run` signs the binary with the `com.apple.security.hypervisor`
entitlement (see `scripts/macos-runner.sh`); without it the VM cannot be created.
On Windows, enable the "Windows Hypervisor Platform" optional feature.

## Design rules

- `src/kernel.rs`, `src/elf.rs`, and `src/arch.rs` must not use POSIX APIs. Windows
  has no `fork`, `mmap`, or signals, so processes, address spaces, and file
  descriptors are implemented inside the runtime and never delegated to the host.
- Syscalls are decoded through `arch::Sysno`, so one implementation serves both
  the arm64 (generic) and x86_64 syscall tables.
- `mm` owns all page tables. Backends contribute only kernel-window pages
  (trap stubs at `paging::KERNEL_WINDOW`, mapped privileged-only into every
  address space) and enter the guest on the page-table root they are given.

## Performance notes

A syscall round trip (guest → host → guest) is ~1.0 µs on an M1 Pro (1M
`getpid` calls in 1.0 s), about 10x a native syscall. Planned mitigations:

- a vDSO page so `clock_gettime` / `gettimeofday` never exit the VM;
- fewer register accesses per exit;
- implementing binder transactions and futex wakeups without extra round trips.

Smoothness is expected to come from what disappears: there is no virtual GPU
pipe, no second compositor, no guest kernel scheduler, and no virtual device
emulation.
