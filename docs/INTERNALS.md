# How zeroemu works

This is the long version of the README's "How it works". It says how each part
works and where it is in the source. For building, tests and debugging aids, see
[DEVELOPMENT.md](DEVELOPMENT.md); for what is missing, [KNOWN-GAPS.md](KNOWN-GAPS.md);
for memory, CPU and frame-time measurements, [PERFORMANCE.md](PERFORMANCE.md).

## The idea

The Android Emulator boots a complete virtual phone: a Linux kernel, virtual
devices, and a GPU command stream forwarded to the host. zeroemu instead runs
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
arm64 Android on Apple Silicon Macs, and, once the Windows backend runs, x86_64
Android on x86_64 Windows PCs. There is no backend for Windows on ARM, and none for
Intel Macs (Hypervisor.framework's x86 interface would need one of its own).

## Milestones

| Milestone | State |
|---|---|
| M0: kernel-less VM, static ELF, basic syscalls (macOS) | done |
| M0: Windows Hypervisor Platform backend (x86_64) | ported to paged memory; compiles (`cargo check`), **never run on Windows** |
| M1: Android's own `linker64`, `toybox`, and `mksh` straight from an SDK `system.img` | done (macOS, Android 16 image) |
| M2: demand paging, threads, futex, `fork`/`execve`/`wait4`, pipes, signals | done on macOS; x86_64 written (signal frames, TLB shootdown), untested |
| M3: binder, `servicemanager`, property service, `logd`, `init` | done (macOS) |
| M4: SurfaceFlinger, with Android's graphics stack unmodified on a virtio-gpu device backed by the Android Emulator's gfxstream renderer | done (macOS) |
| M5: zygote, ART, `system_server`, launcher, apps | done (macOS): Android 16's Pixel launcher in the window, and boot complete about 17 s after start on a first boot and about 12 s after that |
| M6: input from the window | done (macOS): mouse as touch, scroll as a finger drag, keyboard; Chrome and Play Store open and draw from a tap |
| Network | done (macOS): Android validates the network, Chrome loads sites over HTTP, HTTPS and QUIC, and `adb forward` and `reverse` work. See [the network](#the-network) for what a network with no packets can't do |
| Shared storage | done (macOS), as a stand-in for MediaProvider's FUSE daemon: vold mounts the emulated volume, `/sdcard` has its standard directories, `adb push`/`pull` work there, and apps get their `Android/data` directories. See [shared storage](#shared-storage) |
| Smoothness | in progress: the renderer draws straight into the window, and one app's GL stream no longer waits on another's. See [PERFORMANCE.md](PERFORMANCE.md) |
| Windows | no window and never run; compiles (`cargo check --target x86_64-pc-windows-msvc`) |

## Reading the system image (M1)

M1 reads the image directly; nothing is extracted to disk. The chain is
`system.img` (GPT) → `super` (dynamic partitions) → EROFS with LZ4 → `.apex`
zip (CRC-checked) → `original_apex` (deflate, for compressed APEXes) → ext4
payload, mounted at `/apex/<name>` on first use. A program launch takes ~50 ms.

The logical partitions themselves (system, vendor, system_ext, product,
system_dlkm) are opened as EROFS only (`src/android.rs`). The ext4 reader is used
for APEX payloads, so images whose partitions are ext4 are refused for now; see the
README's supported images.

## Processes, memory and signals (M2)

M2 gives each process its own page tables (39-bit VA on arm64, 48-bit on
x86_64), built by `mm` and populated on page faults, so bionic's 8 GiB
allocator reservation costs nothing until touched. Each guest thread runs on
its own host thread with its own vCPU; `fork` copies the address space, and
signals use Linux-compatible frames, so mksh pipelines, `$(...)`, background
jobs, `trap`, and `kill` all work. 40 rounds of `$(ls /system/bin | wc -l)`
(120 processes) take ~1 s.

Guest pages are 4 KB. There is no 16 KB mode, so images built for 16 KB pages
(tags containing `ps16k`) aren't supported.

## IPC and system services (M3)

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

SELinux is permissive: selinuxfs, process and socket contexts, and exec
domain transitions follow the image's CIL policy (with file labels from
the images' xattrs), but no access is ever denied.

## Booting and the window (M4 to M6)

`--boot` (the default when no program is given) runs Android's own `init` in a
window. It needs the Android Emulator installed: zeroemu loads its GPU renderer,
`libgfxstream_backend`, from the SDK (or `ZEROEMU_GFXSTREAM=<path>`), with the SDK's
ANGLE on Metal underneath (`ANGLE_DEFAULT_PLATFORM` overrides). The SDK is looked for
in `ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then the default location
(`~/Library/Android/sdk` on macOS, `%LOCALAPPDATA%\Android\Sdk` on Windows).
`--headless` opens no window and gives the guest no GPU, so the boot stops at
SurfaceFlinger, which needs one: it never reaches the home screen.

Android's graphics stack runs unmodified on a virtio-gpu device, as in the Android
Emulator's virtio-gpu mode: the guest's gralloc is minigbm, and its GLES and Vulkan
calls are encoded by the image's own gfxstream guest libraries and decoded by the
renderer on the host. The display is one panel of a fixed size and density
(gpu::Display, 1080x2400 at 420 dpi by default), whatever the window's size: the KMS
mode and the renderer's framebuffer are that size. The renderer draws each frame into
the window itself, scaled to fit as the Android Emulator does, at the screen's real
pixel density.

In the window, the mouse is a finger and scrolling drags one (a person's flick
becomes a fling). F1 is Home, Escape is Back, F2 is recent apps. Other keys go to
Android as a keyboard's would, except Command shortcuts that the menu bar uses.

The toolbar and the menu bar's Device menu (src/gpu/controls.rs) press a phone's
buttons on a third input device, keys only, whose name no key layout in the image
matches, so that Android gives it the stock `Generic.kl`. That layout has the keys
the image's own `qwerty2.kl` lacks: Mute, Notifications and Android's screenshot,
and Settings as a HID usage. Rotating turns the phone: the accelerometer that zeroemu
serves to the image's sensors HAL reads the new way, Android turns its screen as it
would on a phone, and the window shows the panel turned. The renderer turns the frame
as it draws it (gfxstream's setupSubWindow rotation), and clicks are turned back onto
the panel, as Android expects. Quit stops the device as closing the window does, so
that `/data` is saved.

Device > Location (src/location.rs) is what the GPS reports. The image's GNSS HAL
(android.hardware.gnss-service.ranchu) opens the qemud `gps` service through
libqemupipe, as the sensors HAL opens `sensors`, and reads NMEA sentences from it.
zeroemu sends a `$GPGGA` and a `$GPRMC` four times a second, with nothing before them,
as the Android Emulator's gps service is a serial line that qemud doesn't frame. Not
once a second: the HAL passes a fix on only when the interval an app asked for has
passed since the last, so fixes a second apart that arrive a little early are dropped. With the
location None it sends nothing, and Android keeps the last fix it had, as a phone
with no sky in view does. A route is followed at its speed, heading along the leg it
is on, and starts again from its beginning when chosen.

## Saving /data

A device keeps its `/data` and `/metadata` between boots, in one file per system image
in the user's application data (`~/Library/Application Support/zeroemu/data-<hash>.img`
on macOS, `%LOCALAPPDATA%\zeroemu\` on Windows, `~/.local/share/zeroemu/` elsewhere;
the hash is of the image's full path), saved when the window closes, on SIGINT, SIGTERM
or SIGHUP, or when Android shuts down: `--data <file>` puts it elsewhere, `--ephemeral`
keeps nothing, and `--wipe-data` starts over. A second zeroemu on the same file keeps
nothing, and one that can't read the file moves it aside as `<file>.bad` rather than
saving over it. A second signal while saving exits at once, with status 128 plus the
signal. `--ram <MB>` says how much memory the guest believes it has (4096 by
default, as AVDs do).

## adb

Host `adb` finds a booted device as it finds an emulator, as `emulator-5554` or the
next pair of ports free. adbd keeps its RSA check, and the key in `~/.android/adbkey.pub`
is offered as `/adb_keys`, so the user's own adb is authorized and no other is. Guest
networking isn't involved. `--adb-port <port>` picks the port and `--no-adb` turns this off.

The ports are on 127.0.0.1 only. zeroemu connects each host connection to adbd's vsock
listener in the guest (`src/kernel/adb.rs`), and tells a running adb server about the
device, as an emulator does.

## The network

A device has a network, as `eth1` at 10.0.2.15 with the name server at 10.0.2.3. It's a
NAT without packets: a guest's sockets and ports are its own, and a host socket appears
only when a connection really goes out. `--no-net` leaves the network out altogether.

10.0.2.2 is the host's loopback for every app on the device, as on the emulator, except
for the adb server and devices' own ports. [KNOWN-GAPS.md](KNOWN-GAPS.md) lists what a
network without packets can't do.

## File permissions

File permissions follow Linux's rules (fs/namei.c, fs/attr.c, mm/mmap.c): search
permission on every directory a path walks through, read and write by open's access mode
(and write for `O_TRUNC`), write and search on the directory to create, remove, rename or
link, the sticky bit, chmod and utimes by the owner, chown by `CAP_CHOWN` (and set-uid and
set-gid dropped as Linux drops them), execute permission and `noexec` mounts for `execve`
and executable mappings, write permission on a socket to connect to it, a descriptor open
for reading to map it and for writing to map it shared and writable (which `mprotect`
can't add later, nor past ashmem's protection mask), the xattr namespaces' rules, and
`CAP_SYS_ADMIN` for device-mapper. Root with its capabilities passes as on Linux; an app's
uid is held to them. zeroemu's own device nodes have the modes and owners ueventd.rc
gives them. `src/kernel/perm.rs` has the shared checks and says which filesystems they
cover.

## Shared storage

Shared storage (`/sdcard`, `/storage/emulated`) is the device's arrangement with the
round trips left out. vold opens `/dev/fuse`, mounts it at `/mnt/user/0/emulated` and hands
the descriptor to MediaProvider, whose FUSE daemon reads FUSE_INIT and answers it, so vold,
StorageManagerService and MediaProvider all see the volume mounted. The mount itself is a
second view of `/data/media` in `/data`'s tmpfs, served by zeroemu directly, so its files are
saved with `/data` and no file operation waits on a guest process. As on a fuse mount without
`default_permissions`, nothing is refused there, chmod and chown change nothing, and what is
created belongs to the daemon's uid, as on the lower filesystem where MediaProvider would make
it. vold's binds of `/data/media/0/Android/data` and `obb`, and zygote's per-app views, work as
on a device; `/data`'s tmpfs keeps ext4's inode flags and quota project ids
(`FS_IOC_SETFLAGS`, `FS_IOC_FSSETXATTR`), which vold sets on each app's directories. See
`src/kernel/fuse.rs`, and [KNOWN-GAPS.md](KNOWN-GAPS.md) for what this leaves out.

## Scheduling

Guest threads take their host priority from what Android says about them: real-time
policies and nice -4 or better count as display work, the `top-app` cgroup as
foreground, nice 10 or worse and the `background` and `dex2oat` cgroups as
background. Background threads take turns on half the cores Android is given or the
Mac has, whichever is fewer (one of one), as a phone would keep them to its little
ones.

Android is given all of the host's cores unless a device asks for fewer. macOS cannot
keep a thread to some of the cores, so then zeroemu lets no more guest threads run at
once than the device has cores. A thread takes a core on its way into the guest and
keeps it through its syscalls, as on Linux, until it blocks in the kernel, calls
`sched_yield` while others wait, or has had a 10 ms turn while others wait. A core
given up goes straight to the first thread in line, so one that comes for a core
meanwhile cannot take it. Display work is served first: for each display thread in
line, one thread of other work gives its core up at once, and only threads running
guest code are kicked to make way, as one in the kernel makes way when it comes back.
A display thread that has held its core 50 ms while only other work waits, or calls
`sched_yield` then, takes 10 ms turns with the others until it next blocks, so a
display thread that spins cannot shut them out, as Linux's real-time throttling
ensures; one that blocks now and then is display work again each time it wakes.
Display threads taking turns among themselves could still keep other work out, so a
thread of other work that display work has kept waiting for 50 ms goes first, and
display work makes way for it after its own 50 ms; while both kinds wait that long,
they take turns. Only time while display work waits for a core or holds them all
counts: display work on some of the cores leaves other work the rest, as Linux
throttles real-time threads only once they take a whole CPU. A thread handed a core
looks again on its way into the guest, as display work that came meanwhile could not
stop it there. A thread waiting for a core keeps its vCPU, which costs far less than destroying it and
making another, unless the hypervisor's vCPUs run short. Every thread takes a
background place, a core and a vCPU in that order, and waits for them only on its way
into the guest, where it holds no kernel lock, so threads cannot deadlock over them.
See `src/kernel/vcpus.rs`.

zeroemu tells macOS its work is user-initiated, so App Nap doesn't throttle it while
its window is covered: a device keeps running in the background, as a phone's apps do
with the screen off. The Mac can still sleep.

## Design rules

- `src/kernel/`, `src/elf.rs`, and `src/arch.rs` must not use POSIX APIs to implement
  what the guest sees. Windows has no `fork`, `mmap`, or signals, so processes, address
  spaces, and file descriptors are implemented inside the runtime and never delegated
  to the host. (The only POSIX calls in `src/kernel/` are behind `cfg(unix)`, for the
  host's own signals: SIGUSR1 thread dumps, and saving `/data` on SIGINT, SIGTERM and
  SIGHUP.)
- Syscalls are decoded through `arch::Sysno`, so one implementation serves both
  the arm64 (generic) and x86_64 syscall tables.
- `mm` owns all page tables. Backends contribute only kernel-window pages
  (trap stubs at `paging::KERNEL_WINDOW`, mapped privileged-only into every
  address space) and enter the guest on the page-table root they are given.
