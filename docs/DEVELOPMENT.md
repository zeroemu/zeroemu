# Developing zeroemu

Building from source, the tests, the development commands, and every debugging
variable. [CONTRIBUTING.md](../CONTRIBUTING.md) has the rules for pull requests, and
[INTERNALS.md](INTERNALS.md) says how each part works.

## Building

Requires Rust 1.89+ (`File::try_lock` needs 1.89) and, on macOS, the Xcode Command Line
Tools (`xcode-select --install`): the linker and macOS SDK for zeroemu, and clang to build
the test guests.

```sh
cargo build --release
codesign -s - -f --entitlements entitlements.plist target/release/zeroemu
```

On macOS, `cargo run` signs the binary with the `com.apple.security.hypervisor`
entitlement (see `scripts/macos-runner.sh`, the runner `.cargo/config.toml` sets);
without it the VM cannot be created. `cargo build` relinks the binary and drops the
signature, so after a plain `cargo build`, sign it again as above. `cargo test` goes
through the same runner, so test binaries are signed too.

On Windows, enable the "Windows Hypervisor Platform" optional feature. Windows has
never run zeroemu yet; from a Mac, check that it still compiles with:

```sh
rustup target add x86_64-pc-windows-msvc
cargo check --release --target x86_64-pc-windows-msvc
```

## Running programs and inspecting images

Besides booting, zeroemu runs single Linux programs, static or from an image, and reads
images without running anything:

```
zeroemu [--system <img>] [--strace] [--display] <program> [args...]
zeroemu --system <img> --ls <path> | --cat <path>
zeroemu --gpu-selftest
```

```sh
./scripts/build-guests.sh                 # static Linux test binaries (arm64 + x86_64)
cargo run -- target/guest/smoke_aarch64 alpha beta
cargo run -- --strace target/guest/hello_aarch64

IMG=~/Library/Android/sdk/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img
cargo run --release -- --system $IMG /system/bin/toybox ls -l /apex/com.android.art/bin
cargo run --release -- --system $IMG /system/bin/sh      # Android's mksh, reading stdin
cargo run --release -- --system $IMG --ls /system/bin    # inspect the image without running anything
cargo run --release -- --system $IMG --cat /system/build.prop
cargo run --release                                      # boot the tested image in a window
```

`--display` gives a program run the GPU and a window, as a boot has. `zeroemu
--gpu-selftest` checks the renderer and window alone.

For a boot, `--push <host file>:<guest path>` copies a file into the booted device
(e.g. into `/data/local/tmp`) and `--run "<cmd>"` runs a shell command once
SurfaceFlinger is up, its output on stderr. `ZEROEMU_BACKGROUND=1` opens the window
behind other windows without taking focus, which the boot tests use.

## Tests

| Command | What it does | Needs |
|---|---|---|
| `cargo test --release` | Unit tests: the image readers (EROFS, ext4, zip, inflate, LZ4), page tables, the page cache, tmpfs, the SELinux policy parser, DNS, netlink and more. They don't create a VM | Any Mac that builds zeroemu. Tests that read an SDK image skip when the tested image isn't installed |
| `scripts/build-guests.sh` | Builds the static Linux test programs in `guest/` for arm64 and x86_64, with the host clang and the `rust-lld` that ships with rustup (no Linux toolchain needed) | Xcode Command Line Tools |
| `scripts/test-guests.sh` | Builds and signs zeroemu, builds the guests, and runs each one under zeroemu | Apple Silicon |
| `scripts/test-android.sh [system.img]` | End-to-end checks against a real image: runs bionic's dynamic linker, toybox and mksh from it | Apple Silicon and an SDK image: by default the tested one, in the SDK found as zeroemu finds it (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, then `~/Library/Android/sdk`). Its expected outputs are the tested image's |
| `scripts/test-net.py` | zeroemu's host connections, which adb uses, from the host side | Apple Silicon, a signed `target/release/zeroemu` and the guests |
| `scripts/test-tcp.py` | Guest sockets against real servers on the host, reached through 10.0.2.2 | Apple Silicon, a signed `target/release/zeroemu` and the guests |
| `scripts/test-adb.sh` | Boots the tested image (ephemeral, its window behind others) and uses real adb against it: shell, logcat, push and pull, shared storage, screencap, input, install, reconnecting, and a key adbd doesn't know being refused | Apple Silicon, a signed `target/release/zeroemu`, and the SDK with `emulator`, `platform-tools` and the image (`IMG` picks another). With build-tools, a platform and a JDK it also installs a small app from `scripts/sdtest` |

`ZEROEMU_TEST_IMAGE=<system.img>` picks the image the unit tests read. Without it, they
read the tested image from the SDK zeroemu finds, and skip when it isn't installed. An
image named by `ZEROEMU_TEST_IMAGE` must be one zeroemu can open: the tests fail, rather
than skip, on one it refuses (an ext4 image, for example).

GitHub's macOS runners have no nested virtualization, so CI runs only the build, a
check with Rust 1.89 (the `rust-version` in Cargo.toml), clippy, the unit tests, the
guest build and the Windows compile check. Everything that
creates a VM runs on a developer's Mac.

## Android's log

Android log records (`liblog`, i.e. `ALOGI` and friends) print to stderr as
`<secs since start> <pid> <tid> <prio> <tag>: <message>`; `ZEROEMU_LOG=<V|D|I|W|E|F|S>`
sets the lowest priority shown (by default `W` for a boot and `I` for a program run;
`S` silences them). zeroemu's own notes for its developers print only when it is `I`
or more verbose.

## Debugging variables

Tracing:

- `ZEROEMU_STRACE=1` (or `--strace`) logs every syscall (`ZEROEMU_STRACE=<name>`:
  only of programs whose path contains it).
- `ZEROEMU_BINDER_TRACE=1` logs every binder transaction.
- `ZEROEMU_BINDER_RING=1` keeps each thread's last binder events, ioctls included, and
  prints them when its process is killed by a signal.
- `ZEROEMU_FD_TRACE=<name>` logs every descriptor added to or removed from the tables
  of programs whose path contains it.
- `ZEROEMU_NET_TRACE=1` logs each network socket call and where connections go.
- `ZEROEMU_SCHED_TRACE=1` logs each change in a thread's host priority.
- `ZEROEMU_SENSOR_TRACE=1` logs the rates the sensors HAL asks for.
- `ZEROEMU_DAC_LOG=1` logs every file permission refusal: the process, its ids and
  groups, the syscall, the path, and the mode and owner that refused it (or the rule:
  sticky directory, owner only, a missing capability).
- `ZEROEMU_FAULTLOG=1` reports every fault that raises a signal, handled or not
  (`ZEROEMU_FAULTLOG=0x<address>`: only faults at that address).
- `ZEROEMU_LATEWAKE=1` reports readiness that no wakeup announced. Such files work,
  but only as fast as the fallback timeout.
- `ZEROEMU_TRACE=<file>` writes Android's own trace markers to a host file, each with the
  guest's monotonic time, pid and tid, with zeroemu's GPU ioctls on the guest thread that made
  them; turn Android's tags on with `ZEROEMU_PROPS=debug.atrace.tags.enableflags=0x86e`
  (graphics, input, view, window and activity managers, HALs). Tracing slows the guest
  little enough to measure frames with it.

Stuck or busy guests:

- `ZEROEMU_WATCHDOG=<secs>` forces a stuck guest out of the VM and dumps its registers.
- Fatal faults print a backtrace as library+offset, and writes to `/dev/kmsg` (where
  `servicemanager` and `init` log) appear on stderr.
- `ZEROEMU_DUMP=<secs>` prints, every that many seconds, each guest thread with the
  syscall it is in, for how long, and its backtrace; `kill -USR1` on zeroemu prints one
  such dump at any time (without backtraces unless `ZEROEMU_DUMP` is set).
- `ZEROEMU_SYSCOUNT=1` adds to each thread dump what each thread has called since the
  last, which finds a thread in a loop: send `SIGUSR1` twice, a few seconds apart.
- `ZEROEMU_MEMSTAT=1` adds to each thread dump where memory has gone, by kind and by file.
- `ZEROEMU_WAKE_STATS=1` adds the keys that woke the most to `ZEROEMU_GPU_STATS=1`'s
  line, and prints where a key that wakes over a hundred threads at once is announced
  from.

Behaviour:

- `ZEROEMU_DAC=0` turns file permissions off altogether, as before zeroemu had them,
  to tell whether one is behind a failure.
- `ZEROEMU_PROPS="name=value ..."` adds Android properties at boot (`ro.lmk.debug=true`
  makes `lmkd` say what it decides).
- `ZEROEMU_INPUT_FIFO=<path>` takes lines from a host FIFO as if from the window,
  for tests that must not touch the host's mouse: `down X Y`, `move X Y`, `up X Y`,
  `wheel X Y DX DY` (0 to 1 across the display), `key CODE 1|0` (Linux key codes),
  `resize W H` (the window's content, in points), and `shot PATH`, which writes the frame on
  show as a BMP.
- `ZEROEMU_BACKGROUND=1` opens the window behind other windows without taking focus.
- `ZEROEMU_NET=1` gives a program run (not a boot) the network interface;
  `scripts/test-guests.sh` turns it on only for the guest that expects one.

Graphics:

- `ZEROEMU_GFXSTREAM=<path>` loads the renderer library from this path rather than
  from the SDK. `ANGLE_DEFAULT_PLATFORM` overrides ANGLE's backend (Metal by default).
- `ZEROEMU_GPU=fake` is an in-memory virtio-gpu with no renderer and no window, which
  the guest tests use.
- `ZEROEMU_GPU_FEATURES="Name:enabled,..."` overrides the renderer features zeroemu
  asks for (by default `Minigbm:enabled`, as the guest's gralloc is minigbm).
- `ZEROEMU_GPU_STATS=1` prints the display's frame rate every five seconds (and black
  frames, when frames are read back); the line also says how many sleeping threads
  events woke and how many vCPUs were made each second.
- `ZEROEMU_DRM_TRACE=1` logs GPU ioctls, transfers and fences.
- `ZEROEMU_GPU_LOG=<S|E|W|I|D>` sets how much of the renderer's own log shows, from
  nothing (`S`) to everything (`D`). By default its errors show during a boot.
- `ZEROEMU_READBACK=1` reads each frame back for the window to draw, as zeroemu did
  before the renderer drew into the window itself, and `ZEROEMU_GPU_SERIAL=1` sends
  every GPU call through one thread again.
- `ZEROEMU_SAVE_FRAMES=<dir>` (with `ZEROEMU_READBACK=1`) and `ZEROEMU_DUMP_RES=<dir>`
  save displayed frames and GPU buffers as raw pixels.

Tests:

- `ZEROEMU_TEST_IMAGE=<system.img>` is the image unit tests read.

[PERFORMANCE.md](PERFORMANCE.md) says how memory, CPU and frame times were measured.
