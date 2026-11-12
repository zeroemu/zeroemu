# zeroemu

**Zero emulation.**

zeroemu runs Android on a Mac without emulating a phone. It boots the same system
image as the Android Emulator, from Google's Android SDK, but runs Android's programs
directly on the Mac's CPU. There is no Linux kernel inside: when Android calls the
kernel, the call comes to zeroemu, which implements Linux's system calls in Rust.
Android's own `init`, system services, ART and apps run unmodified. They draw through
the Android Emulator's GPU renderer, which zeroemu loads from the emulator package in
your SDK, into a window on your Mac.

> **Developer preview (v0.1.0).** zeroemu runs on Apple Silicon Macs only. One system
> image is tested: Android 16 QPR2 with Google Play
> (`system-images;android-36.1;google_apis_playstore;arm64-v8a`), with Android Emulator
> 37.1.11 and 37.2.13. A Windows backend is in progress: it compiles but has never run.
> zeroemu is a developer tool, not a sandbox; read [SECURITY.md](SECURITY.md) before
> running apps you don't trust.

## Quick start

```sh
# 1. Install zeroemu, in a new folder. This short form checks nothing; see Install
#    for a checked download, Homebrew and source builds.
mkdir zeroemu && cd zeroemu
curl -L https://github.com/zeroemu/zeroemu/releases/download/v0.1.0/zeroemu-0.1.0-aarch64-apple-darwin.tar.gz | tar xz

# 2. Install the Android SDK pieces (or use Android Studio's SDK Manager; see below).
#    If you installed the Command-line Tools from Android Studio (SDK Tools tab),
#    sdkmanager isn't on your PATH: run it as
#    ~/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager
sdkmanager "emulator" "platform-tools" "system-images;android-36.1;google_apis_playstore;arm64-v8a"

# 3. Check that a boot should work; it prints the fix for anything missing
./zeroemu doctor

# 4. Boot Android in a window
./zeroemu
```

## Install

zeroemu is one command-line program. macOS lets a program create a virtual machine only
if it is signed with the `com.apple.security.hypervisor` entitlement. An ad-hoc
signature can carry it, so no Apple developer account is needed. The release binary and
the Homebrew build are signed already; if you build zeroemu yourself, you sign it.

You need a Mac with Apple Silicon (M1 or later). zeroemu has been tested on macOS 26 on
an M1 Pro. Older versions of macOS are untested.

### From GitHub Releases

The short form downloads and unpacks in one step, and checks nothing:

```sh
mkdir zeroemu && cd zeroemu
curl -L https://github.com/zeroemu/zeroemu/releases/download/v0.1.0/zeroemu-0.1.0-aarch64-apple-darwin.tar.gz | tar xz
./zeroemu --version
```

To check the download before you unpack it, keep the archive and the release's
`SHA256SUMS` file:

```sh
mkdir zeroemu && cd zeroemu
curl -LO https://github.com/zeroemu/zeroemu/releases/download/v0.1.0/zeroemu-0.1.0-aarch64-apple-darwin.tar.gz
curl -LO https://github.com/zeroemu/zeroemu/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify zeroemu-0.1.0-aarch64-apple-darwin.tar.gz --repo zeroemu/zeroemu
tar xzf zeroemu-0.1.0-aarch64-apple-darwin.tar.gz
./zeroemu --version
```

`shasum` checks that the archive is the one the release lists. `gh attestation verify`
uses the [GitHub CLI](https://cli.github.com) to check the release's build provenance
attestation: that GitHub Actions built the archive from this repository.

The archive holds `zeroemu`, `LICENSE`, `NOTICE`, `README.md` and `entitlements.plist`
with no folder around them, so extract it in an empty folder. To run zeroemu from
anywhere, move it to a folder in your `PATH`. On Apple Silicon Macs, `/usr/local/bin`
often doesn't exist yet, and writing to it needs `sudo`:

```sh
sudo mkdir -p /usr/local/bin && sudo mv zeroemu /usr/local/bin/
```

Downloads made with `curl` aren't quarantined. A file downloaded in a browser is, and
macOS then refuses to run zeroemu, because it is signed ad hoc rather than by a
registered developer. Since macOS Sequoia there is no Control-click way around this.
Remove the quarantine flag instead:

```sh
xattr -d com.apple.quarantine ./zeroemu
```

### With Homebrew

```sh
brew install zeroemu/tap/zeroemu
```

The formula builds zeroemu from source (Homebrew installs Rust for the build) and signs it.

### From source

You need Rust 1.89 or newer ([rustup](https://rustup.rs)) and the Xcode Command Line
Tools (`xcode-select --install`).

```sh
git clone https://github.com/zeroemu/zeroemu
cd zeroemu
cargo build --release
codesign -s - -f --entitlements entitlements.plist target/release/zeroemu
```

Every `cargo build` relinks the binary and drops the signature, so sign it again after
each build. `cargo run` signs it for you, through the runner in `.cargo/config.toml`.

`cargo install` has no step after installing, so if you use it, sign the installed
binary yourself:

```sh
cargo install --git https://github.com/zeroemu/zeroemu --tag v0.1.0 --locked
curl -LO https://raw.githubusercontent.com/zeroemu/zeroemu/v0.1.0/entitlements.plist
codesign -s - -f --entitlements entitlements.plist "${CARGO_HOME:-$HOME/.cargo}/bin/zeroemu"
```

Without the entitlement, zeroemu can't create its virtual machine and stops with an
error that names it. `zeroemu doctor` checks for it.

## The Android SDK pieces

zeroemu brings no part of Android with it. It uses these packages from Google's
Android SDK:

| Package | What zeroemu uses it for |
|---|---|
| `emulator` (Android Emulator) | Its GPU renderer, `libgfxstream_backend`, with ANGLE on Metal underneath. zeroemu loads the library; it doesn't run the emulator |
| `system-images;android-36.1;google_apis_playstore;arm64-v8a` (Google Play ARM 64 v8a System Image, Android 16 QPR2) | Android itself. zeroemu reads the image directly; nothing is extracted to disk |
| `platform-tools` | Only `adb`, if you want it. zeroemu runs without it |

Together they take about 3.5 GB.

**With Android Studio:** open the SDK Manager (Tools > SDK Manager, or More Actions >
SDK Manager on the welcome screen). On the SDK Tools tab, check Android Emulator and
Android SDK Platform-Tools. On the SDK Platforms tab, check Show Package Details, find
API level 36.1, and check Google Play ARM 64 v8a System Image.

**On the command line:** `sdkmanager` comes with the Android SDK Command-line Tools
(from Android Studio's SDK Tools tab, or `brew install --cask android-commandlinetools`,
which needs Java). Android Studio's copy isn't on your `PATH`; run it as
`~/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager`:

```sh
sdkmanager "emulator" "platform-tools" "system-images;android-36.1;google_apis_playstore;arm64-v8a"
```

Google now marks `sdkmanager` as deprecated in favour of its new Android CLI, but it
still works.

**Where zeroemu looks for the SDK:** in `ANDROID_HOME`, then `ANDROID_SDK_ROOT` (which
Google calls deprecated), then `~/Library/Android/sdk`, where Android Studio puts it. For
an SDK anywhere else, set `ANDROID_HOME`. Homebrew's `android-commandlinetools`, for
example, keeps its SDK here:

```sh
export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
```

`ZEROEMU_GFXSTREAM=<path>` loads the renderer library from a path of your choice.

**Emulator versions:** zeroemu is tested with Android Emulator 37.1.11 and 37.2.13.
37.2.13 is the release `sdkmanager` and Android Studio install as of November 2026.
zeroemu calls a few of the renderer's internal functions by name, so another emulator
release can break it.
37.3, on Google's preview channel, is untested. `zeroemu doctor` says which release you
have, and warns if it isn't 37.1 or 37.2. If a newer release doesn't work, open an
issue; a tested one can be installed by hand from Google's
[emulator archive](https://developer.android.com/studio/emulator_archive).

## Usage

```
zeroemu [options]       Boot Android in a window. --boot means the same.
zeroemu images          List the system images installed in the SDK, and whether each can boot
zeroemu doctor          Check everything a boot needs, and print the exact fix for each problem
zeroemu --help, -h      Show usage
zeroemu --version, -V   Print the version
```

`zeroemu images` marks each image `tested`, `untested`, or `unsupported:` with the
reason. `zeroemu doctor` exits with 0 when a boot should work, and 1 otherwise.

Boot options:

| Option | |
|---|---|
| `--image <name>` | Boot an installed image: `android-36.1`, `android-36.1/google_apis_playstore`, or the SDK package path `system-images;android-36.1;google_apis_playstore;arm64-v8a`. The ABI is always the host's |
| `--system <path>` | Boot a `system.img` file, or the folder that holds it |
| `--data <file>` | Keep the device's `/data` in this file instead of the default one |
| `--ephemeral` | Keep nothing: start with an empty `/data` and throw it away at exit |
| `--wipe-data` | Start over with an empty `/data` |
| `--ram <MB>` | How much memory Android believes it has: 4096 by default, as AVDs do |
| `--no-net` | No network |
| `--adb-port <port>` | Listen for adb on this port, rather than the first free emulator port |
| `--no-adb` | No adb |
| `--headless` | No window and no GPU. The boot stops at SurfaceFlinger, which needs the GPU, so it never reaches the home screen |
| `--push <host>:<guest>`, `--run <cmd>` | For development: copy a file into the device, or run a shell command once SurfaceFlinger is up. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |

Without `--image` or `--system`, zeroemu boots the tested image if it is installed. If
it isn't, zeroemu stops with a message that lists the images you have and the command
that installs the tested one. Use `--image` to pick an untested image.

What you see:

- A window with a 1080x2400 phone display, scaled to fit your screen. Android finishes
  booting about 17 seconds after start on a first boot, and about 12 seconds on later
  boots.
- The mouse is a finger, and scrolling drags one (a flick becomes a fling). F1 is Home,
  Escape is Back, and F2 is recent apps; on a MacBook keyboard, hold Fn for F1 and F2.
  Other keys type into Android.
- The terminal shows Android's warnings and errors, and the renderer's errors.
  `ZEROEMU_LOG=I` shows more of Android's log, and `ZEROEMU_LOG=S` hides it.
  `ZEROEMU_GPU_LOG=<S|E|W|I|D>` sets how much of the renderer's own log shows.
- Host `adb` sees the device as an emulator: `adb devices` lists it as `emulator-5554`,
  or the next free pair of ports. adbd keeps its key check, and your own key
  (`~/.android/adbkey.pub`) is already authorized.
- Each image keeps its own `/data`, in `~/Library/Application Support/zeroemu`. It is
  saved on a clean exit: closing the window, Ctrl-C in the terminal, or powering off
  from Android. A crash or `kill -9` loses what happened since the last save. There is
  no menu bar, so Cmd-Q doesn't quit.
- `ZEROEMU_BACKGROUND=1` opens the window behind your other windows, without taking focus.

## Supported images

| Image | State |
|---|---|
| `android-36.1` `google_apis_playstore` `arm64-v8a` (Android 16 QPR2 with Google Play) | **Tested**, with emulator 37.1.11 and 37.2.13 |
| Other `google_apis_playstore` `arm64-v8a` images with 4 KB pages | **Untested:** `zeroemu images` says whether zeroemu can read each. One boot of `android-36` (Android 16) brought adb up, but its system services never started |
| Google APIs (`google_apis`), AOSP (`default`), ATD, Wear OS, Android TV and Google TV images | **Not supported yet:** their partitions are ext4, and zeroemu reads only EROFS |
| Google Play images for Android 12, 13 and 14 (API 31, 33 and 34) | **Not supported yet:** their partitions are ext4 too |
| Images older than Android 10 | **Not supported:** they have no `super` partition |
| 16 KB page-size images (tags containing `ps16k`) | **Not supported yet:** zeroemu assumes 4 KB pages |
| `x86_64` images | **Can't run on Apple Silicon:** zeroemu runs guest code on the host CPU, so the image's instruction set must be the host's |

`zeroemu images` shows what it thinks of each image you have installed. If you try an
untested image, please open an issue with what happened.

## How it works

The Android Emulator boots a complete virtual phone: a Linux kernel, virtual devices,
and a GPU command stream forwarded to the host. zeroemu instead runs Android's
unmodified Linux binaries directly on the host CPU inside a minimal hardware VM, and
implements the Linux kernel ABI in Rust on the host side.

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

The guest's instruction set always matches the host CPU, so guest code runs at native
speed: arm64 Android on Apple Silicon, and, once the Windows backend runs, x86_64
Android on x86_64 PCs. Guest code runs at the lowest privilege level, and every system
call or fault leaves the VM for zeroemu. The GPU is a virtio-gpu device backed by
the Android Emulator's renderer, so Android's graphics stack runs unmodified.

How this compares:

- **The Android Emulator** runs a Linux kernel and virtual devices in a QEMU virtual
  machine. zeroemu uses the same system images and the same GPU renderer, without the
  kernel or the devices.
- **Waydroid and Anbox** run Android in a container that shares the host's Linux kernel,
  so they need a Linux host. zeroemu implements Linux's system calls itself, so it runs
  on macOS.
- **Windows Subsystem for Android** ran Android with its own Linux kernel in a Hyper-V
  virtual machine. Microsoft has discontinued it.
- **Fuchsia's Starnix, gVisor and WSL 1** implement Linux's system calls outside the
  Linux kernel, to run Linux programs unmodified. zeroemu is the same idea, aimed at
  Android on desktop systems. gVisor's KVM platform is the closest: it too uses
  hardware virtualization, and a kernel written in a memory-safe language (Go there)
  takes the programs' system calls.

[docs/INTERNALS.md](docs/INTERNALS.md) says how each part works.

## Status and known gaps

On Apple Silicon Macs, Android 16's Pixel launcher, Chrome and the Play Store run in the
window. The network works: Chrome loads sites over HTTP, HTTPS and QUIC. adb works,
including `forward`, `reverse`, `push` and `pull`, and so does shared storage (`/sdcard`).
On an M1 Pro, a device uses about 3.3 GB of memory five minutes after a first boot,
and 16% of one core when it sits idle at the home screen. Smoothness is being worked on;
see [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

Not there yet:

- Windows: no window, and never run. Intel Macs: no backend.
- One tested image (see above).
- The network has no packets: VPN apps, packet capture, `ping`, IPv6 and incoming
  connections (other than `adb forward`) don't work, and apps without the INTERNET
  permission still get out.
- `/data` is saved only on a clean exit.
- SELinux is permissive, and `/sdcard` has no scoped storage.

The full list is in [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md), and the milestones in
[docs/INTERNALS.md](docs/INTERNALS.md#milestones).

## Documentation

- [docs/INTERNALS.md](docs/INTERNALS.md): how each part works, the milestones and the design rules
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): building, tests, development commands and every debugging variable
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md): memory, CPU and frame-time measurements
- [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md): what is missing or different
- [docs/RELEASING.md](docs/RELEASING.md): setting up the repository and making a release
- [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md)

## Legal

zeroemu's binary and release archive contain no Google code: no system image, no
emulator and no renderer, and zeroemu downloads none of them. (The source has one test
file, `testdata/sepolicy_mini.cil`, with declarations taken from AOSP's SELinux policy;
see [NOTICE](NOTICE).) You install the Android SDK and its images yourself, under the
licences `sdkmanager` or the SDK Manager shows when you install them: the
[Android SDK License Agreement](https://developer.android.com/studio/terms) and the
image's own terms. zeroemu reads them from your SDK. The Google Play system image's
licence limits its use to developing and debugging apps, so zeroemu is a developer tool.

zeroemu is not affiliated with or endorsed by Google. Android is a trademark of Google
LLC.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
