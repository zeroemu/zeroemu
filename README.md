# zeroemu

**Zero emulation.**

zeroemu runs Android on a Mac without emulating a phone. It boots the same system
image as the Android Emulator, from Google's Android SDK, but runs Android's programs
directly on the Mac's CPU. There is no Linux kernel inside: when Android calls the
kernel, the call comes to zeroemu, which implements Linux's system calls in Rust.
Android's own `init`, system services, ART and apps run unmodified. They draw through
the Android Emulator's GPU renderer, which zeroemu loads from the emulator package in
your SDK, into a window on your Mac.

> **Developer preview (v0.3.1).** zeroemu runs on Apple Silicon Macs only. One system
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
curl -L https://github.com/zeroemu/zeroemu/releases/download/v0.3.1/zeroemu-0.3.1-aarch64-apple-darwin.tar.gz | tar xz

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

zeroemu comes as a command-line program and a Mac app. macOS lets a program create a virtual machine only
if it is signed with the `com.apple.security.hypervisor` entitlement. An ad-hoc
signature can carry it, so no Apple developer account is needed. The release binary and
the Homebrew build are signed already; if you build zeroemu yourself, you sign it.

You need a Mac with Apple Silicon (M1 or later). zeroemu has been tested on macOS 26 on
an M1 Pro. Older versions of macOS are untested.

### From GitHub Releases

The short form downloads and unpacks in one step, and checks nothing:

```sh
mkdir zeroemu && cd zeroemu
curl -L https://github.com/zeroemu/zeroemu/releases/download/v0.3.1/zeroemu-0.3.1-aarch64-apple-darwin.tar.gz | tar xz
./zeroemu --version
```

To check the download before you unpack it, keep the archive and the release's
`SHA256SUMS` file:

```sh
mkdir zeroemu && cd zeroemu
curl -LO https://github.com/zeroemu/zeroemu/releases/download/v0.3.1/zeroemu-0.3.1-aarch64-apple-darwin.tar.gz
curl -LO https://github.com/zeroemu/zeroemu/releases/download/v0.3.1/SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify zeroemu-0.3.1-aarch64-apple-darwin.tar.gz --repo zeroemu/zeroemu
tar xzf zeroemu-0.3.1-aarch64-apple-darwin.tar.gz
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
cargo install --git https://github.com/zeroemu/zeroemu --tag v0.3.1 --locked
curl -LO https://raw.githubusercontent.com/zeroemu/zeroemu/v0.3.1/entitlements.plist
codesign -s - -f --entitlements entitlements.plist "${CARGO_HOME:-$HOME/.cargo}/bin/zeroemu"
```

Without the entitlement, zeroemu can't create its virtual machine and stops with an
error that names it. `zeroemu doctor` checks for it.

### As a Mac app

Starting with v0.3.1, use the Homebrew cask to install `zeroemu.app` in Applications
and keep it up to date:

```sh
brew install --cask zeroemu/tap/zeroemu-app
# Quit zeroemu before an upgrade so running devices save their data.
brew update && brew upgrade --cask zeroemu/tap/zeroemu-app
```

The `zeroemu/tap/zeroemu` formula updates only the command-line program. If you
already built or installed the app yourself, quit it, move the old bundle out of
Applications if it is there, and install the cask once. Open the Applications copy
from then on, and replace any Dock shortcut that pointed to the old copy. Your saved
devices are kept outside the bundle and don't need to be moved.

The app is signed ad hoc and isn't notarized. If macOS blocks it, review
[Apple's guidance on opening downloaded apps](https://support.apple.com/en-us/102445).
You can check the ZIP's checksum and provenance on the GitHub release before opening it.

From a source checkout, `scripts/build-app.sh` still builds `zeroemu.app`, signed as
above. `scripts/build-app.sh --install` also copies it into `/Applications` (or
`~/Applications` if `/Applications` isn't writable). Use either that copy or the cask,
not both.

It opens on a list of your devices, as Android Studio's Device Manager does. A device is
a name, a system image from your SDK, and its own `/data`. The first time, the app asks
you to make one: **New Device** (⌘N) takes a name and one of your installed images. The
image zeroemu is tested with is chosen first, and images it can't boot are listed but
can't be chosen; if none of them can, the form says why and what to install.

A name, an image and a **Device** (a preset screen) are all a device needs. The rest is
under **Advanced Settings**, closed at first, with these defaults, as in Android Studio's
device wizard; closed, it says which aren't the default. Choosing Custom for the Device
opens it.

| Setting | Default | |
|---|---|---|
| Device | Medium Phone | Shown always. A preset sets the screen: Medium Phone (1080 × 2400, 420 dpi), Pixel 9 (1080 × 2424, 420 dpi), Small Phone (720 × 1280, 320 dpi) or Pixel Tablet (2560 × 1600, 320 dpi) |
| Screen, Density | 1080 × 2400, 420 dpi | Any even number of pixels from 320 to 4096 a side, at 120 to 640 dpi, at least 320 dp across. The form shows the size in dp, as apps see it. Android draws at this size whatever the window's, which scales it to fit |
| Memory | 4 GB | What Android is told it has, which decides how it caches and closes apps |
| CPU cores | All of the Mac's | Fewer cores, two at least, are what Android sees, and at most how many of its threads run at once, which leaves the Mac the rest |
| Network | Connected | |
| Time zone | The Mac's | Set again at every start, over a zone chosen inside Android |
| Location | The main city of its time zone (the Googleplex for a zone with none, such as UTC) | Where its GPS says it is: none, a place, a moving route, or coordinates |

- **Start** boots a device in the window. Closing its window brings the list back; Quit
  (⌘Q) stops it and quits.
- A device that is already running says so, and **Show** brings its window forward.
  File > Show Device List (⇧⌘D) opens the list beside a running device, to start
  another one: each runs in its own zeroemu, with its own adb serial. There is one list
  at a time: chosen again, it brings the open list forward.
- A device's ⋯ menu, or a right click, edits it (its name and the settings above, for
  its next start), wipes its data, shows its files in Finder, or deletes it.
- Device > Location moves a running device, as Simulator's Features > Location does: to
  a place, along a moving route, to coordinates you type, or to none.
- What `zeroemu` saved for an image in a terminal (without `--device`) shows up in the
  list as a device of that image, so nothing is lost: the device and `zeroemu` share
  that `/data`, and it shows as running while the terminal runs it.

Devices are kept in `~/Library/Application Support/zeroemu/devices`. `zeroemu devices`
lists them in a terminal, with the `/data` a terminal boot keeps for each image, and
`zeroemu --device <name>` boots one.

The app has no terminal, so:

- What zeroemu would print goes to `~/Library/Logs/zeroemu/zeroemu.log`, with the run
  before's as `zeroemu.previous.log`. Console opens them. Of Android's own log, only
  init's is there, a few hundred lines a boot, since the rest adds thousands of lines a
  minute: `adb logcat` shows it.
- If Android can't start, stops by itself, or zeroemu crashes, an alert says so, with
  the fix when there is one, and offers the log.
- The app looks for the SDK only in its usual place, `~/Library/Android/sdk`: apps don't
  see your shell's `ANDROID_HOME`. To use an SDK that's somewhere else, link it there:
  `mkdir -p ~/Library/Android && ln -s "$ANDROID_HOME" ~/Library/Android/sdk`.
- Only one zeroemu can use a device's `/data` at a time: a running device's Start
  becomes Show.

Quitting or closing a device's window stops it, and saves its `/data`.

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
zeroemu devices         List your devices, and whether each is running
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
| `--device <name>` | Boot a device made in zeroemu.app, with its image, its `/data` and its settings. `--screen`, `--density`, `--ram`, `--cpus`, `--no-net`, `--timezone` and `--location` override its settings for that boot only |
| `--screen <w>x<h>`, `--density <dpi>` | The screen Android draws, in pixels and dots per inch: 1080x2400 at 420 by default, as Android Studio's Medium Phone |
| `--cpus <n>` | How many cores Android sees, and at most how many of its threads run at once: 2 to 64, all of the computer's by default |
| `--timezone <zone>` | A time zone such as `Europe/Berlin`, set at every boot: the computer's by default |
| `--location <where>` | Where the GPS says the device is: `<latitude>,<longitude>`, a place or route by its name in Device > Location (`"City Run"`) or its id (`city-run`, `googleplex`), or `off`. By default, the main city of the time zone, or the Googleplex for a zone with none, such as UTC |
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

- A window with the device's screen (1080x2400 by default), scaled to fit yours. Android finishes
  booting about 17 seconds after start on a first boot, and about 12 seconds on later
  boots.
- The mouse is a finger, and scrolling drags one (a flick becomes a fling). Other keys
  type into Android.
- The toolbar in the title bar has Back, Home, Recents, Screenshot, Rotate and Power.
  View > Customize Toolbar adds Volume, Mute, Notifications, Settings, Lock and more.
- The **Device** menu has every control, with shortcuts:

  | Control | Shortcut |
  |---|---|
  | Back, Home, Recent Apps | ⌘[, ⇧⌘H, ⇧⌘R (and Escape, F1, F2) |
  | Notifications, Android Settings | ⌘N, ⌘I |
  | Volume Up, Volume Down, Mute | ⌘↑, ⌘↓ |
  | Power Button, Lock Screen, Power Menu | ⇧⌘P, ⌘L |
  | Rotate Left, Rotate Right | ⌘←, ⌘→ |
  | Take Screenshot in Android | |

  File > Save Screenshot (⌘S) saves the screen as a PNG where your Mac saves its own
  screenshots. On a MacBook keyboard, hold Fn for F1 and F2.
- Rotating turns the phone: Android turns its screen as a phone does, if auto-rotate is
  on and the app allows it, and the window takes the new shape.
- **Device > Location** sets where the phone's GPS says it is, as Simulator's Features >
  Location does: None, a latitude and longitude of your own, one of a dozen places
  round the world, or a route round the Googleplex (a run, a bicycle ride or a drive
  on US 101) that the phone follows at its pace, over and over.
- The terminal shows Android's warnings and errors, and the renderer's errors.
  `ZEROEMU_LOG=I` shows more of Android's log, and `ZEROEMU_LOG=S` hides it.
  `ZEROEMU_GPU_LOG=<S|E|W|I|D>` sets how much of the renderer's own log shows.
- Host `adb` sees the device as an emulator: `adb devices` lists it as `emulator-5554`,
  or the next free pair of ports. adbd keeps its key check, and your own key
  (`~/.android/adbkey.pub`) is already authorized.
- Each image keeps its own `/data`, in `~/Library/Application Support/zeroemu`. It is
  saved on a clean exit: quitting (⌘Q), closing the window, Ctrl-C in the terminal, or
  powering off from Android. A crash or `kill -9` loses what happened since the last
  save.
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
