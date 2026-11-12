# Known gaps

What zeroemu doesn't do yet, or does differently from a phone or the Android
Emulator. [INTERNALS.md](INTERNALS.md) says how each part works.

## Platforms and images

- Only Apple Silicon Macs run zeroemu. Intel Macs have no backend.
- Windows has no window and has never run. The Windows Hypervisor Platform backend
  (x86_64) compiles (`cargo check --target x86_64-pc-windows-msvc`), and the x86_64 side
  of processes and threads (signal frames, TLB shootdown) is written but untested. There
  is no backend for Windows on ARM.
- On Windows, nothing saves `/data` on Ctrl-C or when the console closes.
- One system image is tested: `system-images;android-36.1;google_apis_playstore;arm64-v8a`
  (Android 16 QPR2 with Google Play), with emulator 37.1.11 and 37.2.13. The README's
  supported images table lists the rest:
  - Other `google_apis_playstore` `arm64-v8a` images with 4 KB pages are untested.
    `zeroemu images` says whether zeroemu can read each. One boot of `android-36`
    (Android 16) brought adb up, but its system services never started.
  - Images whose partitions are ext4 are refused: the partitions are opened as EROFS
    only. That is every Google APIs, AOSP, ATD, Wear OS, Android TV and Google TV image,
    and the Google Play images for Android 12, 13 and 14 (API 31, 33 and 34).
  - Images older than Android 10 (no `super` partition) aren't supported.
  - 16 KB page-size images (`ps16k`) aren't supported: zeroemu assumes 4 KB pages.
  - x86_64 images can't run on Apple Silicon: the guest's instruction set must be the
    host's.
- zeroemu calls a few of the emulator renderer's internal functions by name, so an
  emulator release other than the tested ones (37.1 and 37.2) can break it. 37.3, on
  Google's preview channel, is untested.
- The display is one 1080x2400 phone panel, whatever the image expects.
- `--headless` gives the guest no GPU, so a headless boot stops at SurfaceFlinger, which
  needs one. It never reaches the home screen.

## The window

- There is no menu bar, so Cmd-Q doesn't quit. Close the window, press Ctrl-C in the
  terminal, or power off from Android.
- On a MacBook keyboard, F1 (Home) and F2 (recent apps) need Fn held, unless the keys are
  set to act as standard function keys.

## Network

- The network has no packets. Guest sockets connect to host sockets directly, so
  what depends on seeing traffic doesn't apply: `VpnService` (a VPN app's traffic goes
  straight out while Android believes it's tunnelled), packet capture, and per-app
  firewalling. An app without the INTERNET permission still gets out. A background
  restriction can block an app's DNS while its TCP still works.
- 10.0.2.2 is the host's loopback for every app on the device, as on the emulator,
  except for the adb server and devices' own ports.
- There's no IPv6, no ICMP (`ping` resolves and never hears back) and no incoming
  connections except through `adb forward`.
- The name server answers from the host's resolver: A records only, with a made-up TTL,
  no CNAMEs or HTTPS records, and every failure is SERVFAIL.
- Android thinks eth1 is unmetered, so Google's services download what they like once
  it's up, into a `/data` that's saved whole.

## /data

- `/data` is only saved at a clean exit. A kill or a crash loses what happened since the
  last boot's save.
- `/data` is kept per image path. An image the SDK Manager updates in place keeps the old
  `/data`, and an SDK moved elsewhere starts with an empty one.

## Files and memory

- A mapping of a file doesn't raise SIGBUS past the file's end: it reads zeros. A read
  of a hole through a private mapping stays zeros if the file is written there later.
- `O_PATH` descriptors can be read and mapped, and `/dev/zero` can't be mapped.
- File permissions are Linux's (see [INTERNALS.md](INTERNALS.md#file-permissions)) only
  where owners and modes are real: tmpfs, binderfs and the images. `/proc`, `/sys`, the
  cgroup hierarchies, selinuxfs, devpts, tracefs and bpffs have modes zeroemu made up and
  owners nobody set, so any process may read and write what they let root.
  fs.protected_symlinks isn't applied, and `access()` walks the path with the effective
  ids rather than the real ones.
- Shared storage has no scoped storage: MediaProvider's daemon is never asked anything
  after FUSE_INIT (see [INTERNALS.md](INTERNALS.md#shared-storage)), so any app with the
  volume in its mount namespace may read and write anything there, MediaProvider only
  learns of new files when it scans, and nothing is redacted or transcoded. Other apps'
  `Android/data` and `Android/obb` directories stay closed, as vold binds them from
  `/data/media` with their owners' modes. Files show the labels `/data/media` has rather
  than `u:object_r:fuse:s0`. vold logs that it can't set the volume's readahead: there is
  no `/sys/class/bdi/0:N`.
- POSIX ACLs on tmpfs are stored but not enforced, and new files don't inherit a default
  ACL: a file an app writes in its `Android/data` directory with umask 077 stays 0600,
  where the default ACL vold sets would let `ext_data_rw` (adb's shell) read it.
- File capabilities (`security.capability`) aren't applied on `execve`, so `run-as`
  can't change its ids and fails.
- userfaultfd has only what ART's compacting collector uses: SIGBUS mode, on private
  anonymous memory.

## Graphics

- Guest GLES reaches the renderer over virtio-gpu's pipe, not its shared-memory ring:
  gfxstream's guest library picks the pipe for the emulator's own EGL. Each GL call that
  waits for an answer is a round trip through zeroemu (a few hundred a second while an
  app scrolls).

## Android's own setup

- SELinux is permissive: selinuxfs, process and socket contexts, and exec
  domain transitions follow the image's CIL policy (with file labels from
  the images' xattrs), but no access is ever denied.
- APEX mount names come from file names (`com.android.tzdata6` should be
  `com.android.tzdata`); reading `apex_manifest.pb` lazily would fix it.
- `/linkerconfig/ld.config.txt` is not generated, so the linker warns and uses
  its default search paths.
