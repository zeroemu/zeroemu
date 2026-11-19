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

- Command doesn't reach Android as Meta: its key layout for zeroemu's keyboard
  (`qwerty2.kl`) has no Meta key, so Android's Meta shortcuts don't work. Command
  shortcuts that the menu bar doesn't use are sent as the key alone.
- The Power toolbar button and menu item press the button briefly. A long press is
  Android's assistant on this image; Device > Power Menu gives the power menu instead.
- Rotation turns the window's picture and what the accelerometer reads. With auto-rotate
  off, Android shows its rotate button rather than turning, as a phone does.
- Quitting during a logout cancels the logout: zeroemu first saves `/data`, then exits.
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
- `madvise` isn't Linux's (mm/madvise.c) in three ways:
  - Only MADV_DONTNEED, MADV_FREE, the fork advice and MADV_POPULATE_READ/WRITE do
    anything. Any other advice, an unknown one too, returns 0: MADV_WILLNEED reads
    nothing ahead, so a file's pages are read when first touched, and MADV_REMOVE leaves
    a shared mapping's data, where Linux frees it and it reads back as zeros.
  - A range with a hole: Linux acts on every mapped part, then returns ENOMEM.
    MADV_DONTNEED, MADV_FREE and the advice that does nothing return 0, the fork advice
    changes nothing and returns ENOMEM, and MADV_POPULATE_READ/WRITE fill in the pages
    before the hole and return ENOMEM. Where a mapping in the range can't take the fork
    advice (EINVAL), zeroemu changes nothing, and Linux has changed the mappings before
    that one. The advice that does nothing returns 0 for a start that isn't page-aligned, where
    Linux returns EINVAL.
  - MADV_FREE drops the pages of any mapping, as MADV_DONTNEED does, so a private file
    mapping's written pages read back from the file. Linux takes it only on private
    anonymous memory and refuses it elsewhere with EINVAL (`madvise_free_single_vma`).
- `epoll_wait` marks a one-shot registration as fired, and an edge-triggered one as
  reported, before it copies the events out. If the copy fails (EFAULT), those events
  are lost, where Linux puts them back (`ep_send_events` in fs/eventpoll.c).

## Threads and signals

- A signal or an exit that comes just as a thread goes to sleep in `sigsuspend`,
  `nanosleep`, `wait4`, a pipe or pty read or write, a file lock or binder, or while it
  waits for a vCPU, can be missed until the sleep's 2-second limit runs out. The thread
  is told without taking the lock it sleeps under (`Thread::sleep`). In `rt_sigtimedwait`
  (ART's signal catcher waits for SIGQUIT there) the window is wider: any of the
  awaited signals sent between its look at what is pending and its sleep can wait the
  2 seconds. Futex waits and `poll`, `select` and `epoll_wait` aren't affected.
- `futex` has no FUTEX_WAKE_OP, FUTEX_WAIT_REQUEUE_PI or FUTEX_CMP_REQUEUE_PI: they
  return ENOSYS.
- FUTEX_CMP_REQUEUE, FUTEX_LOCK_PI and FUTEX_UNLOCK_PI read or change the futex word
  with its bucket locked, and fault the word's page in there if it isn't in: a page read
  from a file then holds up the other futexes in that bucket. Linux faults the page in
  with the bucket unlocked and tries again (`futex_requeue` in kernel/futex/requeue.c,
  `futex_lock_pi` and `futex_unlock_pi` in kernel/futex/pi.c), as zeroemu's futex wait
  does. The callers in bionic and ART have just written or compared the word, so its
  page is in.
- A signal sent to a whole process goes to one thread that lets it in. If that thread
  blocks it or exits before taking it, no other thread is told, where Linux passes it on
  (`retarget_shared_pending`, from `__set_task_blocked` and `exit_signals` in
  kernel/signal.c): the signal waits for a thread that lets it in to look at its
  signals.

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
