# Memory, CPU and smoothness

Measurements of zeroemu on an M1 Pro, and what changed to reach them. The debugging
variables named here are described in [DEVELOPMENT.md](DEVELOPMENT.md).

## Memory

Measured on an M1 Pro with the default 4 GB, as Activity Monitor shows it:

| | Activity Monitor |
|---|---|
| Five minutes after a first boot, nothing opened | 3.3 GB |
| 16 apps opened one after another | 5.6 GB |
| Those closed again | 4.2 GB |
| Five minutes after a first boot, before this was looked at | about 14 GB |

- Files on the system image live in a page cache: read and decompressed a page at a time when
  wanted, one copy each, in guest memory, shared by whatever maps them until it writes.
  Pages nothing has mapped stay up to 256 MB and then go, oldest first. ELF segments map
  from the file.
- Files on `/data` take their turn with those. Their pages can leave memory for the data
  file they were last saved in, unchanged, or a scratch file that goes when zeroemu does.
- The guest is told it has 4 GB. Past that, what the page cache holds goes first, and then
  `/proc/pressure/memory` wakes Android's own `lmkd`, which closes the least important apps
  as on a phone. Frames can go past what the guest is told, up to the 32 GB ceiling, if it
  takes `lmkd` a moment; nothing else stops them.
- Frames are kept together by process in 64 KB blocks, each its own memory object, and whole
  blocks go back to the host beyond 64 MB free. A block with any frame in use can't, so
  closing apps gives back less than they took; the rest gets reused first.

Measure with `top -l 1 -pid <pid> -stats mem` or `footprint <pid>`, which agree. `ps`'s RSS
leaves out what macOS has compressed, and can be a tenth of the truth. They agree because
blocks are *purgeable* memory objects, never marked volatile: macOS charges ordinary memory
once for the host's mapping of a page and again for the VM's, and Activity Monitor would show
guest memory twice. This is accounting: the page exists once either way.

## System calls

A syscall round trip (guest → host → guest) is about 0.92 µs on an M1 Pro: 1M `getpid`
calls (`guest/bench_aarch64.S`) took 0.92 s, against 1.04 s before the changes below, the
two run in turn on a busy machine. The figures here come from microbenchmarks and from
counts in single boots; what they add up to for a whole device is under "Before and
after", below.

- A syscall exit makes 9 calls into Hypervisor.framework rather than 14. The EL0 vector
  goes back to EL0 through its own `eret`, so zeroemu reads no EL1 register and writes
  neither PC nor PSTATE for a syscall; a page fault reads ESR, ELR and FAR only.
- On the way back into the guest a thread takes no lock unless a signal is pending or a
  TLB flush is due: pending signals keep a bitmask beside them, and the address space's
  TLB generations are atomics.
- A TLB flush invalidates only the address space's ASID, or the one page that changed,
  as arm64 Linux's `flush_tlb_mm` and `flush_tlb_page` do, and a new vCPU no longer
  flushes. At idle after boot, flushes of the whole VM went from about 730 a second to
  none; about 390 a second now flush one ASID and 130 one page.
- A synchronous binder call's `BR_TRANSACTION_COMPLETE` comes with its reply, as Linux
  defers it, so a call and its reply take 4 exits rather than 5.

arm64 programs get a vDSO, as on Linux, so `clock_gettime`, `gettimeofday` (and
`time`) and `clock_getres` don't exit the VM: they read the virtual counter, which
every vCPU sets to count from CLOCK_MONOTONIC's zero, and a read-only page of the
kernel's offsets. A clock read takes about 25 ns that way, against about 0.95 µs as a
syscall (`guest/clocks.c` measures both). On a device idle after boot, clock calls
were about half of all syscall exits, 1,350 a second; 36 a second are left, for what
the vDSO passes on to the syscall, as Linux's does: the CPU-time clocks, mostly.
`ZEROEMU_NO_VDSO=1` turns it off.

Page faults exit too. As Linux's fault-around does, a fault also maps the other pages
of its 16-page window that are in memory already. In a file mapped read-only, that is
on a read or exec fault, and only pages another mapping has already, since zeroemu
can't take a page back from a mapping to reclaim it. In shared memory and device memory
it is on any fault (for a `/data` file mapped shared, only where the mapping can't
write). In one boot each, that took faults at idle from about 1,700 a second to 1,100.
A fault whose page has to be read from the system image or `/data` reads it with the
address space unlocked, as Linux does with `VM_FAULT_RETRY`, so the process's other
threads don't wait for the read.

Planned:

- a save slot per vCPU at EL1, so that a syscall exit is one `hv_vcpu_run` and one
  register write: an exit alone measures 0.88 µs, against 0.95 µs with the register
  accesses still made;
- futex wakeups without extra round trips.

## Smoothness

Smoothness, measured on an M1 Pro: flinging the launcher's app list 48 times, with a settled
`/data` and the window covered, as Android's own frame statistics (`dumpsys gfxinfo`)
count it, two runs each:

| | Janky frames | Median frame | 90th percentile | 99th percentile |
|---|---|---|---|---|
| Frames read back into host memory (before) | 7.6%, 7.0% | 19, 19 ms | 23, 22 ms | 28, 29 ms |
| The renderer draws into the window | 5.0%, 5.1% | 12, 14 ms | 21, 21 ms | 25, 28 ms |
| And threads stop waking each other for nothing (CPU, below) | 1.2%, 1.0% | 8, 8 ms | 11, 10 ms | 20, 19 ms |

A freshly booted device, still busy setting itself up, gains more (one run each, opening
the app list included): the median frame went from 29 ms to 18 ms and janky frames from
30% to 16%. What changed:

- The renderer draws each frame into the window itself, as the Android Emulator does,
  at the screen's real pixel density. Before, SurfaceFlinger waited 3 ms per frame while
  zeroemu read the frame back, then copied it twice more to show it.
- GPU calls went through one zeroemu thread, so a read on one app's GL pipe, which
  waits for the renderer's answer, held up every other app and SurfaceFlinger's
  composition. Pipe transfers now run on the thread that asked, one at a time per
  context; only creating or freeing a GPU buffer or context waits for the ones under way,
  as the renderer's maps of them have no lock of their own.
- zeroemu tells macOS its work is user-initiated, so App Nap doesn't throttle it while
  its window is covered: a device keeps running in the background, as a phone's apps do
  with the screen off, and under App Nap frames took about eight times as long. The Mac
  can still sleep.
- Fence, vblank and page-flip times were on the wall clock rather than the guest's
  monotonic clock, so Android's frame statistics said every frame took five seconds,
  and SurfaceFlinger's vsync model was fed times it couldn't use.

What's left is mostly the first time something is drawn: a shader compiled, or icons
uploaded, can cost 50 to 150 ms. The work under System calls and CPU left this as it
was: in the runs under "Before and after", janky frames were 0.2 to 0.4% either way
(one run before it was 2.4%), and the 99th percentile 11 to 20 ms.

The graphics path is the Android Emulator's: GL calls go through the same gfxstream pipe
to the same renderer. What differs is the kernel. zeroemu has no guest kernel and no
emulated devices, but each syscall and page fault leaves the VM, where a guest kernel
would handle it without an exit, and each guest thread that sleeps or wakes is a host
thread doing the same.

## CPU

CPU, as macOS counts zeroemu's threads (Activity Monitor's figure), a settled device:

| | Before | Now |
|---|---|---|
| Idle at the home screen | 51% of a core | 16% |
| Flinging the app list | 270-320% | 95% |

The "Now" column was measured before the changes under System calls and before the
vCPU and 2-second wakeup items below.

- Threads asleep in poll, epoll and the like are woken by keys their files hash onto.
  There were 63 keys for well over a thousand sleeping threads, so every event woke
  dozens of threads that had nothing to do, and that was most of the idle CPU. There
  are now 4096. Netlink sockets, ptys, GPU fences and DRM events have keys of their own,
  where each of their events used to wake everyone or every GPU waiter.
- A vCPU belongs to its host thread, and the hypervisor allows 64. Threads that went to
  sleep holding one kept it for as long as they slept, which kept the pool short, so
  every thread that blocked for a moment gave its own up and made a new one when it
  woke: 150 a second at idle. Now a thread keeps its vCPU while it sleeps, and an eighth
  of the places are kept free by asking the threads that have slept longest for theirs;
  only when that falls behind does a thread give its own up as it blocks. Opening seven
  apps made 2,300 vCPUs a second before this and 960 after.
- Threads asleep in a futex, poll, select or epoll woke every 2 seconds, in case a
  wakeup had been lost. Every wakeup now reaches them under the lock they sleep under,
  so they sleep until woken, with a 30-second backstop. With 300 such sleepers,
  zeroemu's host context switches over 10 seconds went from about 1,700 to 120.
- The emulated sensors sent all nine sensors' readings every 10 ms, the fastest rate
  anything had asked for, each reading waking the sensors HAL. The HAL makes Android's
  events itself, at each sensor's rate, from the last reading it got, so zeroemu now
  sends a reading once, when the HAL turns the sensor on.
- The window's event loop wakes every 50 ms rather than every 8 once the renderer draws
  into the window itself.

Android sees CPU time too now: `/proc/<pid>/stat` and `/proc/stat`, `getrusage`, and
the CPU-time clocks (`CLOCK_THREAD_CPUTIME_ID` was the time since boot), so `top`,
`dumpsys cpuinfo` and ART's own accounting work. All of a thread's time counts as user
time: zeroemu can't tell the time it spends on a thread's behalf from the thread's own.

What idle CPU is left is mostly Android's: the composer calls SurfaceFlinger with a
vsync 60 times a second whatever is on screen, as the emulator's images tell
SurfaceFlinger not to trust present fences, and it keeps hardware vsync on for as long
as it doesn't.

## Before and after

The changes under System calls, the vCPU, wakeup and fault items under CPU, and the GPU
calls taken off the renderer's thread, on a whole device: an M1 Pro in ordinary use
(an editor and a browser open, nothing heavy running), no network, and a `/data` that
starts empty, so each run is a first boot and Android is still setting itself up in
the background while it is measured. zeroemu's own CPU time as `ps` counts it. The
build before is the one the changes started from. Each is the median of three runs,
before and after run in turn (before, after, after, before, before, after):

| | Before | After |
|---|---|---|
| Boot, to `sys.boot_completed` | 16.0 s | 13.0 s |
| Idle, a minute from 2.5 minutes after boot | 18.5% of a core | 14.0% |
| Opening 13 apps, scrolling each, then flinging the launcher (about 145 s) | 88% of a core | 67% |
| Syscall exits a second, idle | 1,630 | 890 |
| Syscall exits a second, opening the apps | 27,300 | 14,800 |
| Page faults a second, opening the apps | 6,270 | 4,950 |
| Memory after opening the apps (`top`) | 4.67 GB | 4.43 GB |
| App launch, `am start -W` TotalTime, sum of ten apps' medians | 4.7 s | 3.6 s |
| Launcher fling: janky frames, 99th percentile | 0.2%, 12 ms | 0.4%, 18 ms |

Launch times went down for every app but Calendar (about the same): Maps from 1,042 to
656 ms, Chrome from 320 to 202 ms, Settings from 282 to 198 ms. The first run of the
new build booted in 18.3 s, the other two in 13.0 s; the median is the latter. Memory
at idle didn't change (3.09 against 3.05 GB). The runs' scripts and logs aren't in the
repository; `ZEROEMU_SYSCOUNT=1` with `kill -USR1` gives the exit counts.

## Measuring

- Memory: `top -l 1 -pid <pid> -stats mem` or `footprint <pid>` (see above).
- Frame rate: `ZEROEMU_GPU_STATS=1` prints the display's frame rate every five seconds.
- Frame times: `adb shell dumpsys gfxinfo <package>`, as in the tables above.
- Android's own trace markers: `ZEROEMU_TRACE=<file>` with
  `ZEROEMU_PROPS=debug.atrace.tags.enableflags=0x86e`.
- Where a stuck or busy thread is: `kill -USR1` on zeroemu, with `ZEROEMU_SYSCOUNT=1`.
- Use `--no-net` when measuring idle CPU: once the network is up, Google's services and
  the Play Store download and install updates in the background.
