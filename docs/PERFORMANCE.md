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

A syscall round trip (guest → host → guest) is ~1.0 µs on an M1 Pro (1M
`getpid` calls in 1.0 s), about 10x a native syscall. Planned mitigations:

- a vDSO page so `clock_gettime` / `gettimeofday` never exit the VM;
- fewer register accesses per exit;
- implementing binder transactions and futex wakeups without extra round trips.

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
uploaded, can cost 50 to 150 ms.

Smoothness is expected to come from what disappears: there is no virtual GPU
pipe, no second compositor, no guest kernel scheduler, and no virtual device
emulation.

## CPU

CPU, as macOS counts zeroemu's threads (Activity Monitor's figure), a settled device:

| | Before | Now |
|---|---|---|
| Idle at the home screen | 51% of a core | 16% |
| Flinging the app list | 270-320% | 95% |

- Threads asleep in poll, epoll and the like are woken by keys their files hash onto.
  There were 63 keys for well over a thousand sleeping threads, so every event woke
  dozens of threads that had nothing to do, and that was most of the idle CPU. There
  are now 4096. Netlink sockets, ptys, GPU fences and DRM events have keys of their own,
  where each of their events used to wake everyone or every GPU waiter.
- A vCPU belongs to its host thread, and the hypervisor allows 64. Threads that went to
  sleep holding one kept it for as long as they slept, which kept the pool short, so
  every thread that blocked for a moment gave its own up and made a new one when it
  woke: 150 a second at idle. Now threads asleep in the kernel for a second give theirs
  back when places run short.
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

## Measuring

- Memory: `top -l 1 -pid <pid> -stats mem` or `footprint <pid>` (see above).
- Frame rate: `ZEROEMU_GPU_STATS=1` prints the display's frame rate every five seconds.
- Frame times: `adb shell dumpsys gfxinfo <package>`, as in the tables above.
- Android's own trace markers: `ZEROEMU_TRACE=<file>` with
  `ZEROEMU_PROPS=debug.atrace.tags.enableflags=0x86e`.
- Where a stuck or busy thread is: `kill -USR1` on zeroemu, with `ZEROEMU_SYSCOUNT=1`.
- Use `--no-net` when measuring idle CPU: once the network is up, Google's services and
  the Play Store download and install updates in the background.
