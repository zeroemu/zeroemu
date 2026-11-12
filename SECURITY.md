# Security

## zeroemu is not a sandbox

zeroemu is a developer tool for running Android's own system image. It doesn't
isolate Android from your Mac, and you shouldn't treat it as if it did.

- **Android runs inside your own process.** Guest code runs in a hardware virtual
  machine, but every system call it makes is carried out by zeroemu, in a process
  that has your user's rights on the Mac. zeroemu reads and writes files (the SDK
  image, the device's `/data` file), opens network connections, and loads Google's
  GPU renderer, which decodes the guest's graphics commands in the same process. A
  bug in zeroemu or in the renderer that guest code can reach would give that code
  your rights on the Mac.
- **Apps' network connections are your Mac's own.** There is no separate network: when
  an app connects somewhere, zeroemu makes that connection from your Mac. 10.0.2.2
  reaches your Mac's loopback, so apps on the device can reach services listening on
  127.0.0.1, as on the Android Emulator (zeroemu keeps the adb server's and devices'
  own ports out of reach). An app without the INTERNET permission still gets out, and
  VPN apps don't see the traffic they believe they tunnel.
- **SELinux is permissive.** The image's policy is loaded and processes get its
  contexts, but no access is ever denied.
- **File permissions are partial.** Linux's rules apply where owners and modes are
  real; `/proc`, `/sys` and some other filesystems have made-up modes, and shared
  storage (`/sdcard`) has no scoped storage, so any app may read and write anything
  there. See [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md).
- **adb listens on 127.0.0.1 only**, and adbd keeps its RSA key check: your own key
  (`~/.android/adbkey.pub`) is authorized, and no other.

Don't run apps on zeroemu that you wouldn't run on your Mac itself.

The release binary is signed ad hoc, with one entitlement:
`com.apple.security.hypervisor`, which lets it create a virtual machine. It doesn't use
the hardened runtime. Check a download with the release's `SHA256SUMS` file, and check
that GitHub Actions built it from this repository with
`gh attestation verify <file> --repo zeroemu/zeroemu`. The README's
[install section](README.md#from-github-releases) shows both.

## Reporting a vulnerability

Please report security problems privately, through GitHub's private vulnerability
reporting: <https://github.com/zeroemu/zeroemu/security/advisories/new>. Don't open a
public issue for them.

Say what the problem is, how to reproduce it, and which version (`zeroemu --version`),
system image and macOS version you used. You'll get a reply in the advisory, and
credit in the fix's release notes if you want it.

Only the newest release and the `main` branch get security fixes.

Problems in Android itself, in the system images or in the Android Emulator's renderer
belong with Google: see <https://source.android.com/docs/security/overview/updates-resources>.
