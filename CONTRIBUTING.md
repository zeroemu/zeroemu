# Contributing to zeroemu

Thanks for helping. Bug reports, reports about images nobody has tried, fixes and
documentation are all welcome. For anything large, open an issue first, so we can
agree on the approach before you spend time on it.

## What you need

- A Mac with Apple Silicon. zeroemu doesn't build for Intel Macs, and the Windows
  build compiles but has never run.
- Rust 1.89 or newer ([rustup](https://rustup.rs)) and the Xcode Command Line Tools
  (`xcode-select --install`).
- For the Android tests, the Android SDK with `emulator`, `platform-tools` and
  `system-images;android-36.1;google_apis_playstore;arm64-v8a`. The README says how to
  install them.

## Build and sign

```sh
cargo build --release
codesign -s - -f --entitlements entitlements.plist target/release/zeroemu
```

macOS refuses to create a virtual machine for a binary without the
`com.apple.security.hypervisor` entitlement. `cargo run` and `cargo test` sign for you,
through the runner in `.cargo/config.toml` (`scripts/macos-runner.sh`). After a plain
`cargo build`, sign again as above, since the build drops the signature.

## Tests

| Command | Needs |
|---|---|
| `cargo test --release` | Nothing more. Unit tests don't create a VM. Tests that read an SDK image skip when the tested image isn't installed |
| `scripts/build-guests.sh` | The Xcode Command Line Tools. Builds the static Linux test programs in `guest/` |
| `scripts/test-guests.sh` | Apple Silicon. Runs every test program under zeroemu |
| `scripts/test-android.sh` | Apple Silicon and the SDK image. Runs Android's linker, toybox and mksh from the image |
| `scripts/test-net.py` | Apple Silicon, a signed release build and the guests |
| `scripts/test-tcp.py` | Apple Silicon, a signed release build and the guests |
| `scripts/test-adb.sh` | Apple Silicon, a signed release build, and the SDK with `emulator`, `platform-tools` and the image. Boots Android (its window opens behind yours) and uses real adb against it |

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) says what each one checks, and lists the
debugging variables.

CI builds zeroemu, checks that it still builds with Rust 1.89, runs clippy and the unit
tests, builds the guests, and checks that the Windows build compiles. GitHub's macOS
runners have no nested virtualization, so CI can't run anything that creates a VM.
Before you open a pull request, run the tests your change can affect on your own Mac,
and say in the pull request which ones you ran.

## How the code is written

- Comments explain why, not what. Say what Linux or Android does and why zeroemu does
  the same, or why it doesn't. When a rule comes from Linux, name the source file
  (for example `fs/namei.c`).
- Plain words and short sentences, in comments, docs, commit messages and errors. No
  marketing words.
- Follow the formatting of the file you change. The code isn't run through rustfmt.
- Keep to the design rules in [docs/INTERNALS.md](docs/INTERNALS.md#design-rules). Most
  of all: nothing under `src/kernel/` may use POSIX APIs to implement what the guest
  sees, because the same code has to run on Windows.
- When you add a debugging variable, name it `ZEROEMU_*` and add it to
  docs/DEVELOPMENT.md. When you find a gap, add it to docs/KNOWN-GAPS.md.
- A change to guest-visible behaviour should come with a check in a test guest
  (`guest/*.c`) or in one of the scripts.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by` line, which says you agree to the
[Developer Certificate of Origin](https://developercertificate.org): that you wrote the
change, or otherwise have the right to submit it under the project's licence.
`git commit -s` adds the line for you:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name, or the name you are known by, and an email address you can be
reached at. To sign off commits you already made, use `git rebase --signoff main`.
Nothing checks for the line automatically yet; maintainers look for it in review.

## Releases

[docs/RELEASING.md](docs/RELEASING.md) has the one-time GitHub setup and the steps for
each release: the version bump, the tag, the release workflow and the Homebrew formula.

## Licence

zeroemu is licensed under Apache-2.0. By contributing, you agree that your
contributions are licensed under it too (section 5 of the [LICENSE](LICENSE)).
