Developer preview. zeroemu runs on Apple Silicon Macs only, and one system image is
tested: `system-images;android-36.1;google_apis_playstore;arm64-v8a` (Android 16 QPR2
with Google Play), with Android Emulator 37.1.11 and 37.2.13. The README says what works
and what doesn't.

Install the Mac app with Homebrew, then open `zeroemu.app` from Applications:

```sh
brew install --cask zeroemu/tap/zeroemu-app
```

The app is signed ad hoc and not notarized, so macOS blocks the first open;
[Apple's guidance](https://support.apple.com/en-us/102445) says how to open it anyway.
If you already installed the cask, quit zeroemu and run
`brew update && brew upgrade --cask zeroemu/tap/zeroemu-app`. The Homebrew formula
`zeroemu/tap/zeroemu` installs only the command-line program.

You can also download the [Mac app ZIP](https://github.com/@REPO@/releases/download/@TAG@/zeroemu-@VERSION@-aarch64-apple-darwin.app.zip).
It contains `zeroemu.app`, signed ad hoc but not notarized. Check it against the
`.app.zip.sha256` file and verify its provenance with `gh attestation verify` as
shown for the command-line archive below.

To install the command-line program in an empty folder, this short form checks nothing:

```sh
curl -L https://github.com/@REPO@/releases/download/@TAG@/zeroemu-@VERSION@-aarch64-apple-darwin.tar.gz | tar xz
./zeroemu doctor
```

To check the download before you unpack it:

```sh
curl -LO https://github.com/@REPO@/releases/download/@TAG@/zeroemu-@VERSION@-aarch64-apple-darwin.tar.gz
curl -LO https://github.com/@REPO@/releases/download/@TAG@/SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify zeroemu-@VERSION@-aarch64-apple-darwin.tar.gz --repo @REPO@
tar xzf zeroemu-@VERSION@-aarch64-apple-darwin.tar.gz
./zeroemu doctor
```

`shasum` checks that the archive is the one listed here, and `gh attestation verify`
checks that GitHub Actions built it from this repository. The archive holds `zeroemu`,
`LICENSE`, `NOTICE`, `README.md` and `entitlements.plist`.

macOS refuses to run a copy downloaded in a browser, because the binary is signed ad
hoc. Remove the quarantine flag with `xattr -d com.apple.quarantine ./zeroemu`.
