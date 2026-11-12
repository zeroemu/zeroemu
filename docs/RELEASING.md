# Releasing zeroemu

How the repository is set up on GitHub, and the steps for each release. The release
binary is built, signed and published by `.github/workflows/release.yml`; the Homebrew
formula is copied by hand into the tap.

## Before going public (once)

1. **Create the `zeroemu` organisation** on GitHub (Your organizations > New
   organization; the free plan is enough), and in it the public repository
   `zeroemu/zeroemu`:

   ```sh
   gh repo create zeroemu/zeroemu --public \
     --description "Runs Android's own system image on the host CPU with no guest kernel; Linux's system calls are implemented in Rust"
   ```

2. **Push only `main`.** The other local branches (`master`, `init/*`) stay local.
   Everything pushed is public for good, so look at the commits' author names and
   email addresses first:

   ```sh
   git log --format='%an <%ae>' | sort -u
   git remote add origin https://github.com/zeroemu/zeroemu.git
   git push -u origin main
   ```

3. **Turn on private vulnerability reporting:** in the repository, Settings > Advanced
   Security (in the sidebar's Security and quality section; called Code security on older
   pages) > Private vulnerability reporting > Enable. SECURITY.md and
   `.github/ISSUE_TEMPLATE/config.yml` send reporters to
   <https://github.com/zeroemu/zeroemu/security/advisories/new>, which works only once
   this is on. It is off for a new repository. From the command line:

   ```sh
   gh api -X PUT repos/zeroemu/zeroemu/private-vulnerability-reporting
   gh api repos/zeroemu/zeroemu/private-vulnerability-reporting   # {"enabled":true}
   ```

4. **Create the Homebrew tap**, `zeroemu/homebrew-tap`. `brew install zeroemu/tap/zeroemu`
   reads `Formula/zeroemu.rb` from it. The formula goes in at the first release, once
   its `sha256` can be filled in:

   ```sh
   gh repo create zeroemu/homebrew-tap --public --description "Homebrew tap for zeroemu"
   git clone https://github.com/zeroemu/homebrew-tap
   mkdir -p homebrew-tap/Formula
   ```

The release workflow's build provenance attestation needs a public repository (a
private one needs GitHub Enterprise Cloud), so push the first tag only after the
repository is public.

## Each release

Replace `X.Y.Z` with the new version. For the first release, v0.1.0, Cargo.toml and
the README already say 0.1.0, so start at step 3.

1. **Bump the version** in `Cargo.toml`. Build once, so `Cargo.lock` has it too: the
   release workflow builds with `--locked`, which fails on a stale lock file.

   ```sh
   cargo build --release
   ```

2. **Change the old version everywhere users copy it from:** README.md (the preview
   note, the download URLs, `cargo install --tag` and the `entitlements.plist` URL)
   and `url` in `packaging/homebrew/zeroemu.rb`. This finds them:

   ```sh
   grep -rn '0\.1\.0' README.md packaging/homebrew/zeroemu.rb   # the old version
   ```

3. **Run the tests on a Mac** ([CONTRIBUTING.md](../CONTRIBUTING.md#tests) lists them),
   including `scripts/test-adb.sh`, which boots the tested image. CI can't create a VM,
   so it doesn't run them.

4. **Commit and push to `main`,** and wait for CI to pass.

5. **Tag the release and push the tag.** The tag must match the version in Cargo.toml;
   the workflow checks.

   ```sh
   git tag -a vX.Y.Z -m "zeroemu X.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Wait for `release.yml`** to finish (`gh run watch`, or the Actions tab). It builds
   and signs zeroemu, checks the signature, the version and the archive's contents,
   attests the archive and the binary, and creates a pre-release with
   `zeroemu-X.Y.Z-aarch64-apple-darwin.tar.gz` and `SHA256SUMS`. Its notes are
   `.github/release-notes.md` followed by GitHub's generated list of changes.

7. **Check the release as a user would:** in a new folder, follow the README's checked
   install (`shasum -a 256 -c SHA256SUMS`, then `gh attestation verify`), then run
   `./zeroemu doctor`.

8. **Fill in the formula's `sha256`** from GitHub's source tarball for the tag, which
   the formula builds from:

   ```sh
   curl -L https://github.com/zeroemu/zeroemu/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
   ```

   Set it in `packaging/homebrew/zeroemu.rb`, next to the new `url`.

9. **Copy the formula to the tap,** then commit and push the tap:

   ```sh
   cp packaging/homebrew/zeroemu.rb ../homebrew-tap/Formula/zeroemu.rb
   ```

10. **Install and test it** on an Apple Silicon Mac (`brew update` first if the tap is
    already tapped):

    ```sh
    brew install --build-from-source zeroemu/tap/zeroemu
    brew test zeroemu/tap/zeroemu
    brew audit --strict --online zeroemu/tap/zeroemu
    ```

    The test checks `zeroemu --version` and that the installed binary still carries
    the `com.apple.security.hypervisor` entitlement.

11. **Commit the formula in this repository too,** so `packaging/homebrew/zeroemu.rb`
    stays the same as the tap's copy.
