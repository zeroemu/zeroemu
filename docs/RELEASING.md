# Releasing zeroemu

How the repository is set up on GitHub, and the steps for each release. The command-line
program and Mac app are built, signed and published by `.github/workflows/release.yml`.
The Homebrew formula and cask are updated by hand in the tap.

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
   reads `Formula/zeroemu.rb` from it, and `brew install --cask zeroemu/tap/zeroemu-app`
   reads `Casks/zeroemu-app.rb`. Publish them once their releases and checksums are ready:

   ```sh
   gh repo create zeroemu/homebrew-tap --public --description "Homebrew tap for zeroemu"
   git clone https://github.com/zeroemu/homebrew-tap
   mkdir -p homebrew-tap/Formula homebrew-tap/Casks
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
   note, the download URLs, `cargo install --tag` and the `entitlements.plist` URL).
   Update the Homebrew downloads and their checksums together after the release:

   ```sh
   grep -n '0\.1\.0' README.md   # the old version
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
   attests the archives and the binary, and creates a pre-release with
   `zeroemu-X.Y.Z-aarch64-apple-darwin.tar.gz` and `SHA256SUMS`, plus the Mac app's
   `zeroemu-X.Y.Z-aarch64-apple-darwin.app.zip` and its `.app.zip.sha256` file.
   Its notes are `.github/release-notes.md` followed by GitHub's generated list of changes.

   If the release was already created without its files, run the Release workflow
   from `main` with the existing tag (for example, `gh workflow run release.yml
   --ref main -f tag=vX.Y.Z`). It builds that tag and attaches the files without
   changing the release's notes or replacing existing archive and checksum pairs.
   This also works for adding the app to a CLI-only release whose tag has `scripts/build-app.sh`.

7. **Check the release as a user would:** in a new folder, follow the README's checked
   install (`shasum -a 256 -c SHA256SUMS`, then `gh attestation verify`), then run
   `./zeroemu doctor`. Check the app ZIP separately with its `.app.zip.sha256` file
   and `gh attestation verify` before extracting it.

8. **Fill in the formula's `sha256`** from GitHub's source tarball for the tag, which
   the formula builds from:

   ```sh
   curl -L https://github.com/zeroemu/zeroemu/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
   ```

   Set it in `packaging/homebrew/zeroemu.rb`, next to the new `url`. The cask uses
   the SHA-256 of the **app ZIP**, not the source tarball or command-line archive.

9. **Copy the formula and generate the cask in the tap,** then commit and push it:

   ```sh
   version=X.Y.Z
   cp packaging/homebrew/zeroemu.rb ../homebrew-tap/Formula/zeroemu.rb
   mkdir -p ../homebrew-tap/Casks
   # The checksum file that step 7 checked the app ZIP against.
   app_sha=$(curl -fsSL "https://github.com/zeroemu/zeroemu/releases/download/v$version/zeroemu-$version-aarch64-apple-darwin.app.zip.sha256" | cut -d' ' -f1)
   echo "$app_sha"   # 64 hex digits; if it is empty, the download failed: stop here
   sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$app_sha/g" \
     packaging/homebrew/zeroemu-app.rb.in > ../homebrew-tap/Casks/zeroemu-app.rb
   ```

10. **Install and test it** on an Apple Silicon Mac (`brew update` first if the tap is
    already tapped). Install before testing: installing by the full name trusts the
    formula, and on a Mac that has never installed it, `brew test` and `brew audit`
    refuse an untrusted one.

    ```sh
    brew install --build-from-source zeroemu/tap/zeroemu
    brew test zeroemu/tap/zeroemu
    brew audit --strict --online zeroemu/tap/zeroemu
    brew install --cask zeroemu/tap/zeroemu-app
    ```

    The test checks `zeroemu --version` and that the installed binary still carries
    the `com.apple.security.hypervisor` entitlement. With an older cask already
    installed, quit it and use `brew upgrade --cask zeroemu/tap/zeroemu-app` instead;
    check that the Applications copy has the new version and still lists your devices.

11. **Commit the formula in this repository too,** so `packaging/homebrew/zeroemu.rb`
    stays the same as the tap's copy.
