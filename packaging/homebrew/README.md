# Homebrew formula

`zeroemu.rb` is the formula for the tap `zeroemu/tap`, which lives in its own repository,
`zeroemu/homebrew-tap`. Users install with:

```sh
brew install zeroemu/tap/zeroemu
```

The formula builds zeroemu from the release's source tarball and signs it ad hoc with
`entitlements.plist`, as homebrew-core's `lume` formula does for its own entitlements.
A formula rather than a cask, because Homebrew disables casks that fail Gatekeeper's
checks, and an ad-hoc signed binary fails them. Files a formula builds aren't
quarantined, so Gatekeeper never sees zeroemu.

[docs/RELEASING.md](../../docs/RELEASING.md) says how to create the tap (once) and how
to update the formula for each release: fill in `sha256` from the tag's source tarball,
copy the formula to the tap, then `brew install --build-from-source` and `brew test`.

Keep `packaging/homebrew/zeroemu.rb` in this repository the same as the tap's copy, so
the formula's history stays next to the code it builds.
