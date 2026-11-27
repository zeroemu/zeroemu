# Homebrew packages

The [zeroemu tap](https://github.com/zeroemu/homebrew-tap) has two packages:

| Package | Installs | Command |
|---|---|---|
| Cask | The signed `zeroemu.app` bundle in Applications | `brew install --cask zeroemu/tap/zeroemu-app` |
| Formula | The signed `zeroemu` command-line program | `brew install zeroemu/tap/zeroemu` |

The formula builds from the tagged source tarball and signs the binary with the
hypervisor entitlement. The cask installs the app ZIP from GitHub Releases. The app
is signed ad hoc, not notarized.

Homebrew loads a package from a tap other than its own only once it is trusted.
Installing it by its full name, as the commands above do, trusts it, so the install
instructions need no `brew trust` step. `brew info`, `brew test` and `brew audit`
refuse a package that was neither installed that way nor trusted with `brew trust`.

Keep [`zeroemu.rb`](zeroemu.rb) in sync with the tap's formula. Generate the tap's
cask from [`zeroemu-app.rb.in`](zeroemu-app.rb.in) using the release version and the
app ZIP's SHA-256. See [the release steps](../../docs/RELEASING.md) for details.
