class Zeroemu < Formula
  desc "Run Android's system image on Apple Silicon with no guest kernel"
  homepage "https://github.com/zeroemu/zeroemu"
  url "https://github.com/zeroemu/zeroemu/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "4df19dd68a97d26dc7bb352e340a3e20ba54c2bee6dfb27067bb96f047dca0ba"
  license "Apache-2.0"
  head "https://github.com/zeroemu/zeroemu.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64 # The macOS backend is Hypervisor.framework's arm64 interface.
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args
    # Hypervisor.framework refuses to create a VM for a binary without this
    # entitlement. An ad-hoc signature can carry it.
    system "/usr/bin/codesign", "-f", "-s", "-",
           "--entitlements", "entitlements.plist",
           bin/"zeroemu"
  end

  def caveats
    <<~EOS
      zeroemu needs pieces of the Android SDK: the Android Emulator (for its GPU
      renderer) and a system image. Install them with Android Studio's SDK Manager,
      or with:
        sdkmanager "emulator" "platform-tools" "system-images;android-36.1;google_apis_playstore;arm64-v8a"
      (Android Studio's copy, if you installed its Command-line Tools:
      ~/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager)

      Set ANDROID_HOME if your SDK isn't in ~/Library/Android/sdk. Then check
      that a boot should work:
        zeroemu doctor
    EOS
  end

  test do
    # A HEAD build's version is "HEAD-<commit>", which --version doesn't print.
    expected = build.head? ? "zeroemu " : "zeroemu #{version}"
    assert_match expected, shell_output("#{bin}/zeroemu --version")
    # Homebrew may re-sign binaries after install; the entitlement must survive.
    assert_match "com.apple.security.hypervisor",
                 shell_output("/usr/bin/codesign -d --entitlements - #{bin}/zeroemu 2>&1")
  end
end
