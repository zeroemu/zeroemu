---
name: Bug report
about: Something doesn't work, or works differently from a phone or the Android Emulator
title: ""
labels: bug
---

**What happened**

What you did, what you expected, and what happened instead.

**Steps to reproduce**

1.
2.
3.

**zeroemu --version**

```
```

**zeroemu doctor**

Paste the whole output. It shows your home folder's path (`/Users/<your name>`); edit
that out if you like.

```
```

**System image**

The image you booted, for example `system-images;android-36.1;google_apis_playstore;arm64-v8a`
(`zeroemu images` lists yours), and the command line you used.

**Mac**

- macOS version (`sw_vers -productVersion`):
- Mac model and chip (Apple menu > About This Mac, or `sysctl -n hw.model machdep.cpu.brand_string`):

**Terminal output**

zeroemu's output from start to the problem. If the window stays black, or the problem
is in what's drawn, run zeroemu again with `ZEROEMU_LOG=I ZEROEMU_GPU_LOG=I` (for
example `ZEROEMU_LOG=I ZEROEMU_GPU_LOG=I zeroemu`) and paste that output: it shows more
of Android's log and of the renderer's. If it's long, attach it as a file. Look through it first for
anything you don't want to make public: Android's log can hold account names, network
names and app data.

```
```
