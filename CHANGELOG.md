# Changelog

All notable changes to zerosign are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0] - 2026-11-02

Zero dependency.

### Changed

- Release binaries are now fully standalone: every third-party library (OpenSSL,
  libzip, libplist, libusbmuxd, libimobiledevice) is linked statically, so a
  single executable runs on a clean machine with no Homebrew, apt, or MSYS2
  packages installed and no companion `.dylib`, `.so`, or `.dll` files next to
  it. Only the operating system USB service is still expected, namely `usbmuxd`
  on macOS and Linux and Apple Mobile Device Support on Windows.
- The Windows release archive now contains only `zerosign.exe`; the `dist/`
  folder with bundled runtime DLLs is gone.
- OpenSSL is built from source with the `legacy` provider compiled into
  `libcrypto.a`, so older `.p12` certificates unlock without any external
  provider module, and the Windows search-path workaround for the provider was
  removed.
- On Linux and Windows the whole device stack is compiled from source against
  OpenSSL, because Debian and Ubuntu build `libimobiledevice` against GnuTLS and
  ship no static archive for `libplist`, and the MSYS2 archives are built for
  DLL import. macOS takes the Homebrew archives, which are already static.
- CI verifies the zero-dependency property on every platform (`otool -L` on
  macOS, `ldd` on Linux and Windows) and runs the test suite on all three hosts.
- The three overlapping workflows became two: `ci.yaml` builds and tests every
  push and pull request with a dependency cache, while `release.yaml` publishes
  an official release from a clean build that never restores that cache.

### Added

- An end-to-end test suite, `tests/test_zerosign.py` (61 checks): build and
  zero-dependency binary inspection, CLI and help/version workflows, saved
  certificate management, and bundle-sealing security and regression checks
  including tamper detection and zip-slip protection.
- A `make deps` target that builds only the static third-party archives under
  `build/prefix`, so repeated builds reuse them.

### Fixed

- The Windows CI jobs now install the native UCRT64 Python instead of the
  POSIX-flavoured one, so the test suite detects the Windows binary correctly.
- The Windows and Linux builds resolve the intended static archives (msys2 path
  forms, OpenSSL and libzip install directories were corrected).
- Windows links the system libraries a static `libcrypto.a` needs (`crypt32`,
  `ws2_32`, `iphlpapi`, and friends), and skips the unused `tools` and `docs`
  subdirectories of libimobiledevice, which only produced command line binaries.
- libimobiledevice 1.3.0 takes a one-line patch from `patches/` to build on
  Windows, where an IPv6 scope-id helper is declared with a POSIX-only type.
- Only the generated `Makefile.in` of libimobiledevice is rewritten, never its
  `Makefile.am`, so `make` cannot try to rerun `automake` on hosts without it.

## [1.0] - 2026-10-30

First public release.

### Added

- Re-signs iOS `.ipa` packages with a `.p12` certificate and a
  `.mobileprovision` profile: Mach-O parsing, code-signature generation, bundle
  sealing with SHA-1 and SHA-256 resource digests, entitlements, designated
  requirements, and CMS signatures.
- Installs signed packages to a connected iPhone or iPad over USB or Wi-Fi
  through AFC staging and the installation proxy, with live progress.
- `zerosign cert` saves a default certificate in `~/.zerosign/` so later signing
  needs no flags.
- `zerosign check` inspects a package without extracting anything to disk.
- Builds and runs on macOS, Linux, and Windows from a single source file.

[Unreleased]: https://github.com/Senophyx/zerosign/compare/2.0...HEAD
[2.0]: https://github.com/Senophyx/zerosign/compare/1.0...2.0
[1.0]: https://github.com/Senophyx/zerosign/releases/tag/1.0
