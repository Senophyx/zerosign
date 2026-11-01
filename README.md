# zerosign

A zero-dependency, single-file C++ command-line tool that re-signs iOS `.ipa` packages and installs them onto a connected iPhone or iPad over USB or Wi-Fi.

Everything lives in `zerosign.cpp`: Mach-O parsing, code signature generation, bundle sealing, and the device install protocol. No Xcode, no `codesign`, no platform-specific headers.

## Features

- **Re-signs `.ipa` packages** with a `.p12` certificate and a `.mobileprovision` profile.
- **Installs to a device** through AFC staging and the installation proxy, with live progress.
- **Saves a default certificate** in `~/.zerosign/` so later signing needs no flags.
- **Inspects a package** without extracting anything to disk.
- **Portable**. No third-party library to install.

## Install

Every release publishes one standalone executable per platform. It contains all
third-party libraries inside, so it runs on a clean machine.
Only the operating system USB service is still expected, `usbmuxd` on
macOS and Linux and Apple Mobile Device Support on Windows.

| Platform | Release asset | Contents |
| --- | --- | --- |
| macOS | `zerosign-<version>-macos.tar.gz` | `zerosign` |
| Linux | `zerosign-<version>-linux.tar.gz` | `zerosign` |
| Windows | `zerosign-<version>-windows.zip` | `zerosign.exe` |

On macOS or Linux, unpack the archive and move the binary somewhere on your `PATH`:

```bash
tar -xzf zerosign-<version>-linux.tar.gz
sudo mv zerosign /usr/local/bin/
```

On Windows, unpack the zip anywhere, for example `C:\Tools\zerosign`, and add
that folder to your `PATH`. The executable is self-contained.

## Usage

```
zerosign sign <ipa-path> [--pkey <p12>] [--prov <profile>] [--password <pw>]
                      [--output <path>] [-i]
zerosign install <ipa-path>
zerosign cert
zerosign check <ipa-path>
zerosign --version
```

| Option | Meaning |
| --- | --- |
| `--pkey <p12>` | signing certificate |
| `--prov <profile>` | provisioning profile |
| `--password <pw>` | certificate password, prompted when omitted |
| `-o, --output <path>` | output path, defaults to `<name>-signed.ipa` |
| `-i, --install` | install right after signing |
| `-v, --version` | print the version and exit |

### Sign a package

With an explicit certificate:

```bash
zerosign sign app.ipa --pkey cert.p12 --prov cert.mobileprovision --password test
```

```
Successfully signed `app.ipa` to `./path/to/app-signed.ipa`!
```

The output defaults to the input directory and base name with `-signed.ipa` appended. Use `--output` to choose the exact path:

```bash
zerosign sign app.ipa --pkey cert.p12 --prov cert.mobileprovision --password test \
    --output ~/Downloads/app.ipa
```

If `--password` is omitted, zerosign prompts for it without echoing:

```
Input Password :
```

### Sign with the saved certificate

After `zerosign cert` has stored a certificate, both flags can be left out:

```bash
zerosign sign app.ipa
```

```
Signing using "main" certificate...
Successfully signed `app.ipa` to `./path/to/app-signed.ipa`!
```

### Install a package

```bash
zerosign install app-signed.ipa
```

```
Installing app-signed.ipa to <device-name>: 50%
app-signed.ipa successfully installed to <device-name>
```

The device name is read from the connected device, and the percentage updates while the install runs. The device must be paired and trusted.

### Sign and install in one step

```bash
zerosign sign app.ipa -i
```

```
Installing app.ipa to <device-name>: 50%
app.ipa successfully installed to <device-name>
```

### Inspect a package

```bash
zerosign check app.ipa
```

```
App Name : TestApp
App Version : 1.0
Bundle Id : com.test.app
Signed : False
```

The name comes from `CFBundleDisplayName`, falling back to `CFBundleName` and then `CFBundleExecutable`. The version comes from `CFBundleShortVersionString`, falling back to `CFBundleVersion`.

`Signed` is `True` only when the signature actually verifies: the bundle carries `_CodeSignature/CodeResources`, the main executable has a code signature with a CMS blob, every code page hash in the code directory matches, and every file listed in `CodeResources` still matches its recorded digest. Editing any sealed file flips the result to `False`.

## Saved certificate

`zerosign cert` copies the certificate and profile into `~/.zerosign/` and records them in `~/.zerosign/zerosign.json`. On Windows the same folder is `%USERPROFILE%\.zerosign`.

```
~/.zerosign/
├── zerosign.json
├── <unique-name>.p12
└── <unique-name>.mobileprovision
```

```json
{
    "version": "1.0",
    "certificate": {
        "name": "main",
        "pkey": "~/.zerosign/main.p12",
        "prov": "~/.zerosign/main.mobileprovision",
        "password": "password"
    }
}
```

The command prompts for both files, the password, and a name:

```
Input .p12 file : ./main.p12
Input .mobileprovision file : ./main.mobileprovision
Input password : 1
Name (for identification only, leave it blank if you want it random) :

Success! Saved to ~/.zerosign/
```

Leave the name blank to get a random identifier. The certificate and profile are validated before anything is written, so a wrong password or a mismatched pair leaves the existing entry untouched. If a certificate is already saved, zerosign asks before replacing it; answering anything other than `y` aborts without changing anything.

The password is stored in plain text inside `~/.zerosign/zerosign.json`, because signing needs it without prompting. Keep that directory private.

## How signing works

For every code bundle in the package, zerosign:

1. Signs nested code first, deepest bundles outward, so the outer seal hashes final bytes.
2. Signs loose Mach-O files inside the bundle.
3. Writes the profile to `embedded.mobileprovision` in every `.app` bundle.
4. Generates `_CodeSignature/CodeResources` with SHA-1 and SHA-256 digests of every sealed file, and records symbolic links by target.
5. Signs the bundle executable last, sealing the `Info.plist` and `CodeResources` digests into the code directory.

Each Mach-O image gets an embedded `SuperBlob` containing:

- a single SHA-256 `CodeDirectory`,
- the designated requirement,
- the entitlements, in both plist and DER form, on the app executable only,
- a CMS signature over the code directory, carrying the Apple intermediate and root certificates.

If a binary has no room for a larger signature, zerosign grows the `__LINKEDIT` segment and injects or resizes `LC_CODE_SIGNATURE`. Universal binaries are rebuilt with each slice re-aligned and the fat header updated.

## Notes and limits

- Only the main executable receives the entitlements from the profile; nested frameworks and libraries are signed without them, which is what Apple's own tooling does.
- The app bundle identifier should match the profile's `application-id`. A mismatch still produces a valid signature, but the device rejects the install.
- Encrypted binaries from the App Store cannot be re-signed meaningfully, because their code pages are still encrypted for the original account.
- macOS reports `CSSMERR_TP_NOT_TRUSTED` when verifying an iOS distribution certificate, since the certificate is not trusted on the desktop. That is expected; the signature itself verifies.

## Uninstall

zerosign keeps no state outside the binary and its certificate folder, so removing both leaves nothing behind.

### macOS and Linux

Remove the binary. If you installed it to `/usr/local/bin`:

```bash
sudo rm -f /usr/local/bin/zerosign
```

If you keep it somewhere else, remove it from there instead. To find it:

```bash
which zerosign
```

Then delete the saved certificate folder, which also removes the stored password:

```bash
rm -rf ~/.zerosign
```

### Windows

Remove the folder you unpacked zerosign into, for example:

```powershell
Remove-Item -Recurse -Force C:\Tools\zerosign
```

Then delete the certificate folder:

```powershell
Remove-Item -Recurse -Force "$env:USERPROFILE\.zerosign"
```

If you added the zerosign folder to your `PATH`, remove that entry as well through **System Properties** > **Environment Variables**.

### Verify it is gone

```bash
which zerosign        # macOS and Linux, prints nothing when removed
ls ~/.zerosign        # macOS and Linux, should report no such file
```

```powershell
Get-Command zerosign   # Windows, should report nothing
Test-Path "$env:USERPROFILE\.zerosign"   # Windows, should print False
```

## Building from source

Requirements:

- A C++17 compiler (`clang++` on macOS, `g++` on Linux and Windows).
- `make`, `pkg-config`, `cmake`, `curl`, and `patch`.

Some libraries are compiled by the build itself, so no package manager version
of them is used: OpenSSL 3, libzip, and on Linux and Windows the whole device stack
(`libplist`, `libimobiledevice-glue`, `libusbmuxd`, `libimobiledevice`). OpenSSL
is built with the `legacy` provider compiled into `libcrypto.a`, which is what
lets older `.p12` certificates unlock without an external provider module.

macOS takes the device stack from Homebrew, which already builds it against
OpenSSL and ships static archives:

```bash
brew install libimobiledevice libplist pkg-config cmake
```

On Debian or Ubuntu the distribution builds `libimobiledevice` against GnuTLS
and ships no static archive for `libplist`, so the build compiles that stack from
source instead. No device library has to be installed:

```bash
sudo apt install build-essential pkg-config cmake curl patch zlib1g-dev
```

On Windows, use an MSYS2 UCRT64 shell; the device stack is compiled from source there too, so only the toolchain is needed:

```bash
pacman -S --needed perl curl tar patch mingw-w64-ucrt-x86_64-gcc \
    mingw-w64-ucrt-x86_64-make mingw-w64-ucrt-x86_64-pkgconf \
    mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-zlib
```

Then build:

```bash
make                 # detects the host OS and builds the binary
make compile mac     # clang++ with Homebrew paths, produces ./zerosign
make compile linux   # g++ with system paths, produces ./zerosign
make compile win     # g++ with MSYS2 UCRT64 paths, produces ./zerosign.exe
make deps            # only builds the static archives under build/prefix
make clean           # removes the binary and the whole build/ directory
```

`make` picks the target from the host: `Darwin` builds macOS, `MINGW*`, `MSYS*`, `CYGWIN*`, or `Windows_NT` builds Windows, everything else builds Linux.

The first build downloads and compiles the libraries into `build/prefix`; later
builds reuse it. Everything is linked statically, so the result is a single
executable in the project root that you can copy to another machine of the same
platform and run as is.

To confirm the binary carries no third-party shared library:

```bash
otool -L ./zerosign      # macOS: no /opt/homebrew or /usr/local entries
ldd ./zerosign           # Linux: only glibc entries, no libz/libcrypto
ldd ./zerosign.exe       # Windows: only C:\Windows system DLLs
```

## Acknowledgements

Special thanks to the creators and contributors of the following projects, which served as great references during the development of `zerosign`:

* [zsign](https://github.com/zhlynn/zsign) – Valuable reference for Mach-O binary structure, code signing, and bundle validation.
* [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller) – Helpful reference for iOS device communication, AFC staging, and the app installation lifecycle.

## License
```
This project is licensed under the MIT License.
Copyright (c) 2026 Senophyx
```