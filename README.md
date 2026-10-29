# csign

A single-file C++ command-line tool that re-signs iOS `.ipa` packages and installs them onto a connected iPhone or iPad over USB or Wi-Fi.

Everything lives in `csign.cpp`: Mach-O parsing, code signature generation, bundle sealing, and the device install protocol. No Xcode, no `codesign`, no platform-specific headers.

## Features

- **Re-signs `.ipa` packages** with a `.p12` certificate and a `.mobileprovision` profile.
- **Installs to a device** through AFC staging and the installation proxy, with live progress.
- **Saves a default certificate** in `~/.csign/` so later signing needs no flags.
- **Inspects a package** without extracting anything to disk.
- **Portable**: builds and runs on macOS and Linux from the same source.

## Requirements

- A C++17 compiler (`clang++` on macOS, `g++` on Linux).
- `pkg-config` and these libraries:
  - `libcrypto`, `libssl` (OpenSSL 3 or newer)
  - `libimobiledevice-1.0`
  - `libplist-2.0`
  - `libzip`
  - `zlib`

On macOS with Homebrew:

```bash
brew install openssl@3 libimobiledevice libplist libzip
```

On Debian or Ubuntu:

```bash
sudo apt install build-essential pkg-config libssl-dev libimobiledevice-dev libplist-dev libzip-dev zlib1g-dev
```

## Build

```bash
make                 # detects the host OS and builds ./csign
make compile mac     # clang++ with Homebrew paths
make compile linux   # g++ with system paths
make clean           # removes the binary and object files
```

The result is a single `csign` executable in the project root.

## Usage

```
csign sign <ipa-path> [--pkey <p12>] [--prov <profile>] [--password <pw>]
                      [--output <path>] [-i]
csign install <ipa-path>
csign cert
csign check <ipa-path>
```

### Sign a package

With an explicit certificate:

```bash
csign sign app.ipa --pkey cert.p12 --prov cert.mobileprovision --password test
```

```
Successfully signed `app.ipa` to `./path/to/app-signed.ipa`!
```

The output defaults to the input directory and base name with `-signed.ipa` appended. Use `--output` to choose the exact path:

```bash
csign sign app.ipa --pkey cert.p12 --prov cert.mobileprovision --password test \
    --output ~/Downloads/app.ipa
```

If `--password` is omitted, csign prompts for it without echoing:

```
Input Password :
```

### Sign with the saved certificate

After `csign cert` has stored a certificate, both flags can be left out:

```bash
csign sign app.ipa
```

```
Signing using "main" certificate...
Successfully signed `app.ipa` to `./path/to/app-signed.ipa`!
```

### Install a package

```bash
csign install app-signed.ipa
```

```
Installing app-signed.ipa to <device-name>: 50%
app-signed.ipa successfully installed to <device-name>
```

The device name is read from the connected device, and the percentage updates while the install runs. The device must be paired and trusted.

### Sign and install in one step

```bash
csign sign app.ipa -i
```

```
Installing app.ipa to <device-name>: 50%
app.ipa successfully installed to <device-name>
```

### Inspect a package

```bash
csign check app.ipa
```

```
App Name : TestApp
App Version : 1.0
Bundle Id : com.test.app
Signed : False
```

The name comes from `CFBundleDisplayName`, falling back to `CFBundleName` and then `CFBundleExecutable`. The version comes from `CFBundleShortVersionString`, falling back to `CFBundleVersion`. `Signed` is `True` only when the bundle carries `_CodeSignature/CodeResources` and the main executable has a code signature with a populated signature blob.

## Saved certificate

`csign cert` copies the certificate and profile into `~/.csign/` and records them in `~/.csign/csign.json`:

```
~/.csign/
├── csign.json
├── <unique-name>.p12
└── <unique-name>.mobileprovision
```

```json
{
    "version": "1.0",
    "certificate": {
        "name": "main",
        "pkey": "~/.csign/main.p12",
        "prov": "~/.csign/main.mobileprovision",
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

Success! Saved to ~/.csign/
```

Leave the name blank to get a random identifier. The certificate and profile are validated before anything is written, so a wrong password or a mismatched pair leaves the existing entry untouched. If a certificate is already saved, csign asks before replacing it; answering anything other than `y` aborts without changing anything.

The password is stored in plain text inside `~/.csign/csign.json`, because signing needs it without prompting. Keep that directory private.

## How signing works

For every code bundle in the package, csign:

1. Signs nested code first, deepest bundles outward, so the outer seal hashes final bytes.
2. Signs loose Mach-O files inside the bundle.
3. Writes a matching `embedded.mobileprovision` when the bundle identifier fits the profile.
4. Generates `_CodeSignature/CodeResources` with SHA-1 and SHA-256 digests of every sealed file.
5. Signs the bundle executable last, sealing the `Info.plist` and `CodeResources` digests into the code directory.

Each Mach-O image gets an embedded `SuperBlob` containing:

- a SHA-1 `CodeDirectory` and a SHA-256 alternate,
- the designated requirement,
- the entitlements, in both plist and DER form,
- a CMS signature over the primary code directory, carrying the Apple intermediate and root certificates.

If a binary has no room for a larger signature, csign grows the `__LINKEDIT` segment and injects or resizes `LC_CODE_SIGNATURE`. Universal binaries are rebuilt with each slice re-aligned and the fat header updated.

## Notes and limits

- Only the main executable receives the entitlements from the profile; nested frameworks and libraries are signed without them, which is what Apple's own tooling does.
- The app bundle identifier should match the profile's `application-id`. A mismatch still produces a valid signature, but the device rejects the install.
- Encrypted binaries from the App Store cannot be re-signed meaningfully, because their code pages are still encrypted for the original account.
- macOS reports `CSSMERR_TP_NOT_TRUSTED` when verifying an iOS distribution certificate, since the certificate is not trusted on the desktop. That is expected; the signature itself verifies.

## Acknowledgements

Special thanks to the creators and contributors of the following projects, which served as great references during the development of `csign`:

* [zsign](https://github.com/zhlynn/zsign) – Valuable reference for Mach-O binary structure, code signing, and bundle validation.
* [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller) – Helpful reference for iOS device communication, AFC staging, and the app installation lifecycle.

## License
```
This Project under MIT License
Copyright (c) 2026 Senophyx
```