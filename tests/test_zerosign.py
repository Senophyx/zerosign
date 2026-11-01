#!/usr/bin/env python3
# End-to-end test suite for zerosign: build, zero-dependency binary inspection,
# CLI workflows, and bundle-sealing security checks. Standard library only.

import json
import os
import platform
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

# os.name is "nt" on native Windows; sys.platform also catches the msys/cygwin
# shells, whose POSIX flavour python would otherwise look like Linux.
IS_WINDOWS = os.name == "nt" or sys.platform in ("msys", "cygwin")
BINARY = "zerosign.exe" if IS_WINDOWS else "zerosign"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "tests", "assets")
TEST_IPA = os.path.join(ASSETS, "test.ipa")
TEST_P12 = os.path.join(ASSETS, "test.p12")
TEST_PROV = os.path.join(ASSETS, "test.mobileprovision")
HAVE_FIXTURES = all(os.path.isfile(p) for p in (TEST_IPA, TEST_P12, TEST_PROV))

passed = 0
failed = 0
failures = []


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  ok   %s" % name)
    else:
        failed += 1
        failures.append(name)
        print("  FAIL %s%s" % (name, (" :: " + detail) if detail else ""))


def section(title):
    print("\n== %s ==" % title)


def run(args, cwd=None, stdin_text=None, env=None):
    environment = dict(os.environ)
    if env:
        environment.update(env)
    return subprocess.run(
        [os.path.join(ROOT, BINARY)] + args,
        cwd=cwd or ROOT,
        input=stdin_text,
        capture_output=True,
        text=True,
        env=environment,
        timeout=600,
    )


def make_env(home):
    # The saved certificate lives in $HOME/.zerosign, so every subprocess that
    # could touch it gets a throwaway home directory.
    env = {"HOME": home}
    if IS_WINDOWS:
        env["USERPROFILE"] = home
    return env


# ---------------------------------------------------------------------------
# Mach-O helpers (little-endian, 64-bit; zerosign's own arm64 output layout)
# ---------------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
SUPERBLOB_MAGIC = 0xFADE0CC0


def macho_signature_command(data):
    """Returns (dataoff, datasize) of LC_CODE_SIGNATURE, or None."""
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        return None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            return None
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > len(data):
            return None
        if cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                return None
            return struct.unpack_from("<II", data, cursor + 8)
        cursor += cmdsize
    return None


def macho_superblob_slots(data):
    """Returns the list of slot indices present in the embedded superblob."""
    signature = macho_signature_command(data)
    if signature is None:
        return None
    dataoff, datasize = signature
    if dataoff + 12 > len(data):
        return None
    magic, _length, count = struct.unpack_from(">III", data, dataoff)
    if magic != SUPERBLOB_MAGIC:
        return None
    slots = []
    for j in range(count):
        index, offset = struct.unpack_from(">II", data, dataoff + 12 + 8 * j)
        slots.append(index)
    return slots


def strip_code_signature(data):
    """Removes the LC_CODE_SIGNATURE load command from a 64-bit Mach-O."""
    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        raise ValueError("not a little-endian 64-bit Mach-O")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    cursor = 32
    out = bytearray(data)
    while cursor + 8 <= len(out):
        cmd, cmdsize = struct.unpack_from("<II", out, cursor)
        if cmdsize < 8:
            break  # malformed tail; there is no command left to strip
        if cmd == LC_CODE_SIGNATURE:
            del out[cursor:cursor + cmdsize]
            struct.pack_into("<II", out, 16, ncmds - 1, sizeofcmds - cmdsize)
            return bytes(out)
        cursor += cmdsize
    return data  # already unsigned: nothing to strip


# ---------------------------------------------------------------------------
# IPA helpers
# ---------------------------------------------------------------------------

def build_ipa(path, payload_files):
    """payload_files: dict of zip name -> bytes, or (bytes, unix_mode) tuple."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in payload_files.items():
            if isinstance(value, tuple):
                contents, mode = value
            else:
                contents, mode = value, None
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            if name.endswith("/"):
                info.external_attr = (0o40755 << 16) | 0x10
                archive.writestr(info, b"")
            else:
                info.external_attr = ((mode if mode is not None else 0o100644) << 16)
                archive.writestr(info, contents)


def read_entry(ipa_path, entry_name):
    with zipfile.ZipFile(ipa_path) as archive:
        return archive.read(entry_name)


def entry_mode(ipa_path, entry_name):
    with zipfile.ZipFile(ipa_path) as archive:
        info = archive.getinfo(entry_name)
    return info.external_attr >> 16


def app_dir(ipa_path):
    with zipfile.ZipFile(ipa_path) as archive:
        for name in archive.namelist():
            if name.startswith("Payload/") and ".app/" in name + "/":
                top = "Payload/" + (name[len("Payload/"):].split("/")[0])
                if top.endswith(".app"):
                    return top
    raise AssertionError("no Payload/*.app in %s" % ipa_path)


def ipa_info_plist(ipa_path):
    return plistlib.loads(read_entry(ipa_path, app_dir(ipa_path) + "/Info.plist"))


def zip_symlink(ipa_path, entry_name):
    """Returns the link target when the entry is stored as a symlink."""
    with zipfile.ZipFile(ipa_path) as archive:
        info = archive.getinfo(entry_name)
    if (info.external_attr >> 16) & 0o170000 != 0o120000:
        return None
    return read_entry(ipa_path, entry_name).decode()


def find_executable(ipa_path):
    return app_dir(ipa_path) + "/" + ipa_info_plist(ipa_path)["CFBundleExecutable"]


def check_output(ipa_path, workdir=None):
    result = run(["check", ipa_path], cwd=workdir)
    fields = {}
    for line in result.stdout.splitlines():
        if " : " in line:
            key, _, value = line.partition(" : ")
            fields[key.strip()] = value.strip()
    return result, fields


def run_main():
    build_requested = "--build" in sys.argv
    binary_path = os.path.join(ROOT, BINARY)

    # -----------------------------------------------------------------------
    section("Stage 1: build & compilation")
    if build_requested or not os.path.isfile(binary_path):
        make = "mingw32-make" if IS_WINDOWS else "make"
        build = subprocess.run([make], cwd=ROOT, timeout=7200)
        check("make exits 0", build.returncode == 0, "exit %d" % build.returncode)
    else:
        check("existing binary found (pass --build to force a rebuild)", True)
    check("binary exists in project root", os.path.isfile(binary_path))
    if not IS_WINDOWS:
        check("binary is executable", os.access(binary_path, os.X_OK))
    version = run(["--version"])
    check("binary runs", version.returncode == 0, version.stderr.strip())

    # -----------------------------------------------------------------------
    section("Stage 2: zero-dependency binary")
    system = platform.system()
    if system == "Darwin":
        output = subprocess.run(["otool", "-L", binary_path],
                                capture_output=True, text=True).stdout
        bad = [token for token in ("/opt/homebrew", "/usr/local", "libcrypto", "libssl",
                                   "libimobiledevice", "libplist", "libusbmuxd", "libzip")
               if token in output]
        check("no homebrew or third-party dylibs", not bad, "found: %s" % bad)
        lines = [line.strip().split(" (")[0] for line in output.splitlines()[1:] if line.strip()]
        outside = [line for line in lines
                   if not line.startswith("/usr/lib/") and not line.startswith("/System/Library/")]
        check("only macOS system libraries linked", not outside, str(outside))
    elif system == "Linux":
        output = subprocess.run(["ldd", binary_path], capture_output=True, text=True).stdout
        bad = [token for token in ("libimobiledevice", "libplist", "libzip", "libcrypto",
                                   "libssl", "libusbmuxd", "libimobiledevice-glue", "libzstd",
                                   "libbz2", "liblzma", "libz.so")
               if token in output]
        check("no third-party shared libraries", not bad, "found: %s" % bad)
    else:
        output = subprocess.run(["ldd", binary_path],
                                capture_output=True, text=True).stdout
        if not output.strip():
            objdump = subprocess.run(["objdump", "-p", binary_path],
                                     capture_output=True, text=True).stdout
            output = objdump
        check("no toolchain DLLs from ucrt64/mingw64/clang64",
              "/ucrt64/" not in output and "/mingw64/" not in output and "/clang64/" not in output)
        check("ldd actually inspected the binary", bool(output.strip()),
              "ldd and objdump both returned nothing")
        dll_lines = [line.split()[-1] for line in output.splitlines()
                     if line.strip().startswith("DLL Name:")
                     or "Name:" in line and ".dll" in line.lower()]
        print("  note  linked DLLs: %s" % dll_lines)

    if not HAVE_FIXTURES:
        print("\n  note  tests/assets fixtures (ipa and certs) are missing, skipping"
              " certificate and real-IPA signing checks.")

    # -----------------------------------------------------------------------
    section("Stage 3: CLI & help/version workflows")
    version_output = run(["--version"]).stdout.strip()
    check("-v prints version", run(["-v"]).stdout.strip() == version_output
          and version_output.startswith("zerosign "))
    check("--version exits 0", run(["--version"]).returncode == 0)
    check("--version matches 'zerosign <version>'", version_output.split(" ")[0] == "zerosign"
          and len(version_output.split(" ")) == 2)

    for flag in ("-h", "--help", "help"):
        result = run([flag])
        check("%s prints usage to stdout, exit 0" % flag,
              result.returncode == 0 and "Usage:" in result.stdout and "zerosign" in result.stdout)
    for args in ([], ["unknown-cmd"]):
        result = run(args)
        check("no arguments / unknown command fail on stderr, non-zero exit"
              if not args else "unknown command fails on stderr, non-zero exit",
              result.returncode != 0 and "Usage:" in result.stderr)

    with tempfile.TemporaryDirectory() as workdir:
        # ---- check on an unsigned synthetic IPA (dynamic expectations) ----
        unsigned_info = plistlib.dumps({
            "CFBundleIdentifier": "com.zerosign.test.synth",
            "CFBundleName": "SynthApp",
            "CFBundleDisplayName": "Synth Display",
            "CFBundleShortVersionString": "9.9.9",
            "CFBundleVersion": "9",
            "CFBundleExecutable": "SynthApp",
        })
        signed_runner = read_entry(TEST_IPA, find_executable(TEST_IPA)) if HAVE_FIXTURES else None
        synth_files = {
            "Payload/Synth.app/Info.plist": unsigned_info,
        }
        if signed_runner is not None:
            synth_files["Payload/Synth.app/SynthApp"] = (
                strip_code_signature(signed_runner), 0o100755)
        synth_ipa = os.path.join(workdir, "synth.ipa")
        build_ipa(synth_ipa, synth_files)
        result, fields = check_output(synth_ipa, workdir)
        check("check output format", all([
            result.returncode == 0,
            fields.get("App Name") == "Synth Display",
            fields.get("App Version") == "9.9.9",
            fields.get("Bundle Id") == "com.zerosign.test.synth",
            fields.get("Signed") == "False",
        ]), result.stdout + result.stderr)
        check("check on real unsigned fixture reports Signed : False" if HAVE_FIXTURES
              else "check on unsigned fixture skipped (no assets)",
              not HAVE_FIXTURES or fields.get("Signed") == "False")
        if HAVE_FIXTURES:
            result, fields = check_output(TEST_IPA)
            info = ipa_info_plist(TEST_IPA)
            check("check on assets/test.ipa (expectations read from its Info.plist)",
                  result.returncode == 0
                  and fields.get("Bundle Id") == info.get("CFBundleIdentifier")
                  and fields.get("App Name") == (info.get("CFBundleDisplayName")
                                                 or info.get("CFBundleName"))
                  and fields.get("Signed") == "False",
                  result.stdout)

        # ---- install argument validation ----
        result = run(["install"])
        check("install with no arguments fails cleanly",
              result.returncode != 0 and "error" in (result.stdout + result.stderr).lower())
        result = run(["install", os.path.join(workdir, "missing.ipa")])
        check("install with missing .ipa fails cleanly",
              result.returncode != 0 and "error" in (result.stdout + result.stderr).lower())

        if not HAVE_FIXTURES:
            print("\nsummary: %d passed, %d failed" % (passed, failed))
            return 1 if failed else 0

        # ---- sign with explicit flags ----
        shutil.copy(TEST_IPA, os.path.join(workdir, "app.ipa"))
        app_ipa = os.path.join(workdir, "app.ipa")
        result = run(["sign", app_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        default_output = os.path.join(workdir, "app-signed.ipa")
        check("sign with default output path",
              result.returncode == 0 and os.path.isfile(default_output)
              and "Successfully signed" in result.stdout
              and "`app.ipa` to `app-signed.ipa`!" in result.stdout.replace(
                  os.path.join(workdir, ""), ""),
              result.stdout + result.stderr)
        result, fields = check_output(default_output, workdir)
        check("signed ipa reports Signed : True",
              fields.get("Signed") == "True", result.stdout)

        for flag in ("--output", "-o"):
            target = os.path.join(workdir, "custom-%s.ipa" % flag.strip("-"))
            result = run(["sign", app_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                          "--password", "1", flag, target], cwd=workdir)
            check("sign with %s writes exact target path" % flag,
                  result.returncode == 0 and os.path.isfile(target)
                  and target in result.stdout,
                  result.stdout + result.stderr)

        result = run(["sign", app_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV],
                     stdin_text="1\n", cwd=workdir)
        check("sign prompts for the password on stdin",
              result.returncode == 0 and "Input Password : " in result.stdout
              and os.path.isfile(os.path.join(workdir, "app-signed.ipa")),
              result.stdout + result.stderr)

        result = run(["sign", app_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "wrong"], cwd=workdir)
        check("sign with wrong password fails",
              result.returncode != 0 and "error" in (result.stdout + result.stderr).lower(),
              result.stdout + result.stderr)
        result = run(["sign", app_ipa, "--pkey", TEST_P12], cwd=workdir)
        check("sign with --pkey only fails with pairing message",
              result.returncode != 0
              and "--pkey and --prov must be used together" in result.stdout + result.stderr,
              result.stdout + result.stderr)

        # ---- codesign cross-check on macOS ----
        if platform.system() == "Darwin":
            import stat as stat_module
            extract_dir = os.path.join(workdir, "extracted")
            with zipfile.ZipFile(default_output) as archive:
                archive.extractall(extract_dir)
            bundle = os.path.join(extract_dir, app_dir(default_output))
            for root, _dirs, files in os.walk(bundle):
                for name in files:
                    path = os.path.join(root, name)
                    mode = os.stat(path).st_mode
                    os.chmod(path, mode | stat_module.S_IRUSR | stat_module.S_IWUSR
                             if mode & stat_module.S_IXUSR else mode)
            codesign = subprocess.run(["codesign", "-vvv", bundle],
                                      capture_output=True, text=True)
            check("macOS codesign validates the signed bundle",
                  codesign.returncode == 0
                  and "valid on disk" in codesign.stderr
                  and "Designated Requirement" in codesign.stderr,
                  codesign.stderr)

        # ---- saved certificate management (isolated HOME) ----
        section("Stage 3: saved certificate management")
        home = os.path.join(workdir, "fake-home")
        os.makedirs(home)
        env = make_env(home)
        zerosign_dir = os.path.join(home, ".zerosign")

        result = run(["sign", app_ipa], cwd=workdir, env=env)
        check("sign before any saved certificate fails",
              result.returncode != 0
              and "zerosign cert" in result.stdout + result.stderr,
              result.stdout + result.stderr)

        stdin = "%s\n%s\n1\ntest\n" % (TEST_P12, TEST_PROV)
        result = run(["cert"], stdin_text=stdin, env=env)
        check("cert interactive flow succeeds",
              result.returncode == 0 and "Success! Saved to ~/.zerosign/" in result.stdout,
              result.stdout + result.stderr)
        check("saved certificate files created",
              os.path.isfile(os.path.join(zerosign_dir, "zerosign.json"))
              and os.path.isfile(os.path.join(zerosign_dir, "test.p12"))
              and os.path.isfile(os.path.join(zerosign_dir, "test.mobileprovision")))
        saved = json.load(open(os.path.join(zerosign_dir, "zerosign.json")))
        check("zerosign.json is valid JSON with name test",
              saved.get("certificate", {}).get("name") == "test")

        result = run(["sign", app_ipa], cwd=workdir, env=env)
        saved_output = os.path.join(workdir, "app-signed.ipa")
        check("flagless sign uses the saved certificate",
              result.returncode == 0
              and 'Signing using "test" certificate...' in result.stdout
              and "Successfully signed" in result.stdout,
              result.stdout + result.stderr)
        result, fields = check_output(saved_output, workdir)
        check("flagless-signed ipa reports Signed : True", fields.get("Signed") == "True")

        before = os.path.getmtime(os.path.join(zerosign_dir, "test.p12"))
        result = run(["cert"], stdin_text="n\n", env=env)
        check("cert replacement declined keeps the certificate",
              result.returncode == 0
              and 'do you want to replace it? (y/n)' in result.stdout
              and not any(name.endswith(".p12") and name != "test.p12"
                          for name in os.listdir(zerosign_dir))
              and os.path.getmtime(os.path.join(zerosign_dir, "test.p12")) == before,
              result.stdout + result.stderr)

        stdin = "y\n%s\n%s\n1\n\n" % (TEST_P12, TEST_PROV)
        result = run(["cert"], stdin_text=stdin, env=env)
        saved = json.load(open(os.path.join(zerosign_dir, "zerosign.json")))
        random_name = saved.get("certificate", {}).get("name")
        check("cert replacement with blank name uses a random identifier",
              result.returncode == 0 and random_name is not None and random_name != "test"
              and os.path.isfile(os.path.join(zerosign_dir, random_name + ".p12"))
              and os.path.isfile(os.path.join(zerosign_dir, random_name + ".mobileprovision")),
              result.stdout + result.stderr)
        check("old test certificate files cleaned up",
              not os.path.exists(os.path.join(zerosign_dir, "test.p12"))
              and not os.path.exists(os.path.join(zerosign_dir, "test.mobileprovision")))
        result = run(["sign", app_ipa], cwd=workdir, env=env)
        check("flagless sign works after replacement",
              result.returncode == 0
              and 'Signing using "%s" certificate...' % random_name in result.stdout,
              result.stdout + result.stderr)

        # -------------------------------------------------------------------
        section("Stage 4: bundle sealing, security & regression")
        signed_ipa = default_output
        bundle = app_dir(signed_ipa)
        check("embedded.mobileprovision written inside Payload/*.app",
              read_entry(signed_ipa, bundle + "/embedded.mobileprovision")
              == open(TEST_PROV, "rb").read())

        runner = read_entry(signed_ipa, bundle + "/" +
                            ipa_info_plist(signed_ipa)["CFBundleExecutable"])
        slots = macho_superblob_slots(runner)
        check("main executable carries entitlements slots 5 and 7",
              slots is not None and 5 in slots and 7 in slots, str(slots))

        with zipfile.ZipFile(signed_ipa) as archive:
            framework_binaries = []
            for name in archive.namelist():
                if ".framework/" not in name or name.endswith("/"):
                    continue
                # top-level file directly inside Frameworks/*.framework/
                parts = name.split("/")
                if (len(parts) == 3 and parts[0] == "Payload" and
                        parts[1].endswith(".app") and parts[2].endswith(".framework")):
                    continue
                if len(parts) == 5 and parts[0] == "Payload" and parts[1].endswith(".app") \
                        and parts[2] == "Frameworks" and parts[3].endswith(".framework") \
                        and parts[4] == parts[3][:-len(".framework")]:
                    framework_binaries.append(name)
        nested_ok = True
        nested_detail = []
        for name in framework_binaries:
            data = read_entry(signed_ipa, name)
            slots = macho_superblob_slots(data)
            if slots is not None and (5 in slots or 7 in slots):
                nested_ok = False
                nested_detail.append(name)
        check("nested framework binaries carry no entitlements slots",
              nested_ok and len(framework_binaries) > 0, str(nested_detail))

        code_resources = read_entry(signed_ipa, bundle + "/_CodeSignature/CodeResources")
        seal = plistlib.loads(code_resources)
        files2 = seal.get("files2", {})
        excluded = [name for name in files2
                    if name.endswith(".lproj/locversion.plist")
                    or name == "Info.plist" or name == "PkgInfo" or name == ".DS_Store"]
        check("CodeResources files2 omits locversion/Info.plist/PkgInfo/.DS_Store",
              not excluded, str(excluded))

        check("main executable mode is 0755 in the output archive",
              (entry_mode(signed_ipa, bundle + "/" +
                          ipa_info_plist(signed_ipa)["CFBundleExecutable"]) & 0o777) == 0o755)

        # ---- symlink sealing (synthetic) ----
        runner_stripped = strip_code_signature(
            read_entry(TEST_IPA, find_executable(TEST_IPA)))
        synth_files = {
            "Payload/Synth.app/Info.plist": unsigned_info,
            "Payload/Synth.app/SynthApp": (runner_stripped, 0o100755),
            "Payload/Synth.app/Resources": (b"en.lproj", 0o120777),
        }
        link_ipa = os.path.join(workdir, "links.ipa")
        build_ipa(link_ipa, synth_files)
        result = run(["sign", link_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        check("signing a bundle with a symlink succeeds",
              result.returncode == 0, result.stdout + result.stderr)
        if result.returncode == 0:
            link_output = os.path.join(workdir, "links-signed.ipa")
            target = zip_symlink(link_output, "Payload/Synth.app/Resources")
            check("symlink preserved and recorded in the output archive",
                  target == "en.lproj", repr(target))
            seal = plistlib.loads(
                read_entry(link_output, "Payload/Synth.app/_CodeSignature/CodeResources"))
            entry = seal.get("files2", {}).get("Resources")
            check("symlink sealed as a 'symlink' entry in CodeResources",
                  isinstance(entry, dict) and entry.get("symlink") == "en.lproj", str(entry))

        # ---- setuid stripping (synthetic) ----
        synth_files = {
            "Payload/Synth.app/Info.plist": unsigned_info,
            "Payload/Synth.app/SynthApp": (runner_stripped, 0o100755),
            "Payload/Synth.app/helper.bin": (b"not mach-o", 0o104755),
        }
        setuid_ipa = os.path.join(workdir, "setuid.ipa")
        build_ipa(setuid_ipa, synth_files)
        result = run(["sign", setuid_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        setuid_output = os.path.join(workdir, "setuid-signed.ipa")
        mode = entry_mode(setuid_output, "Payload/Synth.app/helper.bin")
        check("setuid bit stripped from bundle files",
              result.returncode == 0 and (mode & 0o4000) == 0 and (mode & 0o111) != 0,
              oct(mode))
        mode = entry_mode(setuid_output, "Payload/Synth.app/SynthApp")
        check("Mach-O binary executable mode enforced (0755)",
              (mode & 0o777) == 0o755, oct(mode))

        # ---- stripped LC_CODE_SIGNATURE re-injection ----
        result = run(["sign", synth_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        stripped_output = os.path.join(workdir, "synth-signed.ipa")
        if result.returncode == 0:
            output_runner = read_entry(stripped_output, "Payload/Synth.app/SynthApp")
            check("fresh LC_CODE_SIGNATURE injected into a stripped binary",
                  macho_signature_command(output_runner) is not None)
            result, fields = check_output(stripped_output, workdir)
            check("re-signed stripped binary reports Signed : True",
                  fields.get("Signed") == "True", result.stdout)
        else:
            check("signing a stripped binary succeeds", False,
                  result.stdout + result.stderr)

        # ---- tamper detection ----
        tampered = bytearray(read_entry(signed_ipa, bundle + "/" +
                                        ipa_info_plist(signed_ipa)["CFBundleExecutable"]))
        tampered[len(tampered) // 2] ^= 0xFF
        with zipfile.ZipFile(signed_ipa) as archive:
            names = archive.namelist()
            entries = {name: archive.read(name) for name in names}
        entries[bundle + "/" + ipa_info_plist(signed_ipa)["CFBundleExecutable"]] = bytes(tampered)
        tampered_ipa = os.path.join(workdir, "tampered.ipa")
        build_ipa(tampered_ipa, entries)
        result, fields = check_output(tampered_ipa, workdir)
        check("tampered binary flips Signed to False", fields.get("Signed") == "False",
              result.stdout)

        resource_tampered = dict(entries)
        resource_name = bundle + "/AppIcon60x60@2x.png"
        if resource_name in resource_tampered:
            resource_tampered[resource_name] = b"tampered" + resource_tampered[resource_name]
            resource_ipa = os.path.join(workdir, "resource-tampered.ipa")
            build_ipa(resource_ipa, resource_tampered)
            result, fields = check_output(resource_ipa, workdir)
            check("tampered sealed resource flips Signed to False",
                  fields.get("Signed") == "False", result.stdout)

        # ---- hostile input: malformed Mach-O headers ----
        runner_bytes = read_entry(TEST_IPA, find_executable(TEST_IPA))
        runner_signed = read_entry(signed_ipa, bundle + "/" +
                                   ipa_info_plist(signed_ipa)["CFBundleExecutable"])
        malformed_cases = {
            "truncated segment": runner_bytes[: len(runner_bytes) // 3],
            "cmdsize 8 with LC_CODE_SIGNATURE": patch_cmdsize8(runner_signed),
            "truncated __LINKEDIT": truncate_linkedit(runner_signed),
        }
        for label, contents in malformed_cases.items():
            synth_files = {
                "Payload/Synth.app/Info.plist": unsigned_info,
                "Payload/Synth.app/SynthApp": (contents, 0o100755),
            }
            malformed_ipa = os.path.join(workdir, "malformed.ipa")
            build_ipa(malformed_ipa, synth_files)
            result, fields = check_output(malformed_ipa, workdir)
            check("check survives %s and reports Signed : False" % label,
                  result.returncode == 0 and fields.get("Signed") == "False",
                  result.stdout + result.stderr)

        # ---- hostile input: corrupt LC_CODE_SIGNATURE offsets must not be signed ----
        for label, corrupt in {
            "dataoff = 0": corrupt_dataoff(runner_signed, 0),
            "dataoff past EOF": corrupt_dataoff(runner_signed, len(runner_signed) + 4096),
        }.items():
            synth_files = {
                "Payload/Synth.app/Info.plist": unsigned_info,
                "Payload/Synth.app/SynthApp": (corrupt, 0o100755),
            }
            corrupt_ipa = os.path.join(workdir, "corrupt.ipa")
            build_ipa(corrupt_ipa, synth_files)
            result = run(["sign", corrupt_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                          "--password", "1"], cwd=workdir)
            check("sign rejects %s" % label,
                  result.returncode != 0
                  and "error" in (result.stdout + result.stderr).lower(),
                  result.stdout + result.stderr)

        # ---- hostile input: CFBundleExecutable validation ----
        for executable, label in [("../../victim", "path traversal"),
                                  ("sub/dir/victim", "subdirectory path")]:
            hostile_info = dict(plistlib.loads(unsigned_info))
            hostile_info["CFBundleExecutable"] = executable
            synth_files = {
                "Payload/Synth.app/Info.plist": plistlib.dumps(hostile_info),
                "Payload/Synth.app/SynthApp": (runner_stripped, 0o100755),
            }
            hostile_ipa = os.path.join(workdir, "hostile.ipa")
            build_ipa(hostile_ipa, synth_files)
            result = run(["sign", hostile_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                          "--password", "1"], cwd=workdir)
            check("sign refuses CFBundleExecutable with %s" % label,
                  result.returncode != 0
                  and "unsafe CFBundleExecutable" in result.stdout + result.stderr,
                  result.stdout + result.stderr)

        missing_exec_info = dict(plistlib.loads(unsigned_info))
        del missing_exec_info["CFBundleExecutable"]
        synth_files = {
            "Payload/Synth.app/Info.plist": plistlib.dumps(missing_exec_info),
            "Payload/Synth.app/SynthApp": (runner_stripped, 0o100755),
        }
        hostile_ipa = os.path.join(workdir, "noexec.ipa")
        build_ipa(hostile_ipa, synth_files)
        result = run(["sign", hostile_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        check("sign refuses a bundle missing CFBundleExecutable",
              result.returncode != 0
              and "no CFBundleExecutable" in result.stdout + result.stderr,
              result.stdout + result.stderr)

        # ---- hostile input: zip-slip symlink escape ----
        slip_files = {
            "Payload/Synth.app/Info.plist": unsigned_info,
            "Payload/Synth.app/SynthApp": (runner_stripped, 0o100755),
            "Payload/Synth.app/escape": (b"../pwned", 0o121777),
            "Payload/Synth.app/escape/evil.txt": b"zip-slip payload",
        }
        slip_ipa = os.path.join(workdir, "slip.ipa")
        build_ipa(slip_ipa, slip_files)
        result = run(["sign", slip_ipa, "--pkey", TEST_P12, "--prov", TEST_PROV,
                      "--password", "1"], cwd=workdir)
        combined = result.stdout + result.stderr
        check("sign refuses symlink zip-slip escapes",
              result.returncode != 0
              and ("outside the staging directory" in combined
                   or ("escape" in combined and "error" in combined.lower())),
              combined)
        check("zip-slip payload never written outside staging",
              not os.path.exists(os.path.join(ROOT, "pwned"))
              and not os.path.exists(os.path.join(workdir, "pwned")))

    print("\nsummary: %d passed, %d failed" % (passed, failed))
    if failures:
        print("failed checks:")
        for name in failures:
            print("  - %s" % name)
    return 1 if failed else 0


def patch_cmdsize8(data):
    """Rewrites the first LC_CODE_SIGNATURE cmdsize to 8 so parsing fails."""
    out = bytearray(data)
    if struct.unpack_from("<I", out, 0)[0] != MH_MAGIC_64:
        return bytes(out)
    ncmds = struct.unpack_from("<I", out, 16)[0]
    cursor = 32
    for _ in range(ncmds):
        if cursor + 8 > len(out):
            break
        cmd, _cmdsize = struct.unpack_from("<II", out, cursor)
        if cmd == LC_CODE_SIGNATURE:
            struct.pack_into("<I", out, cursor + 4, 8)
            return bytes(out)
        cmdsize = struct.unpack_from("<I", out, cursor + 4)[0]
        cursor += cmdsize
    return bytes(out)


def truncate_linkedit(data):
    """Truncates the file right past the end of the load commands, so the
    declared __LINKEDIT contents are gone."""
    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        return data
    ncmds = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    commands_end = 32
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            break
        cmdsize = struct.unpack_from("<I", data, cursor + 4)[0]
        if cmdsize < 8:
            break
        cursor += cmdsize
        commands_end = cursor
    return data[:min(commands_end + 64, len(data))]


def corrupt_dataoff(data, new_offset):
    """Rewrites LC_CODE_SIGNATURE dataoff to a corrupt value."""
    out = bytearray(data)
    if struct.unpack_from("<I", out, 0)[0] != MH_MAGIC_64:
        return bytes(out)
    ncmds = struct.unpack_from("<I", out, 16)[0]
    cursor = 32
    for _ in range(ncmds):
        if cursor + 8 > len(out):
            break
        cmd, _cmdsize = struct.unpack_from("<II", out, cursor)
        if cmd == LC_CODE_SIGNATURE:
            struct.pack_into("<I", out, cursor + 8, new_offset)
            return bytes(out)
        cmdsize = struct.unpack_from("<I", out, cursor + 4)[0]
        cursor += cmdsize
    return bytes(out)


if __name__ == "__main__":
    sys.exit(run_main())
