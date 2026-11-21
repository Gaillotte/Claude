#!/usr/bin/env python3
"""Fixtures for the native-executable sweep (transit/scanners/native.py), built at run time.

    make_native_fixtures.py DIR

writes two trees under DIR and nothing else:

    DIR/hit/...    every file holds an executable, hidden in one way or another: the sweep must report each
    DIR/clean/...  near-misses of every rule: the sweep must report none of them

The payloads are the smallest headers a loader accepts, not programs. They are assembled here and never committed,
for the reason the credential tests assemble their tokens: a repository that holds a contiguous ELF or PE (or the
base64 of one) is flagged by its own scanner. `DIR/expect.tsv` lists, for every file under hit/, the kind and the
encoding the finding must name:  <path relative to DIR/hit> TAB <message fragment>.
"""
import base64
import gzip
import io
import os
import struct
import sys
import zipfile
import zlib


# ── payloads ─────────────────────────────────────────────────────────────────────────────────────────────────────
def elf(machine=62, etype=2, big=False, cls=2, ident_junk=False):
    e = ">" if big else "<"
    ident = b"\x7fELF" + bytes([cls, 2 if big else 1, 1]) + b"\x00" * 9
    if ident_junk:                                   # the kernel ignores class, data, version, OS ABI and padding
        ident = b"\x7fELF" + b"\x00\xff\x99\x55" + b"\xff" * 8
    return ident + struct.pack(e + "HHIQQQIHHHHHH", etype, machine, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0) + b"\x00" * 96


def pe(machine=0x8664, dll=False, lfanew=0x80, stub=b""):
    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", lfanew))
    body = dos + b"\x00" * (lfanew - len(dos))
    if stub:
        body[0x40:0x40 + len(stub)] = stub
    nt = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0xF0, 0x2022 if dll else 0x0022)
    return bytes(body) + nt + b"\x00" * 0x120


def macho(cpu=0x01000007, ftype=2, big=False):
    e = ">" if big else "<"
    magic = b"\xfe\xed\xfa\xcf" if big else b"\xcf\xfa\xed\xfe"
    return magic + struct.pack(e + "IIIIIII", cpu, 3, ftype, 1, 8, 0x200085, 0) + b"\x00" * 8 + b"\x00" * 64


def fat():
    thin = macho()
    head = b"\xca\xfe\xba\xbe" + struct.pack(">II", 1, 0x01000007) + struct.pack(">IIII", 3, 0x1000, len(thin), 12)
    return head + b"\x00" * (0x1000 - len(head)) + thin


def java_class():                                    # CAFEBABE, then minor 0 and major 52: not a fat header
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 120


def mask_xor(b, k):
    return bytes(x ^ k for x in b)


def mask_add(b, k):
    return bytes((x + k) & 255 for x in b)


# ── encoders ─────────────────────────────────────────────────────────────────────────────────────────────────────
def wrap(s, n):
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


def hexarr(b, cols=12, fmt="0x%02x"):
    return ",\n  ".join(", ".join(fmt % x for x in b[i:i + cols]) for i in range(0, len(b), cols))


def gz(b):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as f:
        f.write(b)
    return out.getvalue()


def zipped(b):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner/readme.txt", "hello\n")
        z.writestr("inner/tool", b)
    return out.getvalue()


def build(root):
    hit = {}
    expect = {}

    def put(path, data, frag):
        hit[path] = data if isinstance(data, bytes) else data.encode()
        expect[path] = frag

    P = elf()
    PL = P + bytes((i * 37 + 11) & 255 for i in range(400))      # a payload that does not compress to nothing
    # 1. a native file under a name that says something else, at the top and under every directory the scan prunes
    for name in ("notes.txt", "data.json", "logo.png", "blob.dat", "README", "main.py", "style.css", "doc.md",
                 "plugin.node", "module.pyd", "a.o", "libz.so.1", "run.sh", "page.html"):
        put("renamed/" + name, P, "hidden_native_executable:ELF_x86_64_exec:offset_0")
    for d in ("node_modules/pkg", "vendor", "build", "dist", "target", ".venv/bin", "coverage", "__pycache__", ".tox"):
        put(d + "/helper", P, "hidden_native_executable:ELF_x86_64_exec:offset_0")
    # 2. every platform and kind
    put("kinds/elf_x86.dat", elf(3, 3), "ELF_x86_shared:offset_0")
    put("kinds/elf_arm.dat", elf(40, 2), "ELF_arm_exec:offset_0")
    put("kinds/elf_aarch64.dat", elf(183, 3), "ELF_aarch64_shared:offset_0")
    put("kinds/elf_riscv.dat", elf(243, 2), "ELF_riscv_exec:offset_0")
    put("kinds/elf_mips_be.dat", elf(8, 2, big=True), "ELF_mips_exec:offset_0")
    put("kinds/elf_ppc64_be.dat", elf(21, 2, big=True), "ELF_ppc64_exec:offset_0")
    put("kinds/elf_s390.dat", elf(22, 2, big=True), "ELF_s390_exec:offset_0")
    put("kinds/kernel_module.dat", elf(62, 1), "ELF_x86_64_object:offset_0")
    put("kinds/ebpf_object.dat", elf(247, 1), "ELF_bpf_object:offset_0")
    put("kinds/elf_garbage_ident.dat", elf(ident_junk=True), "ELF_x86_64_exec:offset_0")
    put("kinds/pe_x64.dat", pe(), "PE_x86_64_exe:offset_0")
    put("kinds/pe_dll.dat", pe(dll=True), "PE_x86_64_dll:offset_0")
    put("kinds/pe_x86.dat", pe(0x14c), "PE_x86_exe:offset_0")
    put("kinds/pe_arm64.dat", pe(0xaa64), "PE_arm64_exe:offset_0")
    put("kinds/pe_machine0.dat", pe(0), "PE_other_exe:offset_0")
    put("kinds/pe_far_lfanew.dat", pe(lfanew=0x6000), "PE_x86_64_exe:offset_0")                  # a pointer past any 4 KB head
    put("kinds/pe_huge_lfanew.dat", pe(lfanew=0x100000), "PE_x86_64_exe:offset_0")
    put("kinds/macho_x64.dat", macho(), "MachO_x86_64_exec:offset_0")
    put("kinds/macho_arm64_dylib.dat", macho(0x0100000c, 6), "MachO_arm64_dylib:offset_0")
    put("kinds/macho_x86_be.dat", macho(18, 2, big=True), "MachO_ppc_exec:offset_0")
    put("kinds/macho_fat.dat", fat(), "MachO_fat:offset_0")
    # 3. hidden inside: appended, prepended, behind another format
    put("inside/appended_to_text.txt", b"just some notes\n" * 30 + P, "hidden_native_executable:ELF_x86_64_exec:offset_480")
    put("inside/appended_to_py.py", b"print('hi')\n" + P, "hidden_native_executable:ELF_x86_64_exec:offset_12")
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 21 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    put("inside/appended_to_png.png", png + P, "hidden_native_executable:ELF_x86_64_exec:offset_%d" % len(png))
    put("inside/prepended_junk.bin.txt", bytes(range(256)) * 4 + P, "hidden_native_executable:ELF_x86_64_exec:offset_1024")
    put("inside/launcher.sh", b"#!/bin/sh\nexec tail -c +60 \"$0\" > /tmp/x\n" + P, "ELF_x86_64_exec")
    put("inside/pe_in_text.txt", b"x" * 100 + pe(), "hidden_native_executable:PE_x86_64_exe:offset_100")
    put("inside/macho_in_json.json", b'{"a": 1}\n' + macho(0x0100000c), "hidden_native_executable:MachO_arm64_exec:offset_9")
    put("inside/fat_in_text.txt", b"# fat\n" + fat(), "hidden_native_executable:MachO_fat:offset_6")
    put("inside/big_dos_stub.dat", b"Q" * 64 + pe(lfanew=0x5000), "PE_x86_64_exe:offset_64")
    put("inside/two_natives.dat", b"z" * 10 + P + pe(), "ELF_x86_64_exec:offset_10")
    # 4. base64
    b64 = base64.b64encode(P).decode()
    pb64 = base64.b64encode(pe()).decode()
    put("encoded/b64_line.txt", "payload = '" + b64 + "'\n", "encoded_native_executable:ELF_x86_64_exec:base64")
    put("encoded/b64_wrapped76.txt", wrap(b64, 76) + "\n", "ELF_x86_64_exec:base64")
    put("encoded/b64_wrapped64_crlf.pem.txt", wrap(pb64, 64).replace("\n", "\r\n"), "PE_x86_64_exe:base64")
    put("encoded/b64_datauri.html", "<img src=\"data:application/octet-stream;base64," + b64 + "\">", "ELF_x86_64_exec:base64")
    put("encoded/b64_json.json", '{"name": "x", "blob": "' + pb64 + '"}', "PE_x86_64_exe:base64")
    put("encoded/b64_pe_noquote.txt", "blob:" + pb64 + "\n", "PE_x86_64_exe:base64")
    for k in (1, 2, 3):                                              # letters glued before the payload shift its alignment
        put("encoded/b64_glued_%d.txt" % k, "x" * k + b64, "ELF_x86_64_exec:base64")
    put("encoded/b64_prefix_junk.txt", base64.b64encode(bytes(range(256)) * 2 + P).decode(), "ELF_x86_64_exec:base64")
    put("encoded/b64_macho.txt", base64.b64encode(macho()).decode(), "MachO_x86_64_exec:base64")
    put("encoded/b64_fat.txt", base64.b64encode(fat()).decode(), "MachO_fat:base64")
    put("encoded/b64_gzip.txt", base64.b64encode(gz(PL)).decode(), "ELF_x86_64_exec:base64_compressed")
    put("encoded/b64_zlib.txt", base64.b64encode(zlib.compress(PL)).decode(), "ELF_x86_64_exec:base64_compressed")
    put("encoded/b64_zip.txt", base64.b64encode(zipped(PL)).decode(), "ELF_x86_64_exec:base64_compressed")
    put("encoded/b64_after_prose.md", "# Notes\n\nnothing to see.\n\n" + b64 + "\n", "ELF_x86_64_exec:base64")
    # 5. hex, byte arrays, escapes
    h = P.hex()
    put("encoded/hex_lower.txt", h, "encoded_native_executable:ELF_x86_64_exec:hex")
    put("encoded/hex_upper_wrapped.txt", wrap(h.upper(), 60), "ELF_x86_64_exec:hex")
    put("encoded/hex_glued_q.txt", "q" + h, "ELF_x86_64_exec:hex")                       # letters glued before it
    put("encoded/hex_glued_odd.txt", "xya" + h, "ELF_x86_64_exec:hex")                    # …and a stray hex digit that shifts every byte
    put("encoded/hex_gzip.txt", gz(PL).hex(), "ELF_x86_64_exec:hex_compressed")
    put("encoded/c_array.h", "unsigned char payload[] = {\n  " + hexarr(P) + "\n};\n", "ELF_x86_64_exec:hex_array")
    put("encoded/c_array_pe.c", "static const unsigned char blob[] = {\n  " + hexarr(pe()) + "\n};\n", "PE_x86_64_exe:hex_array")
    put("encoded/powershell_bytes.ps1.txt", "[Byte[]] $b = " + ", ".join("0x%02X" % x for x in pe()) + "\n", "PE_x86_64_exe:hex_array")
    put("encoded/go_slice.go", "var payload = []byte{" + ", ".join("0x%02x" % x for x in macho()) + "}\n", "MachO_x86_64_exec:hex_array")
    put("encoded/escaped_hex.py", "payload = b'" + "".join("\\x%02x" % x for x in P) + "'\n", "ELF_x86_64_exec:escaped_hex")
    put("encoded/escaped_octal.c", "const char *p = \"" + "".join("\\%03o" % x for x in P) + "\";\n", "ELF_x86_64_exec:escaped_octal")
    put("encoded/spaced_hex.txt", " ".join("%02x" % x for x in P) + "\n", "ELF_x86_64_exec:spaced_hex")
    put("encoded/spaced_hex_pe.txt", " ".join("%02X" % x for x in pe()) + "\n", "PE_x86_64_exe:spaced_hex")
    put("encoded/decimal_list.py", "payload = bytes([" + ", ".join(str(x) for x in P) + "])\n", "ELF_x86_64_exec:decimal_array")
    put("encoded/decimal_pe.py", "blob = [" + ",".join(str(x) for x in pe()) + "]\n", "PE_x86_64_exe:decimal_array")
    # 6. masked head
    put("encoded/xor_55.dat", mask_xor(P, 0x55), "encoded_native_executable:ELF_x86_64_exec:masked_bytes")
    put("encoded/xor_a7_pe.dat", mask_xor(pe(), 0xA7), "PE_x86_64_exe:masked_bytes")
    put("encoded/add_13.dat", mask_add(P, 13), "ELF_x86_64_exec:masked_bytes")
    put("encoded/xor_macho.dat", mask_xor(macho(), 0x3C), "MachO_x86_64_exec:masked_bytes")

    clean = {}
    text = b"The ELF format and the MZ header are documented in elf.h and pe.go.\n" * 40
    clean["docs/mentions.md"] = text
    clean["docs/elf_h_excerpt.h"] = (b"#define EI_MAG0 0\n#define ELFMAG0 0x7f\n#define ELFMAG1 'E'\n#define ELFMAG2 'L'\n#define ELFMAG3 'F'\n"
                                     b"#define IMAGE_DOS_SIGNATURE 0x5A4D  /* MZ */\n#define MH_MAGIC_64 0xfeedfacf\n") * 5
    clean["docs/magic_table.txt"] = b"0 string \\x7fELF ELF\n0 string MZ MS-DOS executable\n0 belong 0xfeedfacf Mach-O 64-bit\n" * 10
    clean["data/random.bin.txt"] = bytes((i * 131 + 7) & 255 for i in range(5000))
    clean["data/png_only.png"] = png
    clean["data/b64_of_text.txt"] = base64.b64encode(b"A long sentence that is only text. " * 20).decode().encode()
    clean["data/b64_of_png.txt"] = base64.b64encode(png + bytes((i * 7) & 255 for i in range(300))).decode().encode()
    clean["data/b64_random.txt"] = base64.b64encode(bytes((i * 37 + 11) & 255 for i in range(600))).decode().encode()
    clean["data/hex_of_text.txt"] = b"hello world, this is plain text. ".hex().encode() * 4
    clean["data/c_array_ascii.h"] = ("unsigned char s[] = {\n  " + hexarr(b"just ascii bytes in an array, nothing to run, really") + "\n};\n").encode()
    clean["data/numbers.json"] = ("[" + ", ".join(str(i) for i in range(1, 200)) + "]").encode()
    clean["data/decimal_ascii.py"] = ("s = bytes([" + ", ".join(str(x) for x in b"plain ascii text in decimal form, harmless") + "])\n").encode()
    clean["data/spaced_hex_text.txt"] = " ".join("%02x" % x for x in b"This is just text written as spaced hex.").encode()
    clean["data/escaped_text.py"] = ("s = b'" + "".join("\\x%02x" % x for x in b"escaped but harmless text, nothing else") + "'\n").encode()
    clean["data/octal_text.c"] = ("char *s = \"" + "".join("\\%03o" % x for x in b"octal escapes of plain text here") + "\";\n").encode()
    clean["data/mz_zeros.txt"] = b"MZ" + b"\x00" * 200
    clean["data/mz_text.txt"] = b"MZ is the signature; the offset at 0x3c points at PE and a PE header follows. " * 10
    clean["data/elf_magic_alone.dat"] = b"\x7fELF" + b"\xff" * 60                              # a magic with no valid type or machine
    clean["data/elf_bad_type.dat"] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x09\x00\x3e\x00" + b"\x00" * 60
    clean["data/elf_machine0.dat"] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x00\x00" + b"\x00" * 60
    clean["data/pe_pointer_to_nothing.dat"] = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 300
    clean["data/pe_pointer_past_end.dat"] = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x7fffff00) + b"\x00" * 300
    clean["data/macho_bad_header.dat"] = b"\xcf\xfa\xed\xfe" + b"\xff" * 60
    clean["data/fat_bad_slice.dat"] = b"\xca\xfe\xba\xbe" + struct.pack(">II", 1, 0x01000007) + struct.pack(">IIII", 3, 0x40, 10, 12) + b"\x00" * 100
    clean["data/java_class.dat"] = java_class()
    clean["data/wasm.dat"] = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 60
    clean["data/pyc.dat"] = b"\xa7\x0d\x0d\x0a" + b"\x00" * 60
    clean["data/tiny.txt"] = b"MZ"
    clean["data/empty.txt"] = b""
    clean["src/many_mz.txt"] = b"MZ" * 4000                                                      # a candidate every two bytes
    # a file with an owned extension keeps its own scanner's verdict: the sweep does not read it
    clean["owned/lib.so"] = P
    clean["owned/tool.exe"] = pe()
    clean["owned/app.jar"] = b"PK\x03\x04" + P
    clean["owned/doc.pdf"] = b"%PDF-1.4\n" + P

    for tree, files in (("hit", hit), ("clean", clean)):
        for rel, data in files.items():
            path = os.path.join(root, tree, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data if isinstance(data, bytes) else data.encode())
    with open(os.path.join(root, "expect.tsv"), "w") as fh:
        for rel in sorted(expect):
            fh.write("%s\t%s\n" % (rel, expect[rel]))
    return hit, clean


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        sys.exit(2)
    build(sys.argv[1])
