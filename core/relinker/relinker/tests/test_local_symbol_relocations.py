from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_guest_intel_trampolines import pe_sections
from test_linux_dynamic_strings import dynamic_strings, file_offset
from test_linux_load_alignment import loads
from test_macos_output import MachO

DT_RELA = 7
DT_RELASZ = 8
DT_STRTAB = 5
DT_OS_SYMTAB = 0x61000039
DT_OS_SYMTABSZ = 0x6100003F

LOCAL_SLOT = 0x300
ABSOLUTE_SLOT = 0x308
LOCAL_VALUE = 0x800
ABSOLUTE_ADDEND = 0x40
GLOB_DAT_ADDEND = 0x1234
DEFAULT_BASE = 0x400000
NOTE = "Defined symbol references that are local, hidden or internal resolved as RELATIVE relocations: 2"
THROW = "Relocation names a defined symbol that is local, hidden or internal: local"
TARGETS = (("linux", [], b"\x7fELF"), ("windows", ["--windows"], b"MZ"), ("macos", ["--macos"], b"\xcf\xfa\xed\xfe"))


def fixture(local_info=0x01, local_other=0, local_section=1, jump_slot=False):
    image = bytearray(0x1200)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, 0x1000, 64, 0, 0, 64, 56, 8, 64, 0, 0)
    tags = [(1, 1), (DT_STRTAB, 0x600), (10, 16), (DT_OS_SYMTAB, 0x620), (11, 24), (DT_OS_SYMTABSZ, 48),
            (DT_RELA, 0x700), (DT_RELASZ, 48 if not jump_slot else 24), (9, 24), (0x61000027, 0x300), (0, 0)]
    if jump_slot:
        tags = tags[:-1] + [(23, 0x790), (2, 24), (20, 7), (0, 0)]
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 6, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 5, 0x1000, 0x1000, 0x1000, 0x200, 0x200, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 176, 2, 6, 0x400, 0x400, 0x400, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<IIQQQQQQ", image, 232, 0x61000000, 0, 0, 0, 0, 0x1000, 0x1000, 1)
    for index in range(4, 8):
        struct.pack_into("<I", image, 64 + index * 56, 0x6fffff01)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQq", image, 0x700, LOCAL_SLOT, (1 << 32) | 6, GLOB_DAT_ADDEND)
    if not jump_slot:
        struct.pack_into("<QQq", image, 0x718, ABSOLUTE_SLOT, (1 << 32) | 1, ABSOLUTE_ADDEND)
    else:
        struct.pack_into("<QQq", image, 0x790, LOCAL_SLOT, (1 << 32) | 7, 0)
    struct.pack_into("<IBBHQQ", image, 0x638, 1, local_info, local_other, local_section, LOCAL_VALUE, 4)
    image[0x600:0x610] = b"\0local\0lib.so\0\x00\x00"
    return image


def output_entries(data, tags, tag, size_tag):
    entries = []
    if tags.get(size_tag, 0):
        start = file_offset(data, loads(data), tags[tag])
        entries = [struct.unpack_from("<QQq", data, position) for position in range(start, start + tags[size_tag], 24)]
    return entries


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-local-symbol-") as directory:
        work = Path(directory)
        cases = (fixture(), fixture(local_info=0x11, local_other=2))
        for index, source_image in enumerate(cases):
            source = work / f"input-{index}.elf"
            source.write_bytes(source_image)
            for target, options, magic in TARGETS:
                output = work / f"output-{index}-{target}.out"
                result = subprocess.run([str(relinker), "--skip-sce-module", *options, str(source), str(output)],
                                        capture_output=True, text=True, timeout=20)
                assert result.returncode == 0, (index, target, result.stdout, result.stderr)
                assert NOTE in result.stdout, (index, target, result.stdout)
                data = output.read_bytes()
                assert data.startswith(magic), (index, target)
                if not data.startswith(b"\x7fELF"):
                    continue
                tags, _ = dynamic_strings(data)
                assert output_entries(data, tags, 23, 2) == [], (index, target)
                assert sorted((entry[0], entry[1] & 0xffffffff, entry[2]) for entry in output_entries(data, tags, DT_RELA, DT_RELASZ)) == \
                    [(DEFAULT_BASE + LOCAL_SLOT, 8, DEFAULT_BASE + LOCAL_VALUE),
                     (DEFAULT_BASE + ABSOLUTE_SLOT, 8, DEFAULT_BASE + LOCAL_VALUE + ABSOLUTE_ADDEND)], (index, target)
                symbols = file_offset(data, loads(data), tags[6])
                assert struct.unpack_from("<I", data, symbols)[0] == 0, (index, target)
            data = (work / f"output-{index}-windows.out").read_bytes()
            sections = pe_sections(data)
            writable = next(section for section in sections if section[0] == b".elf0")
            pe_header, = struct.unpack_from("<I", data, 0x3C)
            base, = struct.unpack_from("<Q", data, pe_header + 24 + 24)
            for slot, expected in ((LOCAL_SLOT, base + writable[1] + LOCAL_VALUE), (ABSOLUTE_SLOT, base + writable[1] + LOCAL_VALUE + ABSOLUTE_ADDEND)):
                value, = struct.unpack_from("<Q", data, writable[3] + slot)
                assert value == expected, (index, hex(slot), hex(value), hex(expected))
            data = (work / f"output-{index}-macos.out").read_bytes()
            macho = MachO(data)
            writable = macho.segment("__ELF0")
            for slot, expected in ((LOCAL_SLOT, writable["vmaddr"] + LOCAL_VALUE), (ABSOLUTE_SLOT, writable["vmaddr"] + LOCAL_VALUE + ABSOLUTE_ADDEND)):
                value, = struct.unpack_from("<Q", data, writable["fileoff"] + slot)
                assert value == expected, (index, hex(slot), hex(value), hex(expected))
        for label, source_image in (("jump-slot", fixture(jump_slot=True)), ("common", fixture(local_section=0xfff2))):
            source = work / f"{label}.elf"
            source.write_bytes(source_image)
            output = work / f"{label}.out"
            result = subprocess.run([str(relinker), "--skip-sce-module", str(source), str(output)],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 2 and THROW in result.stderr and not output.exists(), (label, result.stderr)
    print("Local symbol relocation tests passed")


if __name__ == "__main__":
    main()
