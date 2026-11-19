from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_guest_none_relocations import TARGET, module

ERROR = "Guest export at address 0 cannot be resolved on Linux: shared"
SYMBOL_ENTRY = 0x2000 + (0x898 - 0x600)
TARGETS = (("linux", [], b"\x7fELF"), ("windows", ["--windows"], b"MZ"), ("macos", ["--macos"], b"\xcf\xfa\xed\xfe"))


def executable(import_info):
    image = bytearray(0x1200)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, 0x1000, 64, 0, 0, 64, 56, 8, 64, 0, 0)
    tags = [(5, 0x600), (10, 16), (0x61000039, 0x620), (11, 24), (0x6100003F, 48), (7, 0x700), (8, 24), (9, 24), (0, 0)]
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 6, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 5, 0x1000, 0x1000, 0x1000, 0x200, 0x200, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 176, 2, 6, 0x400, 0x400, 0x400, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<IIQQQQQQ", image, 232, 0x61000000, 0, 0, 0, 0, 0x1000, 0x1000, 1)
    for index in range(4, 8):
        struct.pack_into("<I", image, 64 + index * 56, 0x6fffff01)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQq", image, 0x700, 0x800, (1 << 32) | 6, 0)
    struct.pack_into("<IBBHQQ", image, 0x638, 1, import_info, 0, 0, 0, 0)
    image[0x600:0x610] = b"\0shared#A#B\0\x00\x00\x00\x00"
    return image


def zero_module(export_info, value=0):
    image = module([], [])
    struct.pack_into("<Q", image, 24, 0x20)
    struct.pack_into("<Q", image, 80, 0)
    struct.pack_into("<IBBHQQ", image, SYMBOL_ENTRY, 1, export_info, 0, 1, value, 1)
    return image


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-guest-zero-export-") as directory:
        work = Path(directory)
        cases = ((0x11, 0, 0x11, ERROR), (0x11, 0, 0x21, None), (0x12, 0, 0x12, None), (0x11, 0x2000, 0x11, None))
        for index, (export_info, value, import_info, error) in enumerate(cases):
            case = work / str(index)
            modules = case / "sce_module"
            modules.mkdir(parents=True)
            (modules / "module.prx").write_bytes(zero_module(export_info, value))
            source = case / "input.elf"
            source.write_bytes(executable(import_info))
            for system, flags, magic in TARGETS:
                output = case / f"output-{system}.elf"
                result = subprocess.run([str(relinker), *flags, str(source), str(output)],
                                        capture_output=True, text=True, timeout=20)
                if error is None or system != "linux":
                    assert result.returncode == 0, (index, system, result.stdout, result.stderr)
                    assert output.read_bytes().startswith(magic), (index, system)
                else:
                    assert result.returncode == 2 and error in result.stderr, (index, system, result.stderr)
                    assert not output.exists(), (index, system)
    print("Guest zero address export tests passed")


if __name__ == "__main__":
    main()
