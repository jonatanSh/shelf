from elf_to_shellcode.mips.mips import mips_make_shellcode
from elf_to_shellcode.intel.x32 import intel_x32_make_shellcode
from elf_to_shellcode.intel.x64 import intel_x64_make_shellcode
from elf_to_shellcode.arm.x32 import arm_x32_make_shellcode
from elf_to_shellcode.arm.x64 import arm_x64_make_shellcode
from elf_to_shellcode.lib.consts import StartFiles


class Arches(object):
    MIPS_32 = "mips"
    INTEL_X32 = "intel_x32"
    INTEL_X64 = "intel_x64"
    ARM_32 = "arm32"
    ARM_64 = "aarch64"
    __all__ = [
        MIPS_32,
        INTEL_X32,
        INTEL_X64,
        ARM_32,
        ARM_64
    ]


ENDIANS = ["big", "little"]

shellcode_handlers = {
    Arches.MIPS_32: mips_make_shellcode,
    Arches.INTEL_X32: intel_x32_make_shellcode,
    Arches.INTEL_X64: intel_x64_make_shellcode,
    Arches.ARM_32: arm_x32_make_shellcode,
    Arches.ARM_64: arm_x64_make_shellcode,
}


def make_shellcode(binary_path, arch, endian, start_file_method):
    assert endian in ENDIANS, 'Chose endain from: {}'.format(ENDIANS)
    assert arch in shellcode_handlers, 'Chose arch from: {}'.format(
        shellcode_handlers.keys()
    )
    assert start_file_method in StartFiles.__all__
    return shellcode_handlers[arch](binary_path, endian=endian,
                                    start_file_method=start_file_method)
