from elf_to_shellcode.mips.mips import mips_make_shellcode
from elf_to_shellcode.intel.x32 import intel_x32_make_shellcode
from elf_to_shellcode.intel.x64 import intel_x64_make_shellcode
from elf_to_shellcode.arm.x32 import arm_x32_make_shellcode
from elf_to_shellcode.arm.x64 import arm_x64_make_shellcode
from elf_to_shellcode.lib.consts import StartFiles, Arches, ArchEndians

ENDIANS = [ArchEndians.big.value, ArchEndians.little.value]

shellcode_handlers = {
    Arches.mips.value: mips_make_shellcode,
    Arches.intel_x32.value: intel_x32_make_shellcode,
    Arches.intel_x64.value: intel_x64_make_shellcode,
    Arches.arm32.value: arm_x32_make_shellcode,
    Arches.aarch64.value: arm_x64_make_shellcode,
}


def make_shellcode(arch, endian, start_file_method, args):
    assert endian in ENDIANS, 'Chose endain from: {}'.format(ENDIANS)
    assert arch in shellcode_handlers, 'Chose arch from: {}, got arch: {}'.format(
        shellcode_handlers.keys(),
        arch
    )
    assert start_file_method in StartFiles.__all__
    return shellcode_handlers[arch](args=args)
