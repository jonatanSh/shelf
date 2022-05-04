from elf_to_shellcode.elf_to_shellcode.mips.mips import mips_make_shellcode
from elf_to_shellcode.elf_to_shellcode.intel.x32 import intel_x32_make_shellcode
from elf_to_shellcode.elf_to_shellcode.intel.x64 import intel_x64_make_shellcode

ENDIANS = ["big", "little"]

shellcode_handlers = {
    "mips": mips_make_shellcode,
    "intel_x32": intel_x32_make_shellcode,
    "intel_x64": intel_x64_make_shellcode
}


def make_shellcode(binary_path, arch, endian):
    assert endian in ENDIANS, 'Chose endain from: {}'.format(ENDIANS)
    assert arch in shellcode_handlers, 'Chose arch from: {}'.format(
        shellcode_handlers.keys()
    )
    return shellcode_handlers[arch](binary_path, endian=endian)
