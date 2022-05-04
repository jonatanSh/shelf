from elf_to_shellcode.elf_to_shellcode.mips.mips import make_shellcode as mips_make_shellcode

ENDIANS = ["big", "little"]

shellcode_handlers = {
    "mips": mips_make_shellcode
}


def make_shellcode(binary_path, arch, endian):
    assert endian in ENDIANS, 'Chose endain from: {}'.format(ENDIANS)
    assert arch in shellcode_handlers, 'Chose arch from: {}'.format(
        shellcode_handlers.keys()
    )
    return shellcode_handlers[arch](binary_path, endian=endian)
