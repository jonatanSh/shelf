from elf_to_shellcode.arguments import ARGUMENTS
from elf_to_shellcode.lib.consts import Arches
from elf_to_shellcode.arches.mips import MipsShellcode

MAP = {
    Arches.MIPS_32: MipsShellcode
}


def get_shellcode_class():
    return MAP[ARGUMENTS.arch]()
