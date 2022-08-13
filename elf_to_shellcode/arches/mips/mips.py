from elf_to_shellcode.lib.shelf.shellcode import Shellcode


class MipsShellcode(Shellcode):
    def __init__(self):
        super(MipsShellcode, self).__init__(ptr_fmt="I",
                                            relocation_table_magic=0xaabbccdd)
