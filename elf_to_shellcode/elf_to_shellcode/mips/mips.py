from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode


class MipsShellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian):
        super(MipsShellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_mips.shellcode",
            mini_loader_big_endian="mini_loader_mipsbe.shellcode",
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.got': {'align_by': 'sh_entsize', 'relocate_all': True},
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            }
        )


mips_make_shellcode = create_make_shellcode(MipsShellcode)
