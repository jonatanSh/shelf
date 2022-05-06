from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode


class IntelX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian):
        super(IntelX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_x64.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
                '.got.plt': {'align_by': 'sh_entsize', 'relocate_all': True},
            }
        )


intel_x64_make_shellcode = create_make_shellcode(IntelX64Shellcode)
