from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elf_to_shellcode.lib.ext.irelative_relocations import IrelativeRelocs


class IntelX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(IntelX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            arch="x64",
            mini_loader_little_endian="mini_loader_x64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",

            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            },
            support_dynamic=False,
            **kwargs
        )
        self.irelative = IrelativeRelocs(ENUM_RELOC_TYPE_x64['R_X86_64_IRELATIVE'])
        self.add_relocation_handler(self.irelative.relocation_for_rela_plt_got_plt)


intel_x64_make_shellcode = create_make_shellcode(IntelX64Shellcode)
