from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elf_to_shellcode.lib.ext.irelative_relocations import IrelativeRelocs
from elf_to_shellcode.lib.consts import RELOC_TYPES


class IntelX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(IntelX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="x64",
            mini_loader_little_endian="mini_loader_x64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",

            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            },
            support_dynamic=True,
            reloc_types={
                RELOC_TYPES.GLOBAL_SYM: ENUM_RELOC_TYPE_x64['R_X86_64_64'],
                RELOC_TYPES.GLOBAL_DAT: ENUM_RELOC_TYPE_x64['R_X86_64_GLOB_DAT'],
                RELOC_TYPES.DO_NOT_HANDLE: [
                ]

            },
            **kwargs
        )
        self.irelative = IrelativeRelocs(ENUM_RELOC_TYPE_x64['R_X86_64_IRELATIVE'])
        self.add_relocation_handler(self.irelative.relocation_for_rela_plt_got_plt)


intel_x64_make_shellcode = create_make_shellcode(IntelX64Shellcode)
