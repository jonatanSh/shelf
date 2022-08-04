from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elf_to_shellcode.lib.consts import RELOC_TYPES
from elftools.elf.enums import ENUM_RELOC_TYPE_MIPS


class MipsShellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(MipsShellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            arch="mips",
            mini_loader_little_endian="mini_loader_mips{}.shellcode",
            mini_loader_big_endian="mini_loader_mipsbe{}.shellcode",
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.got': {'align_by': 'sh_entsize', 'relocate_all': True},
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            reloc_types={
                RELOC_TYPES.GLOBAL_SYM: ENUM_RELOC_TYPE_MIPS['R_MIPS_REL32'],
                RELOC_TYPES.DO_NOT_HANDLE: [
                    ENUM_RELOC_TYPE_MIPS['R_MIPS_NONE']
                ]

            },
            support_dynamic=True,
            **kwargs
        )


mips_make_shellcode = create_make_shellcode(MipsShellcode)
