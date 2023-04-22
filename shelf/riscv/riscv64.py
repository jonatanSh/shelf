import logging
from shelf.lib.consts import RelocationAttributes
from shelf.lib.shellcode import Shellcode, create_make_shellcode
from shelf.mips.mips_dynamic_relocations import MipsDynamicRelocations


class Riscv64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(Riscv64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="riscv64",
            mini_loader_little_endian="mini_loader_riscv64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",
            sections_to_relocate={
                '.got': {'align_by': 'sh_entsize', 'relocate_all': True},
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            support_dynamic=True,
            **kwargs
        )


riscv64_make_shellcode = create_make_shellcode(Riscv64Shellcode)
