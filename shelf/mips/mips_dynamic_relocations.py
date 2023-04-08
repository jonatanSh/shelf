from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_MIPS


class MipsDynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(MipsDynamicRelocations, self).__init__(shellcode=shellcode,
                                                     relocation_mapping=ENUM_RELOC_TYPE_MIPS)

    def r_mips_none(self, relocation):
        return
