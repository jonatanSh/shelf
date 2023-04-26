from shelf.riscv.enums64 import ENUM_RELOC_TYPE_RISCV64
from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations


class Riscv64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(Riscv64DynamicRelocations, self).__init__(shellcode=shellcode,
                                                        relocation_mapping=ENUM_RELOC_TYPE_RISCV64)
