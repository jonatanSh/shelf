from shelf.riscv.enums64 import ENUM_RELOC_TYPE_RISCV64
from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations


# https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#reloc-table
class Riscv64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(Riscv64DynamicRelocations, self).__init__(shellcode=shellcode,
                                                        relocation_mapping=ENUM_RELOC_TYPE_RISCV64)

    def elf_64_reloc(self, relocation):
        s = relocation.symbol.value
        a = relocation.addend
        v_offset = s + a
        f_offset_r = self.shellcode.make_relative(relocation.address)
        v_offset_r = self.shellcode.make_relative(v_offset)

        self.shellcode.add_symbol_relocation_to_relocation_table(f_offset_r, v_offset_r, relocation.symbol.name)

    def jump_slot(self, relocation):
        return self.jump_slot_generic_handle(relocation)