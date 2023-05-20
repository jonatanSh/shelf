from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations


class Arm32DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(Arm32DynamicRelocations, self).__init__(shellcode=shellcode,
                                                      relocation_mapping=ENUM_RELOC_TYPE_ARM)

    def r_arm_glob_dat(self, relocation):
        return self.jmp_slot(relocation)

    def jmp_slot(self, relocation):
        self.jump_slot_generic_handle(relocation)

    def r_arm_abs32(self, relocation):
        """
        A - denotes the addend used to compute the new value of the storage unit being relocated.
        S - denotes the value of the symbol whose symbol table index is given in the r_info field of the relocation directive.
        Relocation is S-P+A
        :param relocation: The relocation
        :return: None
        """
        symbol = self.dynsym.get_symbol(relocation.info)
        s = symbol.entry.st_value
        a = relocation.addend
        v_offset = s + a
        offset = self.shellcode.make_relative(relocation.address)
        self.shellcode.add_symbol_relocation_to_relocation_table(offset, v_offset, symbol.name)
