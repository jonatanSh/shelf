from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations


class Arm32DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(Arm32DynamicRelocations, self).__init__(shellcode=shellcode,
                                                      relocation_mapping=ENUM_RELOC_TYPE_ARM)

    def r_arm_glob_dat(self, relocation):
        return self.jmp_slot(relocation)

    def jmp_slot(self, relocation):
        symbol = relocation.symbol
        offset = self.shellcode.make_relative(relocation.address)
        if self.handle_loader_relocation(relocation):
            return
        if symbol.value == 0x0:
            self.logger.error("Can't relocate: {}".format(
                symbol.name
            ))
        relative_sym = self.shellcode.make_relative(symbol.value)
        self.shellcode.addresses_to_patch[offset] = relative_sym

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
        self.shellcode.addresses_to_patch[offset] = v_offset
