from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elf_to_shellcode.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elf_to_shellcode.lib.consts import RelocationAttributes


class Arm32DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(Arm32DynamicRelocations, self).__init__(shellcode=shellcode)
        self.entry_handlers = {
            ENUM_RELOC_TYPE_ARM['R_ARM_GLOB_DAT']: self.r_arm_glob_dat,
            ENUM_RELOC_TYPE_ARM['R_ARM_JUMP_SLOT']: self.jmp_slot,
            ENUM_RELOC_TYPE_ARM['R_ARM_ABS32']: self.r_arm_abs32,
            # ENUM_RELOC_TYPE_ARM['R_ARM_PC24']: self.r_arm_pc24,
            # ENUM_RELOC_TYPE_ARM['R_ARM_ABS12']: self.r_arm_abs12,
            # ENUM_RELOC_TYPE_ARM['R_ARM_THM_ABS5']: self.r_arm_thm_abs5,

            # ENUM_RELOC_TYPE_ARM['R_ARM_BASE_PREL']: self.r_arm_base_perl,
            # ENUM_RELOC_TYPE_ARM['R_ARM_JUMP24']: self.r_arm_jump24,
            # ENUM_RELOC_TYPE_ARM['R_ARM_GOT_BREL']: self.r_arm_got_brel,
            # ENUM_RELOC_TYPE_ARM['R_ARM_BASE_ABS']: self.r_arm_base_abs,
            # ENUM_RELOC_TYPE_ARM['R_ARM_THM_SWI8']: self.r_arm_thm_swi8,
            # ENUM_RELOC_TYPE_ARM['R_ARM_XPC25']: self.r_arm_xpc25,
            # ENUM_RELOC_TYPE_ARM['R_ARM_THM_XPC22']: self.r_arm_thm_xpc22

        }

    def r_arm_pc24(self, relocation):
        pass

    def r_arm_glob_dat(self, relocation):
        symbol_name = relocation.symbol.name
        if self.shellcode.mini_loader.symbols.has_symbol(symbol_name):
            jmp_slot_address = self.shellcode.mini_loader.symbols.get_relative_symbol_address(
                symbol_name=symbol_name
            )
            offset = self.shellcode.make_relative(relocation.address)
            self.shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                         RelocationAttributes.relative_to_loader_base]

        else:
            raise Exception("Library dynamic link error against symbol: {}".format(
                symbol_name
            ))

    def jmp_slot(self, relocation):
        symbol = relocation.symbol
        offset = self.shellcode.make_relative(relocation.address)
        if self.shellcode.mini_loader.symbols.has_symbol(symbol.name):
            jmp_slot_address = self.shellcode.mini_loader.symbols.get_relative_symbol_address(
                symbol_name=symbol.name
            )
            self.shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                         RelocationAttributes.relative_to_loader_base]

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

    def r_arm_base_perl(self, relocation):
        pass

    def r_arm_jump24(self, relocation):
        pass

    def r_arm_got_brel(self, relocation):
        pass

    def r_arm_abs12(self, relocation):
        pass

    def r_arm_base_abs(self, relocation):
        pass

    def r_arm_thm_swi8(self, relocation):
        pass

    def r_arm_xpc25(self, relocation):
        pass

    def r_arm_thm_xpc22(self, relocation):
        pass

    def r_arm_thm_abs5(self, relocation):
        pass
