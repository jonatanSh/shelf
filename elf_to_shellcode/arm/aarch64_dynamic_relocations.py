import logging

from elf_to_shellcode.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64
from elf_to_shellcode.lib.consts import RelocationAttributes


class AArch64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(AArch64DynamicRelocations, self).__init__(shellcode=shellcode)
        self.entry_handlers = {
            ENUM_RELOC_TYPE_AARCH64['R_AARCH64_TLS_DTPMOD32']: self.r_aarch64_tls_dtpmod32,
            ENUM_RELOC_TYPE_AARCH64['R_AARCH64_ABS64']: self.r_aarch64_abs64,
            ENUM_RELOC_TYPE_AARCH64['R_AARCH64_GLOB_DAT']: self.r_aarch64_glob_dat,
            ENUM_RELOC_TYPE_AARCH64['R_AARCH64_JUMP_SLOT']: self.r_aarch64_jmp_slot

        }

    def r_aarch64_tls_dtpmod32(self, relocation):
        s = relocation.symbol.value
        a = relocation.addend
        v_offset = s + a
        f_offset_r = self.shellcode.make_relative(relocation.address)
        v_offset_r = self.shellcode.make_relative(v_offset)

        self.shellcode.addresses_to_patch[f_offset_r] = [
            v_offset_r,
            RelocationAttributes.call_to_resolve
        ]

    def r_aarch64_abs64(self, relocation):
        symbol = relocation.symbol
        f_offset_r = self.shellcode.make_relative(relocation.address)

        if self.shellcode.mini_loader.symbols.has_symbol(symbol.name):
            jmp_slot_address = self.shellcode.mini_loader.symbols.get_relative_symbol_address(
                symbol_name=symbol.name
            )
            self.shellcode.addresses_to_patch[f_offset_r] = [jmp_slot_address,
                                                             RelocationAttributes.relative_to_loader_base]

            return
        s = relocation.symbol.value
        a = relocation.addend
        v_offset = s + a
        v_offset_r = self.shellcode.make_relative(v_offset)

        self.shellcode.addresses_to_patch[f_offset_r] = v_offset_r

    def r_aarch64_glob_dat(self, relocation):
        return self.r_aarch64_abs64(relocation)

    def r_aarch64_jmp_slot(self, relocation):
        return self.r_aarch64_abs64(relocation)
