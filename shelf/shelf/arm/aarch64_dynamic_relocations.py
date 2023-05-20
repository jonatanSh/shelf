from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64
from shelf.lib.consts import RelocationAttributes


class AArch64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(AArch64DynamicRelocations, self).__init__(shellcode=shellcode,
                                                        relocation_mapping=ENUM_RELOC_TYPE_AARCH64)

    def r_aarch64_tls_dtpmod32(self, relocation):
        s = relocation.symbol.value
        a = relocation.addend
        v_offset = s + a
        f_offset_r = self.shellcode.make_relative(relocation.address)
        v_offset_r = self.shellcode.make_relative(v_offset)

        self.shellcode.add_symbol_relocation_to_relocation_table(f_offset_r, [
            v_offset_r,
            RelocationAttributes.call_to_resolve
        ], relocation.symbol.name)

    def r_aarch64_abs64(self, relocation):
        self.r_aarch64_jmp_slot(relocation)

    def r_aarch64_glob_dat(self, relocation):
        self.r_aarch64_jmp_slot(relocation)

    def r_aarch64_jmp_slot(self, relocation):
        self.jump_slot_generic_handle(relocation)
