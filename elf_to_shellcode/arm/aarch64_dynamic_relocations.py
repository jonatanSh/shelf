from elf_to_shellcode.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64
from elf_to_shellcode.lib.consts import RelocationAttributes


class AArch64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(AArch64DynamicRelocations, self).__init__(shellcode=shellcode)
        self.entry_handlers = {
            ENUM_RELOC_TYPE_AARCH64['R_AARCH64_TLS_DTPMOD32']: self.r_aarch64_tls_dtpmod32

        }

    def r_aarch64_tls_dtpmod32(self, relocation):
        s = relocation.symbol.value
        a = relocation.addend
        v_offset = s + a
        f_offset = self.shellcode.make_relative(relocation.address)
        self.shellcode.addresses_to_patch[f_offset] = [
            v_offset,
            RelocationAttributes.call_to_resolve
        ]
