from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_i386


# ELF SPEC
# https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwiF5uXC8Zr-AhXTVPEDHYJFBEUQFnoECBEQAQ&url=https%3A%2F%2Fraw.githubusercontent.com%2Fwiki%2Fhjl-tools%2Fx86-psABI%2Fintel386-psABI-draft.pdf&usg=AOvVaw2J_DXIDm4X7UhE_aZYYtkI

class X32DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(X32DynamicRelocations, self).__init__(shellcode=shellcode,
                                                    relocation_mapping=ENUM_RELOC_TYPE_i386)

    def r_386_irelative(self, relocation):
        # Handled in the INTEL_IRELATIVE
        pass

    def r_386_jump_slot(self, relocation):
        self.jump_slot_generic_handle(relocation)
