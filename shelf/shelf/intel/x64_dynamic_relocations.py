from shelf.lib.ext.dynamic_relocations_base import BaseDynamicRelocations
from elftools.elf.enums import ENUM_RELOC_TYPE_i386
from shelf.lib.consts import RelocationAttributes


# ELF SPEC
# TLS:
# https://www.uclibc.org/docs/tls.pdf

class X64DynamicRelocations(BaseDynamicRelocations):
    def __init__(self, shellcode):
        super(X64DynamicRelocations, self).__init__(shellcode=shellcode,
                                                    relocation_mapping=ENUM_RELOC_TYPE_i386)

    def r_386_tls_tpoff32(self, relocation):
        # Handled in the INTEL_IRELATIVE
        pass
