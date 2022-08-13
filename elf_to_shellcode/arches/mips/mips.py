from elftools.elf.enums import ENUM_RELOC_TYPE_MIPS
from elf_to_shellcode.lib.shelf.shellcode import Shellcode
from elf_to_shellcode.lib.utils import AddressUtils


class MipsShellcode(Shellcode):
    def __init__(self):
        super(MipsShellcode, self).__init__(ptr_fmt="I",
                                            relocation_table_magic=0xaabbccdd)
        self.bits = 32

    def handle(self):
        self.do_relocations()

    def do_relocations(self):
        # abi: https://refspecs.linuxfoundation.org/elf/mipsabi.pdf
        base_address = 0
        for relocation in self.lief_elf.relocations:
            relocation_value = None
            if ENUM_RELOC_TYPE_MIPS.R_MIPS_NONE:
                pass
            elif ENUM_RELOC_TYPE_MIPS.R_MIPS_16:
                symbol = relocation.symbol
                value = symbol.value
                addend = relocation.addend
                relocated = value + AddressUtils.sign_extend(addend, self.bits)
            elif ENUM_RELOC_TYPE_MIPS.R_MIPS_32:
                symbol = relocation.symbol
                value = symbol.value
                addend = relocation.addend
                relocated = value + addend
            elif ENUM_RELOC_TYPE_MIPS.R_MIPS_REL32:
                raise NotImplementedError()
            elif ENUM_RELOC_TYPE_MIPS.R_MIPS_26:
                raise NotImplementedError()
            elif ENUM_RELOC_TYPE_MIPS.R_MIPS_HI16:
                value = None
                symbol = relocation.symbol
                is_local = False
                if symbol.visibility.value in [
                    symbol.visibility.HIDDEN,
                    symbol.visibility.INTERNAL,
                    symbol.visibility.DEFAULT,
                    symbol.visibility.PROTECTED
                ]:
                    is_local = True

                if symbol.name == "_gp_disp":
                    AHL = 
                    (AHL + GP – P) – (short) \
                        (AHL + GP – P)) >> 16

            else:
                raise Exception("Relocation: {} not handled".format(
                    relocation
                ))
