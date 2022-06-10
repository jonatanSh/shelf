from elf_to_shellcode.elf_to_shellcode.lib.consts import RelocationAttributes
import logging


class DynamicRelocations(object):
    def __init__(self):
        self.logger = logging.getLogger("[DynamicRelocs]")

    def handle(self, shellcode, shellcode_data):

        # This case is already integrated in to the default relocation algorithm
        dynsym = shellcode.elffile.get_section_by_name(".dynsym")
        dynamic = shellcode.elffile.get_section_by_name('.dynamic')
        relocation_table = dynamic.get_relocation_tables()
        if "JMPREL" in relocation_table:
            self.handle_jmp_slot_relocs(shellcode=shellcode,
                                        table=relocation_table["JMPREL"],
                                        dynsym=dynsym)
        return shellcode_data

    def handle_jmp_slot_relocs(self, shellcode,
                               table,
                               dynsym):
        for relocation in table.iter_relocations():
            entry = relocation.entry
            offset = entry.r_offset
            symbol_name = dynsym.get_symbol(entry.r_info_sym).name
            jmp_slot_address = shellcode.loader_symbols.get_relative_symbol_address(
                symbol_name=symbol_name
            )
            self.logger.info("[JMP_SL] Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(offset),
                hex(jmp_slot_address),
                hex(shellcode.make_absolute(offset)),
                hex(shellcode.make_absolute(jmp_slot_address))
            ))
            shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                    RelocationAttributes.relative_to_start_of_table]
