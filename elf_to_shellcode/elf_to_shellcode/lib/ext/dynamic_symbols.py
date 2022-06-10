from elf_to_shellcode.elf_to_shellcode.lib.consts import RelocationAttributes
import logging


class DynamicRelocations(object):
    def __init__(self):
        self.logger = logging.getLogger("[DynamicRelocs]")

    def handle(self, shellcode, shellcode_data):

        # This case is already integrated in to the default relocation algorithm
        dynsym = shellcode.elffile.get_section_by_name(".dynsym")
        dynamic = shellcode.elffile.get_section_by_name('.dynamic')
        if not dynamic:
            return shellcode_data
        assert dynsym
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
            symbol_obj = dynsym.get_symbol(entry.r_info_sym)
            symbol_name = symbol_obj.name
            r_address = symbol_obj.entry.st_value
            """
            Jump slot for local elf symbol.
            the elf is compiled as -shared
            """
            if r_address:
                r_address = shellcode.make_relative(r_address)
                self.logger.info("[JMP_SL_LC] Relative(*{}={}()) Absolute(*{}={}())".format(
                    hex(offset),
                    hex(r_address),
                    hex(shellcode.make_absolute(offset)),
                    hex(shellcode.make_absolute(r_address))
                ))
                shellcode.addresses_to_patch[offset] = r_address
                continue

            """
            External symbol
            Trying to resolve
            """
            if not shellcode.loader_symbols.has_symbol(symbol_name):
                logging.info("[SymNotFound] {}".format(
                    symbol_name
                ))
                continue
            jmp_slot_address = shellcode.loader_symbols.get_relative_symbol_address(
                symbol_name=symbol_name
            )
            self.logger.info("[JMP_SL_EXT] Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(offset),
                hex(jmp_slot_address),
                hex(shellcode.make_absolute(offset)),
                hex(shellcode.make_absolute(jmp_slot_address))
            ))
            shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                    RelocationAttributes.relative_to_loader_base]
