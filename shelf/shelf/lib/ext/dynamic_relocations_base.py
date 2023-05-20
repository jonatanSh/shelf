import logging
from shelf.lib.consts import RelocationAttributes


class BaseDynamicRelocations(object):
    def __init__(self, shellcode, relocation_mapping=None):
        self.logger = logging.getLogger(self.__class__.__name__)

        self.entry_handlers = {
        }
        self.relocation_mapping = {}
        if relocation_mapping:
            for key, value in relocation_mapping.items():
                self.relocation_mapping[value] = key.lower()
        self.shellcode = shellcode

    def call_entry_handler(self, relocation):
        mapped_name = self.relocation_mapping.get(relocation.type, None)
        entry_handler = None
        if mapped_name:
            entry_handler = getattr(self, mapped_name)

        entry_handler = self.entry_handlers.get(relocation.type, entry_handler)
        if not entry_handler:
            self.logger.error("Entry handler for: {} not found, available: {}, mapped: {}".format(
                relocation.type,
                self.entry_handlers.keys(),
                mapped_name
            ))
            assert False
        logging.info("Calling entry handler: {}".format(entry_handler.__name__))
        entry_handler(relocation=relocation)

    @property
    def iter_relocations(self):
        lists = [
            self.shellcode.lief_elf.relocations,
            self.shellcode.lief_elf.dynamic_relocations,
            self.shellcode.lief_elf.object_relocations,
            self.shellcode.lief_elf.pltgot_relocations,
        ]

        for reloc_list in lists:
            for item in reloc_list:
                yield item

    def handle(self, shellcode, shellcode_data):
        assert shellcode == self.shellcode
        for relocation in self.iter_relocations:
            self.call_entry_handler(
                relocation=relocation
            )

        return shellcode_data

    @property
    def dynsym(self):
        return self.shellcode.elffile.get_section_by_name('.dynsym')

    def handle_loader_relocation(self, relocation):
        symbol = relocation.symbol
        offset = self.shellcode.make_relative(relocation.address)
        if self.shellcode.mini_loader.symbols.has_symbol(symbol.name):
            jmp_slot_address = self.shellcode.mini_loader.symbols.get_relative_symbol_address(
                symbol_name=symbol.name
            )
            self.shellcode.add_symbol_relocation_to_relocation_table(offset,
                                                                     [jmp_slot_address,
                                                                      RelocationAttributes.relative_to_loader_base],
                                                                     symbol.name)

            return True

        return False

    def jump_slot_generic_handle(self, relocation):
        symbol = relocation.symbol
        offset = self.shellcode.make_relative(relocation.address)
        if self.handle_loader_relocation(relocation):
            return
        if symbol.value == 0x0:
            self.logger.error("Can't relocate: {}".format(
                symbol.name
            ))
        relative_sym = self.shellcode.make_relative(symbol.value)
        self.shellcode.add_symbol_relocation_to_relocation_table(offset, relative_sym, symbol.name)
