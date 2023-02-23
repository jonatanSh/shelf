import logging


class BaseDynamicRelocations(object):
    def __init__(self, shellcode):
        self.logger = logging.getLogger(self.__class__.__name__)

        self.entry_handlers = {
        }
        self.shellcode = shellcode

    def call_entry_handler(self, relocation):
        entry_handler = self.entry_handlers.get(relocation.type, None)
        if not entry_handler:
            self.logger.error("Entry handler for: {} not found, available: {}".format(
                relocation.type,
                self.entry_handlers.keys()
            ))
            assert False
        logging.info("Calling entry handler: {}".format(entry_handler.__name__))
        entry_handler(relocation=relocation)

    def handle(self, shellcode, shellcode_data):
        assert shellcode == self.shellcode
        for relocation in self.shellcode.lief_elf.relocations:
            self.call_entry_handler(
                relocation=relocation
            )

        return shellcode_data

    @property
    def dynsym(self):
        return self.shellcode.elffile.get_section_by_name('.dynsym')
