import logging


class ElfRelocationHandler(object):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def handle(self, shellcode, shellcode_data):
        for relocation in shellcode.lief_elf.relocations:
            shellcode.arch_handle_relocation(shellcode, shellcode_data, relocation)

        return shellcode_data
