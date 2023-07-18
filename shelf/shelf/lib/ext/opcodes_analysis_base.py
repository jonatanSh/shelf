import logging


class OpcodeAnalyzer(object):
    def __init__(self, shelf):
        self.shelf = shelf
        self.logger = logging.getLogger(self.__class__.__name__)

    def _analyze(self, shellcode_data):
        raise NotImplementedError()

    def _is_required(self, shellcode_data):
        raise NotImplementedError()

    def analyze(self, shellcode_data):
        if not self.is_required(shellcode_data):
            return shellcode_data

        return self._analyze(shellcode_data)

    def is_required(self, shellcode_data):
        if self._is_required(shellcode_data):
            if not self.shelf.args.relocate_opcodes:
                if self.shelf.args.force:
                    self.logger.warning("Detected --force flag, this shellcode contain opcode relocations")
                    return
                raise Exception("Error source binary require opcode relocations,"
                                "probably compiled without -fpic or with (-fpic and -static), try (-fpic -static-pie) "
                                "or use --relocate-opcodes or --force")
            return True
        return False
