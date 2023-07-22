import logging

from shelf.lib.ext.opcodes_analysis_base import OpcodeAnalyzer
from shelf.riscv.opcodes_analyzer.candidate_matchers import ConsecutiveLuiLdMatcher


class Riscv64OpcodesAnalyzer(OpcodeAnalyzer):
    def __init__(self, *args, **kwargs):
        super(Riscv64OpcodesAnalyzer, self).__init__(*args, **kwargs)
        self.supported = False
        self.matchers = [
            ConsecutiveLuiLdMatcher()
        ]
        self.relocations = []

    def init(self, shellcode_data):
        disassembly_offset = self.shelf.opcodes_start_address
        symbols = self.shelf.find_symbols()
        symbol_addresses = {}
        sym_offset = self.shelf.loading_virtual_address
        # Packing symbol pointers
        for symbol in symbols:
            symbol_addresses[symbol[1]] = symbol
        self.logger.info("Finding candidates")
        for instruction in self.shelf.disassembler.raw_disassemble(
                shellcode_data[disassembly_offset:], off=disassembly_offset):

            for matcher in self.matchers:
                if instruction.bytes == b'\x37\x27\x07\x00':
                    print(self.shelf.disassembler.instruction_repr(instruction))
                matcher.match(instruction)

        candidates = []
        for matcher in self.matchers:
            logging.info("Getting matches for matcher: {}".format(matcher))
            candidates += matcher.get_matches()
        for candidate in candidates:
            if self.shelf.in_range_of_shellcode(candidate.resulting_address):
                self.relocations.append(candidate)

    def _is_required(self, shellcode_data):
        self.init(shellcode_data=shellcode_data)
        if self.relocations:
            return True

    def _analyze(self, shellcode_data):
        pass
