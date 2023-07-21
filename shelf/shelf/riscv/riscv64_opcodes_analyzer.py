from shelf.lib.ext.opcodes_analysis_base import OpcodeAnalyzer


class RelocationCandidate(object):
    def __init__(self, shelf):
        self.shelf = shelf

    @property
    def resulting_address(self):
        raise NotImplementedError()


class LuiLdCandidate(RelocationCandidate):
    def __init__(self, shelf, lui, ld):
        super(LuiLdCandidate, self).__init__(shelf=shelf)
        self.lui = lui
        self.ld = ld

    def resulting_address(self):
        return 0x0

    def __str__(self):
        return "LuiLdInstructionCandidate({})".format(
            self.shelf.disassembler.instruction_repr(self.lui),
            self.shelf.disassembler.instruction_repr(self.ld)

        )


class Riscv64OpcodesAnalyzer(OpcodeAnalyzer):
    def __init__(self, *args, **kwargs):
        super(Riscv64OpcodesAnalyzer, self).__init__(*args, **kwargs)
        self.supported = False
        self.candidates = []

    def handle_lui_ld_stack(self, stack):
        self.candidates.append(
            LuiLdCandidate(self.shelf, stack.pop(), stack.pop())
        )

    def init(self, shellcode_data):
        lui_ld_stack = set()
        disassembly_offset = self.shelf.opcodes_start_address
        symbols = self.shelf.find_symbols()
        symbol_addresses = {}
        sym_offset = self.shelf.loading_virtual_address
        # Packing symbol pointers
        for symbol in symbols:
            symbol_addresses[symbol[1]] = symbol

        for instruction in self.shelf.disassembler.raw_disassemble(
                shellcode_data[disassembly_offset:], off=disassembly_offset):
            """
                Trying to get:
                0x400086715c    <SHELF:strlen +0x28>:	lui	a4,0x72
                0x4000867160    <SHELF:strlen +0x2c>:	ld	a1,-1992(a4)
                consecutive instructions
            """
            if 'lui' in instruction.mnemonic:
                lui_ld_stack.add(instruction)
            elif 'ld' in instruction.mnemonic:
                lui_ld_stack.add(instruction)
            elif len(lui_ld_stack) == 2:
                self.handle_lui_ld_stack(lui_ld_stack)
                lui_ld_stack = set()
            else:
                lui_ld_stack = set()

    def _is_required(self, shellcode_data):
        self.init(shellcode_data=shellcode_data)
        for instruction_object in self.candidates:
            print(instruction_object)
        import sys
        sys.exit(1)

    def _analyze(self, shellcode_data):
        pass
