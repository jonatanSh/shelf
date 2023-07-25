from shelf.riscv.opcodes_analyzer.instructions import LuiInstruction, LdInstruction


class RelocationCandidate(object):
    @property
    def f_offset(self):
        raise NotImplementedError()

    @property
    def resulting_address(self):
        raise NotImplementedError()

    def wrapped(self, shelf):
        return str(self)

    def is_valid(self):
        raise NotImplementedError()


class LuiLdCandidate(RelocationCandidate):
    def __init__(self, lui, ld):
        self._lui = lui
        self._ld = ld
        self.lui = LuiInstruction(self._lui)
        self.ld = LdInstruction(self._ld)

    @property
    def resulting_address(self):
        return self.lui.immediate + self.ld.offset

    @property
    def f_offset(self):
        return self._lui.address

    def wrapped(self, shelf):
        return "LuiLdInstructionCandidate(\n{}\n{}\n)".format(
            shelf.disassembler.instruction_repr(self._lui),
            shelf.disassembler.instruction_repr(self._ld)

        )

    def is_valid(self):
        return self.lui.source_register == self.ld.destination_register
