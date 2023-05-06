import capstone
from shelf.lib.consts import DisassemblerConsts


class Disassembler(object):
    def __init__(self, shellcode):
        mode = DisassemblerConsts.BITS[shellcode.args.arch]
        self.cs = capstone.Cs(
            DisassemblerConsts.ARCHES[shellcode.args.arch],
            DisassemblerConsts.ENDIAN[shellcode.args.arch] | mode
        )

    def _disassemble(self, code, off):
        return self.cs.disasm(code, off)

    @staticmethod
    def instruction_repr(instruction):
        dis = "0x%x:    %s    %s    " % (instruction.address,
                                         instruction.mnemonic,
                                         instruction.op_str)
        ins_bytes = " ".join([hex(c) for c in instruction.bytes])

        dis = dis.ljust(50, " ") + "# {}".format(ins_bytes)
        return dis

    def disassemble(self,
                    opcodes,
                    address,
                    mark=None,
                    binary_path=None,
                    limit=-1,
                    symbol_name="UNKNOWN_SYMBOL",
                    symbol_at_marked=""):
        _instructions = [instruction for instruction in self._disassemble(
            opcodes,
            address,
        )][:limit]

        instructions = ["\n{}:\n   S:{}".format(
            binary_path,
            symbol_name)]
        for i, instruction in enumerate(_instructions):
            rpr = "        " + len(symbol_at_marked) * " "
            if instruction.address == mark:
                rpr = " {} ----> ".format(symbol_at_marked)
            dis_out = self.instruction_repr(instruction)
            rpr += dis_out
            instructions.append(rpr)
        return "\n".join(instructions)
