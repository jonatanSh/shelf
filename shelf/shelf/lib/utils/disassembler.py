import capstone
from shelf.lib.consts import DisassemblerConsts
from shelf.lib.utils.objdump_disassembler_backend import ObjdumpDisassemblerBackend

class Disassembler(object):
    def __init__(self, shellcode):
        if shellcode.args.arch in DisassemblerConsts.ARCHES:
            mode = DisassemblerConsts.ENDIAN[shellcode.args.arch]
            if shellcode.args.arch in DisassemblerConsts.BITS:
                mode |= DisassemblerConsts.BITS[shellcode.args.arch]
            self.cs = capstone.Cs(
                DisassemblerConsts.ARCHES[shellcode.args.arch],
                mode
            )
        else:
            self.cs = ObjdumpDisassemblerBackend(
                shellcode.args.arch
            )

    def raw_disassemble(self, code, off):
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
        _instructions = [instruction for instruction in self.raw_disassemble(
            opcodes,
            address,
        )]

        instructions = ["\n{}:\n   S:{}".format(
            binary_path,
            symbol_name)]
        index_at_marked = None
        for i, instruction in enumerate(_instructions):
            if symbol_at_marked:
                additional_padding = len(symbol_at_marked) * " "
            else:
                additional_padding = ""
            rpr = "        " + additional_padding
            if instruction.address == mark:
                rpr = " {} ----> ".format(symbol_at_marked if symbol_at_marked else "")
                index_at_marked = i
            dis_out = self.instruction_repr(instruction)
            rpr += dis_out
            instructions.append(rpr)

        if index_at_marked and limit != -1:
            start = int(index_at_marked - (limit / 2))
            end = int(index_at_marked + (limit / 2))

            instructions = instructions[start:end]
        elif limit:
            instructions = instructions[:limit]
        return "\n".join(instructions)
