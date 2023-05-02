import capstone
from shelf.lib import five
from shelf.lib.consts import Arches

ARCHES = {
    Arches.mips.value: capstone.CS_ARCH_MIPS,
    Arches.intel_x32.value: capstone.CS_ARCH_X86,
    Arches.intel_x64.value: capstone.CS_ARCH_X86,
    Arches.aarch64.value: capstone.CS_ARCH_ARM64,
    Arches.arm32.value: capstone.CS_ARCH_ARM,
}

ENDIAN = {
    Arches.mips.value: capstone.CS_MODE_BIG_ENDIAN,
    Arches.intel_x32.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.intel_x64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.aarch64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.arm32.value: capstone.CS_MODE_LITTLE_ENDIAN,
}

BITS = {
    Arches.mips.value: capstone.CS_MODE_32,
    Arches.intel_x32.value: capstone.CS_MODE_32,
    Arches.intel_x64.value: capstone.CS_MODE_64,
    Arches.aarch64.value: capstone.CS_MODE_ARM,
    Arches.arm32.value: capstone.CS_MODE_ARM,
}


class Disassembler(object):
    def __init__(self, shellcode):
        mode = BITS[shellcode.args.arch]
        self.cs = capstone.Cs(
            ARCHES[shellcode.args.arch],
            ENDIAN[shellcode.args.arch] | mode
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
                    binary_path=None):
        _instructions = [instruction for instruction in self._disassemble(
            opcodes,
            address,
        )]

        instructions = ["\n{}:\n   S:{}:RA:{}".format(
            binary_path,
            "UNKNOWN_SYMBOL",
            "UNKNOWN_RELATIVE_ADDRESS")]
        for i, instruction in enumerate(_instructions):
            rpr = "      "
            if instruction.address == mark:
                rpr = "----> "
            dis_out = self.instruction_repr(instruction)
            rpr += dis_out
            instructions.append(rpr)
        return "\n".join(instructions)
