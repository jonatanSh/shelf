import capstone
from elf_to_shellcode.lib import five

ARCHES = {
    "mips": capstone.CS_ARCH_MIPS,
    "x32": capstone.CS_ARCH_X86,
    "x64": capstone.CS_ARCH_X86,
    "arm64": capstone.CS_ARCH_ARM64,
    "arm32": capstone.CS_ARCH_ARM
}

ENDIAN = {
    "<": capstone.CS_MODE_LITTLE_ENDIAN,
    ">": capstone.CS_MODE_BIG_ENDIAN
}


class Disassembler(object):
    def __init__(self, shellcode):
        mode = capstone.CS_MODE_32
        if shellcode.arch in ['x64']:
            mode = capstone.CS_MODE_64
        if shellcode.arch in ["arm32", 'arm64']:
            mode = capstone.CS_MODE_ARM
        self.cs = capstone.Cs(
            ARCHES[shellcode.arch],
            ENDIAN[shellcode.endian] | mode
        )
        self.shellcode = shellcode
        offset = self.shellcode.instruction_offset_after_objdump
        self.opcodes = self.shellcode.do_objdump(self.shellcode.shellcode_data)[offset:]
        self.instructions = [instruction for instruction in self.cs.disasm(
            five.to_disasm(self.opcodes),
            offset,
        )]

    def get_instruction_addresses(self, instruction_filter):
        addresses = []
        for instruction in self.instructions:
            if instruction_filter(instruction):
                to_off = instruction.size
                to_off -= self.shellcode.ptr_size
                addresses.append(instruction.address + to_off)
        return addresses
