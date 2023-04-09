import capstone
import subprocess
from test_runner.extractor.utils import extract_text_between
from test_runner.consts import ShellcodeLoader, Arches

ARCHES = {
    Arches.MIPS.value: capstone.CS_ARCH_MIPS,
    Arches.intel_x32.value: capstone.CS_ARCH_X86,
    Arches.intel_x64.value: capstone.CS_ARCH_X86,
    Arches.aarch64.value: capstone.CS_ARCH_ARM64,
    Arches.arm32.value: capstone.CS_ARCH_ARM
}

ENDIAN = {
    Arches.MIPS.value: capstone.CS_MODE_BIG_ENDIAN,
    Arches.intel_x32.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.intel_x64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.aarch64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.arm32.value: capstone.CS_MODE_LITTLE_ENDIAN,
}

BITS = {
    Arches.MIPS.value: capstone.CS_MODE_32,
    Arches.intel_x32.value: capstone.CS_MODE_32,
    Arches.intel_x64.value: capstone.CS_MODE_64,
    Arches.aarch64.value: capstone.CS_MODE_ARM,
    Arches.arm32.value: capstone.CS_MODE_ARM,
}


class OpcodesExtractor(object):
    def __init__(self, stream, test_context):
        self.stream = stream
        self.memory_dumps = extract_text_between(self.stream, ShellcodeLoader.MemoryDumpStart,
                                                 ShellcodeLoader.MemoryDumpEnd)
        self.text_context = test_context
        mode = BITS[self.text_context['arch']]
        self.cs = capstone.Cs(
            ARCHES[self.text_context['arch']],
            ENDIAN[self.text_context['arch']] | mode
        )
        try:
            self.symbols = subprocess.check_output(" ".join(["readelf", '-s', self.text_context[
                'elf'
            ]]), shell=True)
        except:
            self.symbols = ""

    def get_symbol(self, address):
        for line in self.symbols.split("\n"):
            if not line:
                continue
            parts = [p for p in line.split(" ") if p]
            if len(parts) != 8:
                continue
            _, s_address, size, _, _, _, _, name = parts
            try:
                s_address = int(s_address, 16)
                size = int(size)
            except:
                pass

            if s_address <= address <= s_address + size:
                return name

        return ""

    @property
    def parsed(self):
        for memory_dump in self.memory_dumps:
            opcodes, address = self.extract_bytes_address(memory_dump)
            instructions = self.disassemble(opcodes=opcodes, off=address)
            dmp_full = "{}{}{}".format(ShellcodeLoader.MemoryDumpStart,
                                       memory_dump,
                                       ShellcodeLoader.MemoryDumpEnd)
            parsed = "{}\nOpcodes parser for: {}\n{}".format(
                memory_dump.strip(),
                self.text_context['arch'],
                instructions
            )
            self.stream = self.stream.replace(
                dmp_full,
                parsed
            )

        return self.stream

    @staticmethod
    def extract_bytes_address(stream):
        address = extract_text_between(stream, ShellcodeLoader.DumpAddressStart,
                                       ShellcodeLoader.DumpAddressEnd,
                                       times=1)
        dump_bytes = extract_text_between(stream,
                                          ShellcodeLoader.DumpAddressEnd,
                                          "\n",
                                          times=1)

        dump_bytes = "".join([chr(int(b, 16)) for b in dump_bytes.split(" ") if b.startswith("0x")])

        return dump_bytes, int(address, 16)

    def disassemble(self, opcodes, off):
        _instructions = [instruction for instruction in self.cs.disasm(
            opcodes,
            off,
        )]
        instructions = ["\n{}:".format(self.get_symbol(address=off))]
        for i, instruction in enumerate(_instructions):
            rpr = "      "
            if (i + 1) == len(_instructions) / 2:
                rpr = "----> "
            rpr += self.instruction_repr(instruction)
            instructions.append(rpr)
        return "\n".join(instructions)

    @staticmethod
    def instruction_repr(instruction):
        return "0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str)
