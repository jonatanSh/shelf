import binascii
import logging

from shelf.lib.ext.opcodes_analysis_base import OpcodeAnalyzer
from shelf.riscv.opcodes_analyzer.candidate_matchers import ConsecutiveLuiLdMatcher
from shelf.lib.consts import RelocationAttributes


class Riscv64OpcodesAnalyzer(OpcodeAnalyzer):
    def __init__(self, *args, **kwargs):
        super(Riscv64OpcodesAnalyzer, self).__init__(*args, **kwargs)
        self.supported = True
        self.matchers = [
            ConsecutiveLuiLdMatcher()
        ]
        self.relocations = {}

    def init(self, shellcode_data):
        disassembly_offset = self.shelf.opcodes_start_address
        self.logger.info("Finding candidates")
        for instruction in self.shelf.disassembler.raw_disassemble(
                shellcode_data[disassembly_offset:], off=disassembly_offset):

            for matcher in self.matchers:
                matcher.match(instruction)

        candidates = []
        for matcher in self.matchers:
            logging.info("Getting matches for matcher: {}".format(matcher))
            candidates += matcher.get_matches()
        for candidate in candidates:
            if self.shelf.in_range_of_shellcode(candidate.resulting_address):
                self.relocations[candidate.f_offset] = candidate.resulting_address

    def get_instruction_relocation_offset(self, instruction):
        to_off = instruction.size
        to_off -= self.shelf.address_utils.ptr_size
        return instruction.address + to_off

    def _is_required(self, shellcode_data):
        self.init(shellcode_data=shellcode_data)
        if self.relocations:
            return True

    def replace_lui_ld_with_auipc(self, shellcode_data):
        """
        The lui ld consecutive sequence for accessing memory addresses
        Can't access the entire 64 bit address range.
        Therefor, we replace them with opcodes that are PC relative.
        :return:
        """
        for f_offset, v_offset in self.relocations.items():
            f_offset_relative = f_offset - self.shelf.opcodes_start_address
            # Now going to construct a relative pc load
            pc_relative = v_offset - f_offset
            if pc_relative < 0:
                # TODO figure out if this is ok
                self.logger.warning("Riscv invalid pc relative offset")
                continue
            lui_instruction = self.shelf.address_utils.unpack(
                "I",
                shellcode_data[f_offset_relative:f_offset_relative + 4]
            )[0]
            # Lui and auipc differs only in the 6th bit
            # This mask will convert to instruction to auipc
            auipc_instruction = lui_instruction & 0x00000fdf
            assert pc_relative < (1 << 20)
            auipc_instruction += (pc_relative << 12)
            auipc_instruction_packed = self.shelf.address_utils.pack("I", auipc_instruction)
            self.logger.info("Patching lui={} with auipc={}".format(
                hex(lui_instruction),
                hex(auipc_instruction)
            ))
            # Replacing the instruction with a relative auipc instruction
            shellcode_data = shellcode_data[:f_offset_relative] + auipc_instruction_packed + shellcode_data[
                                                                                             f_offset_relative + 4:]
            # Now going to override the addiu instruction
            ld_instruction = self.shelf.address_utils.unpack(
                "I",
                shellcode_data[f_offset_relative + 4:f_offset_relative + 8]
            )[0]
            patched_ld_instruction = (ld_instruction & 0xfffff) << 12
            patched_ld_instruction_packed = self.shelf.address_utils.pack("I", patched_ld_instruction)

            shellcode_data = shellcode_data[:f_offset_relative + 4] + patched_ld_instruction_packed + shellcode_data[
                                                                                                      f_offset_relative + 8:]

        return shellcode_data

    def _analyze(self, shellcode_data):
        return self.replace_lui_ld_with_auipc(shellcode_data=shellcode_data)
