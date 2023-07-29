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

    @staticmethod
    def get_lui_ld_offsets(target_address):
        """
        This helper function try to do its best to find the correct lui ld sequence
        :param target_address:
        :return:
        """
        lui_relative = target_address >> 12
        for i in [-1, 0, 1]:
            current_relative_lui = (lui_relative + i)
            ld_relative = (target_address - (current_relative_lui << 12))
            if current_relative_lui < 0:
                continue
            if -2048 < ld_relative < 2048:
                return current_relative_lui, ld_relative
        return None, None

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
            pc_relative = v_offset - self.shelf.f_offset_get_matching_virtual_address(f_offset_relative)

            pc_relative_lui, pc_relative_ld = self.get_lui_ld_offsets(
                pc_relative
            )

            if not all([pc_relative_ld, pc_relative_lui]):
                self.logger.error("Address for relative lui, ld not found")
                continue
            lui_instruction = self.shelf.address_utils.unpack(
                "I",
                shellcode_data[f_offset_relative:f_offset_relative + 4]
            )[0]

            # Lui and auipc differs only in the 6th bit
            # This mask will convert to instruction to auipc
            auipc_instruction = lui_instruction & 0x00000fdf
            assert pc_relative < (1 << 20)
            auipc_instruction += (pc_relative_lui << 12)
            auipc_instruction_packed = self.shelf.address_utils.pack("I", auipc_instruction)

            # Replacing the instruction with a relative auipc instruction
            shellcode_data = shellcode_data[:f_offset_relative] + auipc_instruction_packed + shellcode_data[
                                                                                             f_offset_relative + 4:]
            # Now going to override the addiu instruction
            ld_instruction = self.shelf.address_utils.unpack(
                "I",
                shellcode_data[f_offset_relative + 4:f_offset_relative + 8]
            )[0]
            patched_ld_instruction = (ld_instruction & 0x000fffff)
            patched_ld_instruction += (self.shelf.address_utils.twos_complement(
                pc_relative_ld,
                12
            ) << 20)

            patched_ld_instruction_packed = self.shelf.address_utils.pack("I", patched_ld_instruction)

            shellcode_data = shellcode_data[:f_offset_relative + 4] + patched_ld_instruction_packed + shellcode_data[
                                                                                                      f_offset_relative + 8:]

            self.logger.info("LUI-LD PATCH Patching lui={} with auipc={}, ld={}, ld={}".format(
                hex(lui_instruction),
                hex(auipc_instruction),
                hex(ld_instruction),
                hex(patched_ld_instruction)
            ))
        return shellcode_data

    def _analyze(self, shellcode_data):
        return self.replace_lui_ld_with_auipc(shellcode_data=shellcode_data)
