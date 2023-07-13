import binascii
import logging

from shelf.lib.ext.opcodes_analysis_base import OpcodeAnalyzer


class IntelX32OpcodesAnalyzer(OpcodeAnalyzer):
    def __init__(self, *args, **kwargs):
        super(IntelX32OpcodesAnalyzer, self).__init__(*args, **kwargs)
        """
            Dictionary where key is the address and value is the symbol
            address: symbol
        """
        self.symbol_fixes = {

        }

    def get_instruction_relocation_offset(self, instruction):
        to_off = instruction.size
        to_off -= self.shelf.address_utils.ptr_size
        return instruction.address + to_off

    def x86_handle_lea_instruction(self, instruction, symbol_addresses):
        instruction_address = -1
        if 'lea' in instruction.mnemonic:
            if len(instruction.bytes) < 6:
                # self.logger.info("Unknown lea instruction skipping: {}".format(
                #     self.shelf.disassembler.instruction_repr(instruction)
                # ))
                return
            instruction_address = self.shelf.unpack_ptr(
                instruction.bytes[2:6])
        if instruction_address in symbol_addresses:
            symbol = symbol_addresses[instruction_address]
            off = self.get_instruction_relocation_offset(instruction)
            self.symbol_fixes[off] = symbol

    def init(self, shellcode_data):
        disassembly_offset = self.shelf.opcodes_start_address
        symbols = self.shelf.find_symbols()
        symbol_addresses = {}
        # Packing symbol pointers
        for symbol in symbols:
            symbol_addresses[symbol[1]] = symbol

        for instruction in self.shelf.disassembler.raw_disassemble(
                shellcode_data[disassembly_offset:], off=disassembly_offset):
            self.x86_handle_lea_instruction(instruction=instruction,
                                            symbol_addresses=symbol_addresses)

    def _is_required(self, shellcode_data):
        self.init(shellcode_data=shellcode_data)

        if self.symbol_fixes:
            return True
        return False

    def _analyze(self, shellcode_data):
        for off, symbol_object in self.symbol_fixes.items():
            sym_name, address, _ = symbol_object
            relative_address = self.shelf.make_relative(address)
            self.logger.info("Instruction fixup for symbol: {} at: {}, with: {}".format(
                sym_name,
                off,
                address
            ))
            self.shelf.add_to_relocation_table(
                off, relative_address
            )

        return shellcode_data