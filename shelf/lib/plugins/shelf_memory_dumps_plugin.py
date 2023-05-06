import logging
from shelf.lib import exceptions
from shelf.lib.plugins.base_shelf_plugins import BaseShelfPlugin


class ShelfMemoryDump(object):
    def __init__(self, plugin,
                 memory_dump,
                 dump_address,
                 loading_address):
        self.plugin = plugin
        self.memory_dump = memory_dump
        self.dump_address = dump_address
        self.loading_address = loading_address

    def disassemble(self, mark=None, limit=-1,
                    offset=0x0):
        """
        Print disassembly representation of the memory dump
        :param mark: Mark certain address in the disassembly
            eg ... dump_address = 0x12340, mark=0x12344 and the size of a single opcode is 4 bytes
            Then > will be printed next to the second opcode
        :param limit: Limit the number of opcodes disassembled -1 = no limit
        :param offset: Offset to start disassemble from
            Eg ... if the binary was loaded at 0x12340 and offset is 4
            The disassembly output start from 0x12344
        :return:
        """
        dump_address = self.dump_address + offset
        symbol_name = self.find_symbol_at_address(dump_address)
        disassembly_object = self.plugin.shelf.disassembler.disassemble(
            opcodes=self.memory_dump[offset:],
            address=dump_address,
            mark=mark,
            binary_path=self.plugin.shelf.args.input,
            limit=limit,
            symbol_name=symbol_name
        )
        print(disassembly_object)

    def compute_absolute_address(self, address):
        """
        Get address from the elf file and translate it to the absolute address in shelf
        Eg ...
            matching_symbols = api.shelf.find_symbols(symbol_name='main')
            symbol_name, symbol_address, function_size = matching_symbols[0]
            absolute_address = dump.compute_absolute_address(symbol_address)
            print("Symbol in memory: {}".format(hex(absolute_address)))
        :param address:
        :return:
        """
        relative_offset = self.plugin.shelf.convert_to_shelf_relative_offset(
            address=address
        )

        return self.loading_address + relative_offset

    def find_symbol_at_address(self, address):
        """
        Find a symbol at address
        :param address: The address in memory where the requested symbol is reqruied
        :return:
        """
        for symbol in self.plugin.shelf.find_symbols():
            symbol_name, symbol_address, symbol_size = symbol
            try:
                shelf_relative = self.compute_absolute_address(address=symbol_address)
                if shelf_relative <= address <= shelf_relative + symbol_size:
                    return symbol_name
            except exceptions.AddressNotInShelf:
                continue


class MemoryDumpPlugin(BaseShelfPlugin):
    def construct_shelf_from_memory_dump(self,
                                         memory_dump,
                                         dump_address,
                                         loading_address):
        """
        If you gathered bytes from memory contains shelf object
        This function convert the bytes into a shelf object
        :param memory_dump: bytes extracted from memory
        :param dump_address: The address where the memory_dump (bytes) where taken
        :param loading_address: the loading address of shelf
        :return:
        """
        return ShelfMemoryDump(
            plugin=self,
            memory_dump=memory_dump,
            dump_address=dump_address,
            loading_address=loading_address
        )
