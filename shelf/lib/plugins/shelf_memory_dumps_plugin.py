"""
This plugin is used for debugging and analyzing memory dumps containing shelf shellcode
"""
import logging
from shelf.lib import exceptions
from shelf.lib import consts
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
        self.found_mini_loader = False
        self.mini_loader_start_index = -1
        self._base_address_offset = -1
        self.find_mini_loader()

    def find_mini_loader(self):
        """
        Parses the dump and finds the mini loader within the dump
        :return:
        """
        magic = self.plugin.shelf.address_utils.pack_pointer(self.plugin.shelf.shellcode_table_magic)
        self.mini_loader_start_index = self.memory_dump.find(magic)
        if self.mini_loader_start_index >= 0:
            self.found_mini_loader = True
            self._parse_relocation_table()

    def _parse_relocation_table(self):
        """
        This function parsers the mini loader header and calculate the base address offset within the dump
        :return:
        """
        is_hooks, is_dynamic = (False, False)
        magic, version_and_features, padding, total_size, header_size, \
        padding_between_table_and_loader, elf_header_size, loader_size = self.plugin.shelf.address_utils.unpack_pointers(
            self.memory_dump[self.mini_loader_start_index:],
            8
        )
        features = (version_and_features & ((2 ** 12) - 1))
        _version = (version_and_features >> 12)
        if features & consts.ShelfFeatures.HOOKS.value:
            is_hooks = True

        if features & consts.ShelfFeatures.DYNAMIC.value:
            is_dynamic = True

        version = float(_version >> 8)
        version += float((_version >> 4) & ((2 ** 4) - 1)) / 10
        version += float(_version & ((2 ** 4) - 1)) / 100

        logging.info("Found magic: {}, padding: {}, total_size: {},"
                     "is_dynamic: {}, is_hooks: {}, version: {}".format(
            magic,
            hex(padding),
            hex(total_size),
            is_dynamic,
            is_hooks,
            version
        ))
        # 6 Elements in the header
        table_struct_size = self.plugin.shelf.ptr_size * 6
        table_struct_size += self.plugin.shelf.mini_loader.structs.elf_information_struct.size
        table_struct_size += self.plugin.shelf.mini_loader.structs.loader_function_descriptor.size

        if is_hooks:
            table_struct_size += self.plugin.shelf.mini_loader.structs.mini_loader_hooks_descriptor.size

        self._base_address_offset = loader_size + table_struct_size + total_size + header_size + padding

    def disassemble(self, mark=None, limit=30,
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
        if mark:
            assert mark >= dump_address, "Error invalid mark address"
            assert mark - dump_address <= len(self.memory_dump[offset:]), "Error dump to small"
        symbol_name = self.find_symbol_at_address(dump_address)
        if mark:
            symbol_at_marked = self.find_symbol_at_address(mark)
        else:
            symbol_at_marked = ""
        disassembly_object = self.plugin.shelf.disassembler.disassemble(
            opcodes=self.memory_dump[offset:],
            address=dump_address,
            mark=mark,
            binary_path=self.plugin.shelf.args.input,
            limit=limit,
            symbol_name=symbol_name,
            symbol_at_marked=symbol_at_marked
        )
        print(disassembly_object)

    def compute_absolute_address(self, address):
        """
        Get address from the elf file and translate it to the absolute address in shelf
        This function only works if the mini loader was found inside the dump
        Eg ...
            matching_symbols = api.shelf.find_symbols(symbol_name='main')
            symbol_name, symbol_address, function_size = matching_symbols[0]
            absolute_address = dump.compute_absolute_address(symbol_address)
            print("Symbol in memory: {}".format(hex(absolute_address)))
        :param address:
        :return:
        """
        if not self.found_mini_loader:
            raise exceptions.MiniLoaderNotFound()

        relative_offset = self.plugin.shelf.convert_to_shelf_relative_offset(
            address=address
        )

        return self.loading_address + relative_offset + self._base_address_offset

    def find_symbol_at_address(self, address):
        """
        Find a symbol at address
        :param address: The address in memory where the requested symbol is required
        :return:
        """
        for symbol in self.plugin.shelf.find_symbols():
            symbol_name, symbol_address, symbol_size = symbol
            try:
                shelf_absolute = self.compute_absolute_address(address=symbol_address)
                if shelf_absolute <= address <= shelf_absolute + symbol_size:
                    return symbol_name
            except exceptions.AddressNotInShelf:
                continue
            except exceptions.MiniLoaderNotFound:
                return


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
