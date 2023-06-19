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
        self.elf_header_size = -1
        self.shelf_version = None
        self.shelf_features = None
        self.find_mini_loader()

    @property
    def shelf_base_address(self):
        return self.loading_address + self._shelf_base_address_offset

    def is_address_in_mini_loader(self, address):
        # Check and returns if and address is inside the mini loader
        return address < self.shelf_base_address

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
        rstruct = self.plugin.shelf.mini_loader.structs.relocation_table
        relocation_table = rstruct(
            self.memory_dump[self.mini_loader_start_index: self.mini_loader_start_index + rstruct.size]
        )
        is_hooks, is_dynamic = (False, False)
        self.shelf_features = (relocation_table.version_and_fatures & ((2 ** 16) - 1))
        _version = (relocation_table.version_and_fatures >> 16)
        if self.shelf_features & consts.ShelfFeatures.HOOKS.value:
            is_hooks = True

        if self.shelf_features & consts.ShelfFeatures.DYNAMIC.value:
            is_dynamic = True

        self.shelf_version = _version / 100.0

        logging.info("Found table: {}"
                     "is_dynamic: {}, is_hooks: {}, version: {}\n".format(
            relocation_table,
            is_dynamic,
            is_hooks,
            self.shelf_version
        ))
        # 6 Elements in the header
        table_struct_size = self.plugin.shelf.mini_loader.structs.relocation_table.size

        self._shelf_base_address_offset = relocation_table.total_size + relocation_table.header_size
        self._shelf_base_address_offset += relocation_table.padding
        self._shelf_base_address_offset += relocation_table.elf_information.loader_size + table_struct_size

        if is_hooks:
            pass
            # self._shelf_base_address_offset += relocation_table.hook_descriptor.size_of_hook_shellcode_data
            # hooks = [
            #     relocation_table.hook_descriptor.startup_hooks,
            #     relocation_table.hook_descriptor.pre_relocate_write_hooks,
            #     relocation_table.hook_descriptor.pre_relocate_execute_hooks,
            #     relocation_table.hook_descriptor.pre_calling_shellcode_main_hooks,
            #
            # ]
            # for hook in hooks:
            #     if type(hook) is not list:
            #         hook = [hook]
            #     for hook_attribute in hook:
            #         self._shelf_base_address_offset += hook_attribute.shellcode_size

        # This is a quick fix until hook support is added
        self._shelf_base_address_offset = self._shelf_base_address_offset + self.memory_dump[
                                                                            self._shelf_base_address_offset:].find(
            b"\x7fELF")
        elf_magic = self.memory_dump[self._shelf_base_address_offset:self._shelf_base_address_offset + 4]
        assert elf_magic == b'\x7fELF', 'Error invalid elf magic !: {}'.format(elf_magic)

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
        if not offset:
            # Because the mini loader has the relocation will force
            # Capstone to stop disassemble the opcodes
            if not self.is_address_in_mini_loader(mark):
                first_exec_section_off = self.plugin.shelf.get_first_section(
                    check_x=True,
                )
                offset = self._shelf_base_address_offset + first_exec_section_off

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

    def convert_to_shelf_address(self, address):
        """
        Get address from the memory dump and convert it into a shelf relative address
        :param address:
        :return:
        """
        if not self.found_mini_loader:
            raise exceptions.MiniLoaderNotFound()
        assert address > self.shelf_base_address
        return address - self.shelf_base_address

    def convert_to_memory_absolute_address(self, relative_address):
        """
        Doing the exact revese operation from convert to shelf address
        This function gets a relative_address and return absolute address in memory
        :param relative_address:
        :return:
        """
        if not self.found_mini_loader:
            raise exceptions.MiniLoaderNotFound()

        return relative_address + self.shelf_base_address

    def find_symbol_at_address_in_shelf(self, address):
        """
        Find a symbol at address inside shelf
        :param address: The address in memory where the requested symbol is required
        :return: symbol name
        """
        return self._generic_find_symbol_at_address(
            address=self.convert_to_shelf_address(address),
        )

    def find_symbol_at_address_in_mini_loader(self, address):
        """
        Find a symbol at address inside shelf
        :param address: The address in memory where the requested symbol is required
        :return: symbol name
        """
        off = address - self.loading_address
        return self.plugin.shelf.mini_loader.get_relative_symbol_at_offset(
            off=off
        )

    def _generic_find_symbol_at_address(self, address):
        """
        Generic method to find symbol address
        :param address: the symbol address to find
        :return: symbol name
        """
        for symbol in self.plugin.shelf.find_symbols(return_relative_address=True):
            symbol_name, relative_symbol_address, symbol_size = symbol
            if relative_symbol_address <= address <= relative_symbol_address + symbol_size:
                return symbol_name

    def find_symbol_at_address(self, address, with_original=False):
        """
        Get address as input and find the correlated symbol inside shelf or the mini loader
        :param address: address
        :param with_original: Also return the original symbol name
        :return: symbol name
        """
        if self.is_address_in_mini_loader(address):
            original_name = self.find_symbol_at_address_in_mini_loader(
                address=address
            )
            sym = "MLOADER:{}".format(original_name)
        else:
            original_name = self.find_symbol_at_address_in_shelf(address)
            sym = "SHELF:{}".format(original_name)
        if with_original:
            return original_name, sym
        else:
            return sym

    def get_symbol_by_name(self, symbol_name=None):
        """
        Compute and return the symbol in memory
        :param symbol_name: the symbol to locate
        :return: SymbolObject(Tuple)
        """
        empty_symbol = (None, None, None)
        symbols_mapped = []
        symbols = self.plugin.shelf.find_symbols(
            return_relative_address=True, symbol_name=symbol_name
        )
        for symbol_object in symbols:
            sym_name, relative_symbol_address, symbol_size = symbol_object
            symbol_address = self.convert_to_memory_absolute_address(relative_symbol_address)
            if not symbol_name or symbol_name == sym_name:
                symbols_mapped.append((sym_name, symbol_address, symbol_size))

        for mini_loader_symbol_object in self.plugin.shelf.mini_loader.iterate_relative_symbols():
            sym_name, relative_symbol_address, symbol_size = mini_loader_symbol_object
            relative_symbol_address += self.loading_address
            symbols_mapped.append((sym_name, relative_symbol_address, symbol_size))

        if symbol_name:
            return empty_symbol if len(symbols_mapped) <= 0 else symbols_mapped[0]
        return symbols_mapped


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
