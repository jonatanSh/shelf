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

    def disassemble(self, mark=None):
        disassembly_object = self.plugin.shelf.disassembler.disassemble(
            opcodes=self.memory_dump,
            address=self.dump_address,
            mark=mark,
            binary_path=self.plugin.shelf.args.input
        )
        print(disassembly_object)



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
