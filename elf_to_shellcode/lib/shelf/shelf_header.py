from collections import OrderedDict
from elf_to_shellcode.lib import five


class ShelfHeader(object):
    def __init__(self, shellcode, magic):
        self.shellcode = shellcode
        self.magic = magic
        self._relocations = OrderedDict()

    def add_relocation(self, address, value, relocation_type=None):
        self._relocations[address] = [value, relocation_type]

    def _get_relocation_table(self):
        table = five.py_obj()
        for address, value in self._relocations.items():
            r_entry = [address] + value
            relocation_entry = self.shellcode.pack_list_of_pointers(r_entry)
            relocation_size = self.shellcode.pack_pointer(len(relocation_entry) + self.shellcode.ptr_size)
            relocation_entry = relocation_size + relocation_entry
            table += relocation_entry

        return table

    def _get_elf_information(self):
        sht_entry_header_size = 2 * self.shellcode.sizeof("short")  # two shorts
        elf_header_size = self.shellcode.elffile.header.e_ehsize + sht_entry_header_size
        elf_loader_size = len(self.shellcode.loader)

        return self.shellcode.pack_list_of_pointers([
            elf_header_size,
            elf_loader_size
        ])

    def shelf_get_header(self):
        table = self._get_relocation_table()
        struct_relocation_table = self.shellcode.pack_list_of_pointers([self.magic, len(table)])
        struct_elf_information = self._get_elf_information()
        header = struct_relocation_table + struct_elf_information + table

        return header
