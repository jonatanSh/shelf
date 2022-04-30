from elftools.elf.elffile import ELFFile
from elf_to_shellcode.elf_to_shellcode.resources import get_resource
import struct
import sys

py_version = int(sys.version[0])
assert py_version == 2, "Python3 is not supported for now :("


class Shellcode(object):
    def __init__(self, elffile, shellcode_data, endian):
        self.elffile = elffile
        self.shellcode_table_magic = 0xaabbccdd
        # Key is the file offset, value is the offset to correct to
        self.addresses_to_patch = {}
        assert endian in ["big", "little"]
        if endian == "big":
            self.endian = ">"
            self._loader = get_resource("mini_loader_mipsbe.shellcode")
        else:
            self._loader = get_resource("mini_loader_mips.shellcode")
            self.endian = "<"
        self.shellcode_data = shellcode_data
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                self.linker_base_address = segment.header.p_vaddr
                break

    @property
    def loader(self):
        loader = self._loader
        idx = struct.pack("{}I".format(self.endian), self.shellcode_table_magic)
        idx = loader.find(idx) + 4
        return loader[:idx]

    @property
    def relocation_table(self):
        size = len(self.addresses_to_patch) - 1  # Because we count from 0
        table = "".join([str(v) for v in struct.pack("{}I".format(self.endian), size)])
        for key, value in self.addresses_to_patch.items():
            table += "".join([str(v) for v in struct.pack("{}II".format(self.endian), key, value)])
        return table

    def got_find_symbol_address_by_value(self, symbol_value):
        got = self.elffile.get_section_by_name(".got")
        header = got.header
        assert header.sh_size % 4 == 0
        for i in range(header.sh_offset, header.sh_offset + header.sh_size, 4):
            value = struct.unpack("{}I".format(self.endian), self.shellcode_data[i:i + 4])[0]
            if value == symbol_value:
                return i

    def correct_symbols(self, shellcode_data):
        got = self.elffile.get_section_by_name(".got")
        data_rel_ro = self.elffile.get_section_by_name('.data.rel.ro')
        original_symbol_addresses = self.get_original_symbols_addresses()
        got_header = got.header
        assert got_header.sh_entsize == 4
        for got_sym_start in range(got_header.sh_offset, got_header.sh_offset + got_header.sh_size,
                                   got_header.sh_entsize):
            got_sym_end = got_sym_start + 4
            got_sym_value = struct.unpack("{}I".format(self.endian), shellcode_data[got_sym_start:got_sym_end])[0]
            sym_offset = got_sym_value - self.linker_base_address
            symbol_relative_offset = got_sym_start - got_header.sh_offset
            virtual_offset = got_header.sh_addr - self.linker_base_address
            virtual_offset += symbol_relative_offset
            if sym_offset < 0:
                continue
            self.addresses_to_patch[virtual_offset] = sym_offset
        if data_rel_ro:
            data_rel_ro_header = data_rel_ro.header

            for data_rel_sym_start in range(data_rel_ro_header.sh_offset,
                                            data_rel_ro_header.sh_offset + data_rel_ro_header.sh_size,
                                            data_rel_ro_header.sh_addralign):
                data_rel_sym_end = data_rel_sym_start + 4
                data_rel_sym_value = \
                    struct.unpack("{}I".format(self.endian), shellcode_data[data_rel_sym_start:data_rel_sym_end])[0]
                if data_rel_sym_value not in original_symbol_addresses:
                    continue
                sym_offset = data_rel_sym_value - self.linker_base_address
                if sym_offset < 0:
                    continue
                symbol_relative_offset = data_rel_sym_start - data_rel_ro_header.sh_offset
                virtual_offset = data_rel_ro_header.sh_addr - self.linker_base_address + data_rel_sym_start
                virtual_offset += symbol_relative_offset
                self.addresses_to_patch[virtual_offset] = sym_offset

        return shellcode_data

    def get_original_symbols_addresses(self):
        symtab = self.elffile.get_section_by_name(".symtab")
        addresses = []
        for sym in symtab.iter_symbols():
            address = sym.entry.st_value
            if address >= self.linker_base_address:
                addresses.append(address)

        return addresses

    def do_objdump(self, data):
        new_binary = ""
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                segment_size = header.p_memsz
                start = (header.p_vaddr - self.linker_base_address)
                end = start + segment_size
                f_start = header.p_offset
                f_end = f_start + header.p_filesz

                assert f_end <= len(data), "Error p_offset + p_filesz > len(data)"
                # first we make sure this part is already filled
                new_binary = new_binary.ljust(end, '\x00')
                segment_data = data[f_start:f_end]

                # Now we rewrite the segment data
                # We look at new binary as memory dump so we write using virtual addresses offsets
                new_binary = str(new_binary[:start]) + str(segment_data) + str(new_binary[start + len(segment_data):])
        return new_binary

    def get_new_symbol_address(self, symbol_name, new_base_address):
        symtab = self.elffile.get_section_by_name(".symtab")
        sym = symtab.get_symbol_by_name(symbol_name)
        if not sym:
            raise Exception("Symbol: {0} not found".format(symbol_name))
        assert len(sym) == 1, "Error more then one symbol with name: {0}".format(symbol_name)
        sym = sym[0]
        return (sym.entry.st_value - self.linker_base_address) + new_base_address

    def get_symbol_address_after_relocation(self, symbol_name, base_address):
        return self.get_new_symbol_address(symbol_name, base_address + len(self.get_shellcode_header(
            base_address
        )))

    def get_shellcode_header(self, dummy=False):
        # Fixing elf entry point
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.linker_base_address)
        return struct.pack("{}I".format(self.endian), new_entry_point)

    def get_shellcode(self):
        shellcode_data = self.shellcode_data
        shellcode_header = self.get_shellcode_header()
        shellcode_data = self.correct_symbols(shellcode_data)
        shellcode_data = self.do_objdump(shellcode_data)
        # This must be here !
        relocation_table = self.relocation_table

        shellcode_data = str(self.loader) + str(relocation_table) + str(shellcode_header) + str(shellcode_data)
        return shellcode_data


def get_shellcode_class(elf_path, endian):
    fd = open(elf_path, 'rb')
    elffile = ELFFile(fd)
    with open(elf_path, "rb") as fp:
        shellcode_data = fp.read()
    shellcode = Shellcode(elffile=elffile, shellcode_data=shellcode_data, endian=endian)
    return shellcode, fd


def relocate(elf_path, endian):
    shellcode, fd = get_shellcode_class(elf_path, endian)
    shellcode = shellcode.get_shellcode()
    fd.close()
    return shellcode


# Endian here doesn't really matter
def get_symbol_address(elf_path, symbol_name, base_address, endian="big"):
    shellcode, fd = get_shellcode_class(elf_path, endian=endian)
    sym = shellcode.get_symbol_address_after_relocation(symbol_name, base_address)
    fd.close()
    return sym
