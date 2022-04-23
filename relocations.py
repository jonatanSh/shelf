from elftools.elf.elffile import ELFFile
import struct


class Shellcode(object):
    def __init__(self, elffile, shellcode_data):
        self.elffile = elffile
        self.shellcode_data = shellcode_data
        self.linker_base_address = 0x0400000

    def got_find_symbol_address_by_value(self, symbol_value):
        got = self.elffile.get_section_by_name(".got")
        header = got.header
        assert header.sh_size % 4 == 0
        for i in xrange(header.sh_offset, header.sh_offset + header.sh_size, 4):
            value = struct.unpack(">I", self.shellcode_data[i:i + 4])[0]
            if value == symbol_value:
                return i

    def correct_symbols(self, shellcode_data, new_base_address):
        got = self.elffile.get_section_by_name(".got")
        data_rel_ro = self.elffile.get_section_by_name('.data.rel.ro')
        original_symbol_addresses = self.get_original_symbols_addresses()
        got_header = got.header
        assert got_header.sh_entsize == 4
        for got_sym_start in xrange(got_header.sh_offset, got_header.sh_offset + got_header.sh_size,
                                    got_header.sh_entsize):
            got_sym_end = got_sym_start + 4
            got_sym_value = struct.unpack(">I", shellcode_data[got_sym_start:got_sym_end])[0]
            new_offset = new_base_address + (got_sym_value - self.linker_base_address)

            if new_offset > 0xffffffff:
                pass
            else:
                shellcode_data = shellcode_data[:got_sym_start] + struct.pack(">I", new_offset) + shellcode_data[
                                                                                                  got_sym_end:]
        if data_rel_ro:
            data_rel_ro_header = data_rel_ro.header

            for data_rel_sym_start in xrange(data_rel_ro_header.sh_offset,
                                             data_rel_ro_header.sh_offset + data_rel_ro_header.sh_size,
                                             data_rel_ro_header.sh_addralign):
                data_rel_sym_end = data_rel_sym_start + 4
                data_rel_sym_value = struct.unpack(">I", shellcode_data[data_rel_sym_start:data_rel_sym_end])[0]
                if data_rel_sym_value not in original_symbol_addresses:
                    continue
                new_offset = new_base_address + (data_rel_sym_value - self.linker_base_address)

                if new_offset > 0xffffffff:
                    pass
                else:
                    shellcode_data = shellcode_data[:data_rel_sym_start] + struct.pack(">I",
                                                                                       new_offset) + shellcode_data[
                                                                                                     data_rel_sym_end:]

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
                new_binary = new_binary[:start] + segment_data + new_binary[start + len(segment_data):]
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

    def get_shellcode_header(self, new_base_address, dummy=False):
        # Fixing elf entry point
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.linker_base_address) + new_base_address
        header = ""
        # Building jump opcode
        nop = "\x00" * 4
        """
        Here the stub loads the address of main into t9, and create a call stub to the entry point
        The entry point and main can be different
        3C 19 12 34    lui $t9, 0x1234
        37 39 56 78    ori $t9, $t9, 0x5678
        3C 18 12 34    lui $t8, 0x1234
        37 18 56 78    ori $t8, $t8, 0x5678
        03 00 00 08 jr $t8
        """

        # This trick make sure we skip the header
        main_function_address = self.get_new_symbol_address("main", new_base_address)
        if not dummy:
            dummy_header = self.get_shellcode_header(new_base_address, dummy=True)
            new_entry_point += len(dummy_header)
            main_function_address += len(dummy_header)

        hi_entry = new_entry_point >> 16
        lw_entry = new_entry_point & 0xffff
        hi_main = main_function_address >> 16
        lw_main = main_function_address & 0xffff

        # use here endian from header
        header += "\x3c\x19" + struct.pack(">H", hi_main)
        header += "\x37\x39" + struct.pack(">H", lw_main)
        header += "\x3c\x18" + struct.pack(">H", hi_entry)
        header += "\x37\x18" + struct.pack(">H", lw_entry)
        header += "\x03\x00\x00\x08"
        header += nop

        return header

    def get_shellcode(self, new_base_address):
        shellcode_data = self.shellcode_data
        shellcode_header = self.get_shellcode_header(new_base_address)
        base_address_with_header = new_base_address + len(shellcode_header)
        shellcode_data = self.correct_symbols(shellcode_data, base_address_with_header)
        shellcode_data = self.do_objdump(shellcode_data)
        # This must be here !
        shellcode_data = shellcode_header + shellcode_data
        return shellcode_data


def get_shellcode_class(elf_path, new_base_address):
    assert new_base_address % 4 == 0, "Error invalid base address"
    fd = open(elf_path, 'rb')
    elffile = ELFFile(fd)
    with open(elf_path, "rb") as fp:
        shellcode_data = fp.read()
    shellcode = Shellcode(elffile=elffile, shellcode_data=shellcode_data)
    return shellcode, fd


def relocate(elf_path, new_base_address):
    shellcode, fd = get_shellcode_class(elf_path, new_base_address)
    shellcode = shellcode.get_shellcode(new_base_address)
    fd.close()
    return shellcode


def get_symbol_address(elf_path, symbol_name, base_address):
    shellcode, fd = get_shellcode_class(elf_path, base_address)
    sym = shellcode.get_symbol_address_after_relocation(symbol_name, base_address)
    fd.close()
    return sym
