from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
import struct


class MipsShellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian):
        super(MipsShellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_mips.shellcode",
            mini_loader_big_endian="mini_loader_mipsbe.shellcode",
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I"
        )

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


mips_make_shellcode = create_make_shellcode(MipsShellcode)
