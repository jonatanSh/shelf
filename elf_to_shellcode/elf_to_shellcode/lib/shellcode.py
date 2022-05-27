from elftools.elf.elffile import ELFFile
from elf_to_shellcode.elf_to_shellcode.resources import get_resource
import struct
import sys

py_version = int(sys.version[0])
assert py_version == 2, "Python3 is not supported for now :("


class Shellcode(object):
    def __init__(self, elffile, shellcode_data, endian,
                 mini_loader_big_endian,
                 mini_loader_little_endian,
                 shellcode_table_magic,
                 ptr_fmt,
                 sections_to_relocate={},
                 ext_bindings=[]):
        self.elffile = elffile
        self.shellcode_table_magic = shellcode_table_magic
        # Key is the file offset, value is the offset to correct to
        self.addresses_to_patch = {}
        assert endian in ["big", "little"]
        self._loader = None  # Default No loader is required
        self.sections_to_relocate = sections_to_relocate

        if endian == "big":
            self.endian = ">"
            if mini_loader_big_endian:
                self._loader = get_resource(mini_loader_big_endian)
        else:
            if mini_loader_little_endian:
                self._loader = get_resource(mini_loader_little_endian)
            self.endian = "<"
        self.shellcode_data = shellcode_data
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                self.linker_base_address = segment.header.p_vaddr
                break
        self.ptr_fmt = ptr_fmt
        self.relocation_handlers = []

        for binding in ext_bindings:
            get_binding, arguments = binding[0], binding[1]
            self.add_relocation_handler(get_binding(*arguments))

    def add_relocation_handler(self, func):
        self.relocation_handlers.append(func)

    def pack(self, fmt, n):
        return struct.pack("{}{}".format(self.endian, fmt), n)

    def pack_pointer(self, n):
        return self.pack(self.ptr_fmt, n)

    def pack_list_of_pointers(self, lst):
        packed = ""
        for item in lst:
            packed += self.pack_pointer(item)
        return packed

    @property
    def ptr_size(self):
        if self.ptr_fmt == "I":
            return 4
        if self.ptr_fmt == "Q":
            return 8
        raise Exception("Unknown ptr size")

    @property
    def loader(self):
        if not self._loader:
            raise Exception("No loader for arch+endianes")
        assert self.pack_pointer(self.shellcode_table_magic) not in self._loader
        return self._loader

    @property
    def relocation_table(self):
        table = ""

        for key, value in self.addresses_to_patch.items():
            if type(value) is not list:
                value = [value]

            value_packed = self.pack_list_of_pointers(value)

            relocation_entry = "".join([str(v) for v in struct.pack("{0}{1}".format(self.endian,
                                                                                    self.ptr_fmt), key)])
            relocation_entry += value_packed

            relocation_size = self.pack_pointer(len(relocation_entry) + self.ptr_size)
            relocation_entry = relocation_size + relocation_entry
            table += relocation_entry

        size_encoded = "".join([str(v) for v in struct.pack("{}{}".format(self.endian,
                                                                          self.ptr_fmt), len(table))])
        return self.pack_pointer(self.shellcode_table_magic) + size_encoded + table

    def correct_symbols(self, shellcode_data):
        for section, attributes in self.sections_to_relocate.items():
            self.section_build_relocations_table(
                section_name=section,
                align_attr=attributes['align_by'],
                relocate_all=attributes.get("relocate_all", False),
                shellcode_data=shellcode_data
            )
        return shellcode_data

    def section_build_relocations_table(self, section_name, align_attr, relocate_all, shellcode_data):
        data_section = self.elffile.get_section_by_name(section_name)
        original_symbol_addresses = self.get_original_symbols_addresses()
        if data_section:
            data_section_header = data_section.header

            for data_section_start in range(data_section_header.sh_offset,
                                            data_section_header.sh_offset + data_section_header.sh_size,
                                            self.ptr_size):
                data_section_end = data_section_start + self.ptr_size
                data_section_value = \
                    struct.unpack("{}{}".format(self.endian, self.ptr_fmt),
                                  shellcode_data[data_section_start:data_section_end])[0]
                if data_section_value not in original_symbol_addresses and not relocate_all:
                    continue
                sym_offset = data_section_value - self.linker_base_address
                if sym_offset < 0:
                    continue
                symbol_relative_offset = data_section_start - data_section_header.sh_offset
                virtual_offset = data_section_header.sh_addr - self.linker_base_address
                virtual_offset += symbol_relative_offset

                self.addresses_to_patch[virtual_offset] = sym_offset

        return shellcode_data

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

    def get_original_symbols_addresses(self):
        symtab = self.elffile.get_section_by_name(".symtab")
        addresses = []
        for sym in symtab.iter_symbols():
            address = sym.entry.st_value
            if address >= self.linker_base_address:
                addresses.append(address)

        return addresses

    def get_symbol_name_from_address(self, address):

        symtab = self.elffile.get_section_by_name(".symtab")
        for sym in symtab.iter_symbols():
            sym_address = sym.entry.st_value
            if sym_address == address:
                return sym.name

        return None

    def get_shellcode_header(self):
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.linker_base_address)
        return struct.pack("{}{}".format(self.endian, self.ptr_fmt), new_entry_point)

    def build_shellcode_from_header_and_code(self, header, code):
        return header + code

    def get_shellcode(self):
        shellcode_data = self.shellcode_data
        shellcode_header = self.get_shellcode_header()
        shellcode_data = self.correct_symbols(shellcode_data)
        for handler in self.relocation_handlers:
            shellcode_data = handler(shellcode=self,
                                     shellcode_data=shellcode_data)
        shellcode_data = self.do_objdump(shellcode_data)
        # This must be here !
        relocation_table = self.relocation_table

        full_header = str(self.loader) + str(relocation_table) + str(shellcode_header)

        return self.build_shellcode_from_header_and_code(full_header, shellcode_data)

    def unpack_ptr(self, stream):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt), stream)[0]

    def stream_unpack_pointers(self, stream, num_of_ptrs):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt * num_of_ptrs), stream[:self.ptr_size * num_of_ptrs])

    def get_loader_base_address(self, shellcode):
        loader_size = len(self.loader)
        table_length = len(self.relocation_table)
        offset = loader_size + table_length
        return self.unpack_ptr(shellcode[offset:offset + self.ptr_size])

    def set_loader_base_address(self, shellcode, new_base_address):
        loader_size = len(self.loader)
        table_length = len(self.relocation_table)
        offset = loader_size + table_length
        shellcode = shellcode[:offset] + self.pack_pointer(new_base_address) + shellcode[offset + self.ptr_size:]
        return shellcode

    def move_header_by_offset(self, header, offset):
        """
        This function move the shellcode header by offset.
        It actually parse the shellcode just like the loader and correct the offsets
        :param shellcode_data:
        :param offset:
        :return:
        """
        current_offset = 0
        loader_size = len(self.loader)
        # Skipping the loader
        current_offset += loader_size
        magic = self.unpack_ptr(header[current_offset:current_offset + self.ptr_size])
        assert magic == self.shellcode_table_magic, 'Error reading magic'
        current_offset += self.ptr_size  # skipping magic
        table_size = self.unpack_ptr(header[current_offset:current_offset + self.ptr_size])
        current_offset += self.ptr_size  # skip ptr size

        handled_size = 0
        while handled_size < table_size:
            size, voff1, voff2 = self.stream_unpack_pointers(
                header[current_offset:],
                3
            )
            voff1 += offset
            voff2 += offset
            voff1 = self.pack_pointer(voff1)
            voff2 = self.pack_pointer(voff2)
            header_next = header[current_offset + self.ptr_size * 3:]
            header = header[:current_offset + self.ptr_size] + voff1 + voff2 + header_next

            current_offset += size
            handled_size += size
        entry_point = self.unpack_ptr(header[current_offset:current_offset + self.ptr_size])
        entry_point += offset
        entry_point = self.pack_pointer(entry_point)
        header = header[:current_offset] + entry_point + header[current_offset + self.ptr_size:]
        return header


def get_shellcode_class(elf_path, shellcode_cls, endian):
    fd = open(elf_path, 'rb')
    elffile = ELFFile(fd)
    with open(elf_path, "rb") as fp:
        shellcode_data = fp.read()
    shellcode = shellcode_cls(elffile=elffile, shellcode_data=shellcode_data, endian=endian)
    return shellcode, fd


def make_shellcode(elf_path, shellcode_cls, endian):
    shellcode, fd = get_shellcode_class(elf_path, shellcode_cls, endian)
    shellcode = shellcode.get_shellcode()
    fd.close()
    return shellcode


def create_make_shellcode(shellcode_cls):
    def wrapper(elf_path, endian):
        return make_shellcode(elf_path, shellcode_cls, endian)

    return wrapper


def not_supported_yet():
    def wrapper(elf_path, endian):
        raise Exception("Arch not supported yet")

    return wrapper
