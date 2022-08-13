import os

from elftools.elf.elffile import ELFFile
from elf_to_shellcode.resources import get_resource, get_resource_path
import struct
import sys
from elf_to_shellcode.lib.utils.address_utils import AddressUtils
from elf_to_shellcode.lib.consts import StartFiles, OUTPUT_FORMAT_MAP
from elf_to_shellcode.lib.utils.disassembler import Disassembler
from elf_to_shellcode.lib.ext.loader_symbols import ShellcodeLoader
from elf_to_shellcode.lib.ext.dynamic_symbols import DynamicRelocations
from elf_to_shellcode.arguments import ARGUMENTS
import logging
from elftools.elf.constants import P_FLAGS
from elf_to_shellcode.lib import five
import lief
import tempfile

PTR_SIZES = {
    4: "I",
    8: "Q"
}


class Shellcode(object):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger("[{}]".format(
            self.__class__.__name__
        ))
        self._args = args
        self._kwargs = kwargs

    def format_loader(self, ld):
        if StartFiles.no_start_files == ARGUMENTS.start_file_method:
            ld_base = ""
        elif StartFiles.glibc == ARGUMENTS.start_file_method:
            ld_base = "_glibc"
        else:
            raise Exception("Unknown start method: {}".format(
                ARGUMENTS.start_file_method
            ))
        features_map = sorted(ARGUMENTS.loader_supports, key=lambda lfeature: lfeature[1])
        for feature in features_map:
            value = getattr(self, "support_{}".format(feature))
            if not value:
                raise Exception("Arch does not support: {}".format(feature))
        loader_additional = "_".join([feature for feature in features_map])
        if loader_additional:
            loader_additional = "_" + loader_additional
        if self.args.output_format == OUTPUT_FORMAT_MAP.eshelf:
            loader_additional += "_eshelf"
        ld_name = ld.format(ld_base + loader_additional)

        self.logger.info("Using loader: {}".format(ld_name))
        return ld_name

    def make_absolute(self, address):
        return address + self.linker_base_address

    def add_relocation_handler(self, func):
        self.relocation_handlers.append(func)

    def pack(self, fmt, n):
        return struct.pack("{}{}".format(self.endian, fmt), n)

    def pack_pointer(self, n):
        return self.pack(self.ptr_fmt, n)

    def pack_list_of(self, lst, fmt):
        packed = five.py_obj()
        for item in lst:
            packed += self.pack(fmt, item)
        return packed

    def pack_list_of_pointers(self, lst):
        packed = five.py_obj()
        for item in lst:
            packed += self.pack_pointer(item)
        return packed

    def unpack_size(self, data, size):
        ptr_size = PTR_SIZES[size]
        return struct.unpack("{}{}".format(
            self.endian,
            ptr_size
        ), data)[0]

    @property
    def ptr_size(self):
        if self.ptr_fmt == "I":
            return 4
        if self.ptr_fmt == "Q":
            return 8
        raise Exception("Unknown ptr size")

    def sizeof(self, tp):
        if tp == "short":
            return 2
        else:
            raise NotImplementedError()

    @property
    def loader(self):
        if not self._loader:
            raise Exception("No loader for arch+endianes")
        assert self.pack_pointer(self.shellcode_table_magic) not in self._loader
        return self._loader

    @property
    def relocation_table(self):
        table = five.py_obj()

        for key, value in self.addresses_to_patch.items():
            if type(value) is not list:
                value = [value]

            value_packed = self.pack_list_of_pointers(value)

            relocation_entry = self.pack_pointer(key)
            relocation_entry += value_packed

            relocation_size = self.pack_pointer(len(relocation_entry) + self.ptr_size)
            relocation_entry = relocation_size + relocation_entry
            table += relocation_entry

        size_encoded = self.pack_pointer(len(table))
        return self.pack_pointer(self.shellcode_table_magic) + size_encoded + self.pre_table_header + table

    @property
    def pre_table_header(self):
        header = five.py_obj()
        sht_entry_header_size = 2 * self.sizeof("short")  # two shorts
        header += self.pack_pointer(
            self.elffile.header.e_ehsize + sht_entry_header_size
        )
        header += self.pack_pointer(len(self.loader))
        return header

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
                    self.logger.info("[R_SKIPPED]{}".format(hex(data_section_value)))
                    continue
                sym_offset = data_section_value - self.linker_base_address
                if sym_offset < 0:
                    continue
                symbol_relative_offset = data_section_start - data_section_header.sh_offset
                virtual_offset = data_section_header.sh_addr - self.linker_base_address
                virtual_offset += symbol_relative_offset
                self.logger.info("|{}| Relative(*{}={}), Absolute(*{}={})".format(
                    section_name,
                    hex(virtual_offset),
                    hex(sym_offset),
                    hex(self.make_absolute(virtual_offset)),
                    hex(self.make_absolute(sym_offset)),
                ))
                self.addresses_to_patch[virtual_offset] = sym_offset

        return shellcode_data

    def do_objdump(self, data):
        new_binary = five.py_obj()
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                segment_size = header.p_memsz
                start = (header.p_vaddr - self.linker_base_address)
                end = start + segment_size
                f_start = header.p_offset
                f_end = f_start + header.p_filesz
                assert f_end <= len(data), "Error segment offset outside of data: {} {}".format(
                    hex(f_end),
                    hex(len(data))
                )
                # first we make sure this part is already filled
                new_binary = five.ljust(new_binary, end, b'\x00')
                segment_data = data[f_start:f_end]

                # Now we rewrite the segment data
                # We look at new binary as memory dump so we write using virtual addresses offsets
                new_binary = new_binary[:start] + segment_data + new_binary[start + len(segment_data):]
        return new_binary  # TODO check if the elf header is really required

    @property
    def instruction_offset_after_objdump(self):
        # This function return the offset for the first executable section
        min_s = 2 ** 32
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                if header.p_flags & P_FLAGS.PF_X:
                    min_s = min(min_s, header.p_offset)
        assert min_s != 2 ** 32
        return min_s

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

    @property
    def args(self):
        return sys.modules["global_args"]

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
        if self.args.output_format == OUTPUT_FORMAT_MAP.eshelf:
            return self.build_eshelf(

                relocation_table=relocation_table,
                shellcode_header=shellcode_header,
                shellcode_data=shellcode_data
            )

        full_header = self.loader + relocation_table + shellcode_header
        if self.args.save_without_header:
            self.logger.info("Saving without shellcode table")
            return shellcode_data
        else:
            return self.build_shellcode_from_header_and_code(full_header, shellcode_data)

    def build_eshelf(self, relocation_table, shellcode_header, shellcode_data):
        shellcode_data = relocation_table + shellcode_header + shellcode_data
        loader = lief.parse(self.loader_path)
        segment = lief.ELF.Segment()
        segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        rwx = lief.ELF.SEGMENT_FLAGS(lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W | lief.ELF.SEGMENT_FLAGS.X)
        segment.flags = rwx
        segment.content = bytearray(shellcode_data)
        segment = loader.add(segment)
        tmp_path = tempfile.mktemp(".out")
        elf_buffer = None
        try:
            loader.write(tmp_path)
            with open(tmp_path, "rb") as fp:
                elf_buffer = fp.read()
        except Exception as e:
            self.logger.error("Error: {}".format(e))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        assert elf_buffer is not None, "Error"
        loader_symbol_address = self.loader.find(self.pack_pointer(0xdeadbeff))
        assert loader_symbol_address == self.loader.rfind(self.pack_pointer(0xdeadbeff)), "Error found more then one " \
                                                                                          "occurrence"
        self.logger.info("Setting shellcode base address at: {}".format(
            hex(segment.virtual_address)
        ))
        shellcode_start = self.pack_pointer(segment.virtual_address)
        elf_buffer_with_address = elf_buffer[:loader_symbol_address]
        elf_buffer_with_address += shellcode_start
        elf_buffer_with_address += elf_buffer[loader_symbol_address + self.ptr_size:]
        return elf_buffer_with_address

    def make_relative(self, address):
        return address - self.linker_base_address

    def unpack_ptr(self, stream):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt), stream[:self.ptr_size])[0]

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
        current_offset += len(self.pre_table_header)

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


def get_shellcode_class(elf_path, shellcode_cls, endian,
                        start_file_method):
    fd = open(elf_path, 'rb')
    elffile = ELFFile(fd)
    with open(elf_path, "rb") as fp:
        shellcode_data = fp.read()
    shellcode = shellcode_cls(elffile=elffile,
                              shellcode_data=shellcode_data,
                              endian=endian,
                              start_file_method=start_file_method)
    return shellcode, fd


def make_shellcode(elf_path, shellcode_cls, endian,
                   start_file_method):
    shellcode, fd = get_shellcode_class(elf_path, shellcode_cls, endian,
                                        start_file_method=start_file_method)
    args = sys.modules["global_args"]
    if args.interactive:
        print("Opening interactive shell")
        import IPython
        IPython.embed()
        sys.exit(1)
    shellcode = shellcode.get_shellcode()

    fd.close()
    return shellcode


def create_make_shellcode(shellcode_cls):
    def wrapper(elf_path, endian, start_file_method):
        return make_shellcode(elf_path, shellcode_cls, endian,
                              start_file_method=start_file_method)

    return wrapper


def not_supported_yet():
    def wrapper(elf_path, endian):
        raise Exception("Arch not supported yet")

    return wrapper
