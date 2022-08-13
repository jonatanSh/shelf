import struct
import lief
import logging
from elftools.elf.elffile import ELFFile
from elf_to_shellcode.arguments import ARGUMENTS
from elf_to_shellcode.lib import five
from elf_to_shellcode.lib.consts import PTR_SIZES, ENDIAN_MAP
from elf_to_shellcode.lib.shelf.loader import ShellcodeLoader
from elf_to_shellcode.lib.shelf.shelf_header import ShelfHeader


class ShellcodeBase(object):
    def __init__(self, ptr_fmt, relocation_table_magic):
        self.loader = ShellcodeLoader()
        self.endian = ENDIAN_MAP[ARGUMENTS.endian]
        self.ptr_fmt = ptr_fmt
        self.fd = open(ARGUMENTS.input, 'rb')
        self.shellcode_data = self.fd.read()
        self.fd.seek(0)
        self.elffile = ELFFile(self.fd)
        self._base_address = None
        self.shelf_header = ShelfHeader(shellcode=self,
                                        magic=relocation_table_magic)
        self.lief_elf = lief.parse(ARGUMENTS.input)
        self.logger = logging.getLogger(self.__class__.__name__)

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

    def stream_unpack_pointers(self, stream, num_of_ptrs):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt * num_of_ptrs), stream[:self.ptr_size * num_of_ptrs])

    @property
    def base_address(self):
        if not self._base_address:
            self._base_address = self.locate_base_address()
        return self._base_address

    def locate_base_address(self):
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                return segment.header.p_vaddr

    def do_objdump(self):
        new_binary = five.py_obj()
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                segment_size = header.p_memsz
                start = (header.p_vaddr - self.base_address)
                end = start + segment_size
                f_start = header.p_offset
                f_end = f_start + header.p_filesz
                assert f_end <= len(self.shellcode_data), "Error segment offset outside of data: {} {}".format(
                    hex(f_end),
                    hex(len(self.shellcode_data))
                )
                # first we make sure this part is already filled
                new_binary = five.ljust(new_binary, end, b'\x00')
                segment_data = self.shellcode_data[f_start:f_end]

                # Now we rewrite the segment data
                # We look at new binary as memory dump so we write using virtual addresses offsets
                new_binary = new_binary[:start] + segment_data + new_binary[start + len(segment_data):]
        return new_binary  # TODO check if the elf header is really required

    def get_shelf(self):
        opcodes = self.do_objdump()
        header = self.shelf_header.shelf_get_header()
        return header + opcodes

    def get_shellcode(self):
        """
        Here support other output formats
        :return:
        """
        self.handle()
        shelf = self.get_shelf()
        return self.loader.bytes + shelf

    def handle(self):
        raise NotImplementedError()
