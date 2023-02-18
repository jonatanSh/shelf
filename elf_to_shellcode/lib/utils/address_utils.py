import logging
import struct
from logging import getLogger
from elf_to_shellcode.lib import five


class AddressUtils(object):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.logger = getLogger(self.__class__.__name__)

    def section_get_ptr_at_address(self, section, address, alignment):
        """
        Return relative offset in section in essence of section offsets,
        eg ... MIPS got section has pointer alignment therefor if .got
        start at address 0x40000 and the address 0x400010 the returned value is 4
        because 0x10 = 16 / ptr_size = 4. and there are 4 pointer up to that address
        :param section: the section
        :param address: the address inside that section
        :param alignment: the section alignment, eg for got use got_plt.header.sh_entsize
        :return:
        """
        start = section.header.sh_addr
        end = start + section.header.sh_size
        assert address < end, 'Error, address: {} out of range'.format(address)
        index_start = address - start
        index_end = index_start + alignment

        return self.shellcode.address_utils.unsigned_unpack_size(
            size=alignment,
            data=section.data()[index_start:index_end]
        )

    def make_absolute(self, relative_address):
        """
        Return Absolute from relative address
        :param relative_address: relative address
        :return: address
        """
        return relative_address + self.shellcode.loading_virtual_address

    def pack(self, fmt, n):
        """
        Call struct pack in the endian of the input binary
        :param fmt: The format to use in struct packet
        :param n: the value to pack
        :return: Packed value
        """
        try:
            return struct.pack("{}{}".format(self.shellcode.endian, fmt), n)
        except Exception as e:
            logging.error("Pack exception: {} {} {}".format(self.shellcode.endian, fmt, n))
            raise e

    def pack_pointer(self, n):
        """
        Pack a pointer
        :param n: The value of pack
        :return: packed pointer
        """
        return self.pack(self.shellcode.ptr_fmt, n)

    def pack_list_of(self, fmt, *args):
        """
        Pack list of arguments
        :param fmt: the format to pack the list
        :param args: the arguments
        :return:
        """
        packed = five.py_obj()
        for item in args:
            packed += self.pack(fmt, item)
        return packed

    def pack_pointers(self, *pointers):
        """
        Pack list of pointers
        :param pointers: Pointers to pack
        :return: packed argument
        """
        return self.pack_list_of(
            self.shellcode.ptr_fmt,
            *pointers
        )

    def unsigned_unpack_size(self, data, size):
        """
        Unpack element in input shellcode endian
        :param data: data to unpack
        :param size: size to use while unpacking
        :return:
        """
        ptr_size = self.translate_ptr_size_to_struct_format_unsigned(size)
        return struct.unpack("{}{}".format(
            self.shellcode.endian,
            ptr_size
        ), data)[0]

    @staticmethod
    def translate_ptr_size_to_struct_format_unsigned(size):
        """
        Translate size into its unpacking format
        :param size: the size to translate
        :return:
        """
        return {
            4: "I",
            8: "Q"
        }[size]
