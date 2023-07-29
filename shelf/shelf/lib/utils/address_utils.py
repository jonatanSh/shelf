import logging
import struct
from logging import getLogger
from shelf.lib import five


class AddressUtils(object):
    def __init__(self, shellcode=None, ptr_fmt=None, endian=None):
        if not shellcode:
            assert all([ptr_fmt, endian]), "Error either shellcode or ptr format and endian must be supplied"
        self.shellcode = shellcode
        self.ptr_fmt = ptr_fmt if not shellcode else self.shellcode.ptr_fmt
        self.endian = endian if not shellcode else self.shellcode.endian
        self.ptr_size = struct.calcsize(self.ptr_fmt)
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

        return self.unsigned_unpack_size(
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
            return struct.pack("{}{}".format(self.endian, fmt), n)
        except Exception as e:
            logging.error("Pack exception: {} {} {}".format(self.endian, fmt, n))
            raise e

    def unpack(self, fmt, n):
        """
        Call struct pack in the endian of the input binary
        :param fmt: The format to use in struct packet
        :param n: the value to unpack
        :return: Packed value
        """
        try:
            return struct.unpack("{}{}".format(self.endian, fmt), n)
        except Exception as e:
            logging.error("Pack exception: {} {} {}".format(self.endian, fmt, n))
            raise e

    def pack_pointer(self, n):
        """
        Pack a pointer
        :param n: The value of pack
        :return: packed pointer
        """
        return self.pack(self.ptr_fmt, n)

    def signed_pack_pointer(self, n):
        """
        Pack a pointer
        :param n: The value of pack
        :return: packed pointer
        """
        return self.pack(self.ptr_fmt.lower(), n)

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
            self.ptr_fmt,
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
            self.endian,
            ptr_size
        ), data)[0]

    def unpack_pointers(self, stream, number_of_pointers):
        """
        Unpack list of pointers
        :param stream: Stream to unpack from
        :param number_of_pointers: number of pointers
        :return:
        """
        stream = stream[:self.ptr_size * number_of_pointers]
        return struct.unpack("{}{}".format(
            self.endian,
            self.ptr_fmt * number_of_pointers
        ), stream)

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

    def _align(self, data, direction, padding=b'\x00'):
        if len(data) % self.ptr_size == 0x0:
            return data
        alignment = len(data) + (self.ptr_size - (len(data) % self.ptr_size))
        if direction == 'left':
            return data.ljust(alignment, padding)
        elif direction == 'right':
            return data.rjust(alignment, padding)
        else:
            raise Exception("Padding error")

    def left_align(self, data, padding=b'\x00'):
        return self._align(data=data, direction="left", padding=padding)

    def right_align(self, data, padding=b'\x00'):
        return self._align(data=data, direction="right", padding=padding)

    @staticmethod
    def get_alignment(size, aligned):
        if size > aligned:
            return size + (aligned - (size % aligned))
        else:
            return aligned - size

    @classmethod
    def for_32_bit_little_endian(cls):
        return cls(
            endian="<",
            ptr_fmt="I"
        )

    @classmethod
    def for_32_bit_big_endian(cls):
        return cls(
            endian=">",
            ptr_fmt="I"
        )

    @classmethod
    def for_64_bit_little_endian(cls):
        return cls(
            endian="<",
            ptr_fmt="Q"
        )

    @classmethod
    def for_64_bit_big_endian(cls):
        return cls(
            endian=">",
            ptr_fmt="Q"
        )

    @staticmethod
    def twos_complement(num, num_bits):
        # Calculate the two's complement representation using int() with base conversion
        two_complement = (num + (1 << num_bits)) % (1 << num_bits)

        # Convert the result to binary representation and return it as a string
        return int(bin(two_complement)[2:].zfill(num_bits), 2)

    def __repr__(self):
        return "AddressUtils(endian={}, format={})".format(
            self.endian,
            self.ptr_fmt
        )
