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
                 ptr_fmt):
        self.elffile = elffile
        self.shellcode_table_magic = shellcode_table_magic
        # Key is the file offset, value is the offset to correct to
        self.addresses_to_patch = {}
        assert endian in ["big", "little"]
        if endian == "big":
            self.endian = ">"
            self._loader = get_resource(mini_loader_big_endian)
        elif mini_loader_little_endian:
            self._loader = get_resource(mini_loader_little_endian)
            self.endian = "<"
        else:
            self._loader = None  # No loader is required
        self.shellcode_data = shellcode_data
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                self.linker_base_address = segment.header.p_vaddr
                break
        self.ptr_fmt = ptr_fmt

    @property
    def loader(self):
        if not self._loader:
            return ""
        loader = self._loader
        idx = struct.pack("{}I".format(self.endian), self.shellcode_table_magic)
        idx = loader.find(idx) + 4
        return loader[:idx]

    @property
    def relocation_table(self):
        size = len(self.addresses_to_patch) - 1  # Because we count from 0
        table = "".join([str(v) for v in struct.pack("{}{}".format(self.endian,
                                                                   self.ptr_fmt), size)])
        for key, value in self.addresses_to_patch.items():
            table += "".join([str(v) for v in struct.pack("{0}{1}{1}".format(self.endian,
                                                                             self.ptr_fmt,
                                                                             self.ptr_fmt), key, value)])
        return table

    def correct_symbols(self, shellcode_data):
        raise NotImplemented()

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

    def get_shellcode_header(self):
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.linker_base_address)
        return struct.pack("{}{}".format(self.endian, self.ptr_fmt), new_entry_point)

    def get_shellcode(self):
        shellcode_data = self.shellcode_data
        shellcode_header = self.get_shellcode_header()
        shellcode_data = self.correct_symbols(shellcode_data)
        shellcode_data = self.do_objdump(shellcode_data)
        # This must be here !
        relocation_table = self.relocation_table

        shellcode_data = str(self.loader) + str(relocation_table) + str(shellcode_header) + str(shellcode_data)
        return shellcode_data


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
