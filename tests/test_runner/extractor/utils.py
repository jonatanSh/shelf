import logging
import subprocess
from shelf.relocate import make_shellcode


def extract_text_between(stream, start_s, end_s, times=-1,
                         rindex_start=False):
    streams = []
    if rindex_start:
        start = stream.rfind(start_s)
    else:
        start = stream.find(start_s)

    i = 0
    while start >= 0 and i != times:
        start += len(start_s)
        if not end_s:
            end = len(stream) - start
        else:
            end = stream[start:].find(end_s)

        if end < 0:
            raise Exception("Infinite loop detected")
        end += start
        sub = stream[start:end]
        stream = stream[end + len(end_s):]
        streams.append(sub)
        if rindex_start:
            start = stream.rfind(start_s)
        else:
            start = stream.find(start_s)
        i += 1
    if not streams:
        return []
    if times == 1:
        return streams[0]
    return streams


def extract_int16(stream, start, end):
    value = extract_text_between(stream, start, end, times=1)
    if value and type(value) is str:
        return int(value, 16)
    return


class Binary(object):
    def __init__(self, binary_path, loading_address=None):
        self.binary_path = binary_path
        self.symbols = ""
        self.program_headers = ""
        self.load_and_get_binary_program_headers()
        self.load_and_get_binary_symbols()
        self.loading_address = loading_address

    def get_bytes_at_virtual_address(self, size, address):
        try:
            gdb_out = subprocess.check_output(
                'gdb -batch -ex "x/{}bx {}" "{}"'.format(size, hex(address), self.binary_path),
                shell=True
            )
            opcodes = []
            for line in gdb_out.split("\n"):
                for opcode in line.split("\t"):
                    if len(opcode) != 0x4:
                        continue
                    opcodes.append(chr(int(opcode, 16)))

            gdb_opcodes = "".join(opcodes)
            return gdb_opcodes
        except Exception as e:
            logging.error(e)
            return

    def get_symbol(self, address):
        for line in self.symbols.split("\n"):
            if not line:
                continue
            parts = [p for p in line.split(" ") if p]
            if len(parts) != 8:
                continue
            _, s_address, size, _, _, _, _, name = parts
            try:
                s_address = int(s_address, 16)
                size = int(size)
            except:
                pass

            if s_address <= address <= s_address + size:
                return name

        return ""

    def load_and_get_binary_symbols(self):
        try:
            self.symbols = subprocess.check_output(" ".join(["readelf", '-s', self.binary_path]), shell=True)
        except:
            self.symbols = ""

    def load_and_get_binary_program_headers(self):
        try:
            self.program_headers = subprocess.check_output(" ".join(["readelf", '-l', self.binary_path]), shell=True)
        except:
            self.program_headers = ""

    def get_virtual_loading_addresses(self):
        addresses = []
        for line in self.program_headers.split("\n"):
            if 'LOAD' in line:
                parts = [p.strip() for p in line.strip().split(" ") if p]
                _, off, virt, phys, filesize, memsize = parts[:6]
                virt = int(virt, 16)
                memsize = int(memsize, 16)
                addresses.append([virt, memsize])
        return addresses

    def in_region_of_loading_addresses(self, address):
        for obj in self.get_virtual_loading_addresses():
            add, size = obj
            if address_in_region(address=address, start=add, size=size):
                return True
        return False

    @property
    def shelf(self):
        shellcode, shellcode_repr = make_shellcode(arch=self.arch, endian=self.endian,
                                                   start_file_method=None, args=None)
        return shellcode

def address_in_region(address, start, size):
    return start <= address <= start + size
