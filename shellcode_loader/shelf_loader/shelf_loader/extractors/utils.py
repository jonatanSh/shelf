import subprocess
from shelf.api import ShelfApi


def extract_text_between(stream, start_s, end_s, times=-1,
                         rindex_start=False,
                         allow_end_on_terminated_string=False,
                         return_mapped=False):
    streams = []
    mapped = {}
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
            if allow_end_on_terminated_string:
                end = len(stream) - start
            else:
                raise Exception("Infinite loop detected: start_s={}, end_s={}, r_index_start={}".format(
                    start_s,
                    end_s,
                    rindex_start
                ))
        end += start
        original = stream[start - len(start_s):end - len(end_s)]
        sub = stream[start:end]
        stream = stream[end + len(end_s):]
        streams.append(sub)
        mapped[original] = sub
        if rindex_start:
            start = stream.rfind(start_s)
        else:
            start = stream.find(start_s)
        i += 1
    if return_mapped:
        assert times == -1
        return mapped
    if not streams:
        return []
    if times == 1:
        return streams[0]
    return streams


def extract_int16(stream, start, end):
    value = extract_text_between(stream, start, end,
                                 times=1)
    if value and type(value) is str:
        return int(value, 16)
    return


def extract_int10(stream, start, end):
    value = extract_text_between(stream, start, end, times=1)
    if value and type(value) is str:
        return int(value)
    return


class Binary(object):
    def __init__(self, binary_path, loading_address=None, **shelf_kwargs):
        self.binary_path = binary_path
        self.symbols = ""
        self.program_headers = ""
        self.load_and_get_binary_program_headers()
        self.load_and_get_binary_symbols()
        self.loading_address = loading_address
        self.shelf = ShelfApi(self.binary_path, **shelf_kwargs)

    def get_symbol(self, address):
        for symbol in self.shelf.shelf.find_symbols():
            name, s_address, size = symbol
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

    def translate_to_relative_off(self, address):
        loading_add = self.shelf.shelf.linker_base_address
        relative = address - self.loading_address
        return loading_add + relative

    def translate_to_relative_address(self, address):
        loading_add = self.shelf.shelf.loading_virtual_address
        relative = address - self.loading_address
        return loading_add + relative


def address_in_region(address, start, size):
    return start <= address <= start + size
