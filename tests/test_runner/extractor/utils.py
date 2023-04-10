import subprocess


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
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.symbols = ""
        self.load_and_get_binary_symbols()

    def get_bytes_at_virtual_address(self, size, address):
        gdb_out = subprocess.check_output(
            'gdb -batch -ex "x/{}bx {}" "{}"'.format(size, hex(address), self.binary_path),
            shell=True
        )
        gdb_opcodes = "".join([chr(int(op, 16)) for op in gdb_out.split("\t") if op.startswith("0x") and len(op) == 4])
        return gdb_opcodes

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


def address_in_region(address, start, size):
    return start <= address <= start + size
