from shelf.lib.consts import MemoryProtection


class MemorySection(object):
    def __init__(self, start, f_start, f_end, vsize, size, protection):
        self.start = start
        self.vsize = vsize
        self.f_start = f_start
        self.f_end = f_end
        self.size = size
        self.memory_protection = protection
