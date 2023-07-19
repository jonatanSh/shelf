from shelf.lib.consts import MemoryProtection


class MemorySection(object):
    def __init__(self, v_start, start, f_start, f_end, vsize, vsize_aligned, size, protection):
        self.v_start = v_start
        self.start = start
        self.vsize_aligned = vsize_aligned
        self.vsize = vsize
        self.f_start = f_start
        self.f_end = f_end
        self.size = size
        self.memory_protection = protection
