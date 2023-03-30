from shelf.hooks import Arches, ArchEndians
from shelf.resources import get_resource_path


class MemoryProtectionDescriptor(object):
    def __init__(self, protection, size, address=0x0):
        self.protection = protection
        self._size = size
        self.address = address

    @property
    def size(self):
        return self._size


class MemoryProtectionHook(object):
    def __init__(self, descriptors, *args, **kwargs):
        self.descriptors = descriptors
        super(MemoryProtectionHook, self).__init__(*args, **kwargs)

    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(endian, ArchEndians)
        return get_resource_path("resource_{0}_mem_change_protection_hook.hook".format(arch.value))

    def calc_size(self):
        raise NotImplemented("Error either size or calc size should be implemented")

    def hook_get_attributes(self):
        obj = self.shellcode.address_utils.pack_pointer(len(self.descriptors))
        for descriptor in self.descriptors:
            obj += self.shellcode.address_utils.pack_pointers(
                descriptor.protection,
                descriptor.size,
                descriptor.address
            )
        return obj
