from elf_to_shellcode.hooks import Arches, ArchEndians, MemoryProtection
from elf_to_shellcode.resources import get_resource_path


class MemoryProtecitonHook(object):
    def __init__(self, protection, size=None, *args, **kwargs):
        self.protection = protection
        self.size = size
        super(MemoryProtecitonHook, self).__init__(*args, **kwargs)

    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(endian, ArchEndians)
        return get_resource_path("resource_{0}_mem_change_protection_hook.hook".format(arch.value))

    def calc_size(self):
        raise NotImplemented("Error either size or calc size should be implemented")

    def hook_get_attributes(self):
        size = self.size
        if not size:
            size = self.calc_size()
        return self.shellcode.address_utils.pack_pointers(
            self.protection,
            size
        )
