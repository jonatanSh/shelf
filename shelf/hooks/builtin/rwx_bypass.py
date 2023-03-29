from shelf.hooks import ShelfPreRelocateWriteHook, ShelfPreCallingShellcodeMainHook, \
    ShelfPreRelocateExecuteHook
from shelf.hooks.builtin.change_memory_protection import MemoryProtectionHook, \
    MemoryProtectionDescriptor
from shelf.lib.consts import MemoryProtection


class PreExecuteHook(MemoryProtectionHook, ShelfPreRelocateExecuteHook):
    def __init__(self, *args, **kwargs):
        super(PreExecuteHook, self).__init__(
            descriptors=[MemoryProtectionDescriptor(
                protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value,
                size=4096)],
            *args, **kwargs)


class PreWriteHook(MemoryProtectionHook, ShelfPreRelocateWriteHook):
    def __init__(self, *args, **kwargs):
        super(PreWriteHook, self).__init__(
            descriptors=[MemoryProtectionDescriptor(
                protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_WRITE.value,
                size=4096)], *args, **kwargs)


class PreCallMain(MemoryProtectionHook, ShelfPreCallingShellcodeMainHook):
    def __init__(self, shellcode, *args, **kwargs):
        super(PreCallMain, self).__init__(shellcode=shellcode,
                                          descriptors=[MemoryProtectionDescriptor(
                                              protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value,
                                              size=shellcode.post_build_length)], *args, **kwargs)
