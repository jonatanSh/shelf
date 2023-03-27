from elf_to_shellcode.hooks import ShelfPreRelocateWriteHook, ShelfPreCallingShellcodeMainHook, \
    ShelfPreRelocateExecuteHook
from elf_to_shellcode.hooks.builtin.change_memory_protection import MemoryProtectionHook, \
    MemoryProtectionDescriptor
from elf_to_shellcode.lib.consts import MemoryProtection


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
