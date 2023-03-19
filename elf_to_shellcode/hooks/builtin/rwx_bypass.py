from elf_to_shellcode.hooks import ShelfPreRelocateWriteHook, ShelfPreCallingShellcodeMainHook, \
    ShelfPreRelocateExecuteHook
from elf_to_shellcode.hooks.builtin.change_memory_protection import MemoryProtecitonHook, MemoryProtection


class PreExecuteHook(MemoryProtecitonHook, ShelfPreRelocateExecuteHook):
    def __init__(self, *args, **kwargs):
        super(PreExecuteHook, self).__init__(
            protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value,
            size=8192,
            *args, **kwargs)


class PreWriteHook(MemoryProtecitonHook, ShelfPreRelocateWriteHook):
    def __init__(self, *args, **kwargs):
        super(PreWriteHook, self).__init__(
            protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_WRITE.value,
            size=8192, *args, **kwargs)


class PreCallMain(MemoryProtecitonHook, ShelfPreCallingShellcodeMainHook):
    def __init__(self, *args, **kwargs):
        super(PreCallMain, self).__init__(
            protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value, *args, **kwargs)

    def calc_size(self):
        return self.shellcode.post_build_length
