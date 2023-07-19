from shelf.hooks import ShelfPreRelocateWriteHook, ShelfPreCallingShellcodeMainHook, \
    ShelfPreRelocateExecuteHook
from shelf.hooks.builtin.change_memory_protection import MemoryProtectionHook, \
    MemoryProtectionDescriptor
from shelf.lib.consts import MemoryProtection
from shelf.lib.utils.memory_section import MemorySection


class PreExecuteHook(MemoryProtectionHook, ShelfPreRelocateExecuteHook):
    def __init__(self, *args, **kwargs):
        super(PreExecuteHook, self).__init__(
            descriptors=[MemoryProtectionDescriptor(
                protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value,
                size=8192)],
            *args, **kwargs)


class PreWriteHook(MemoryProtectionHook, ShelfPreRelocateWriteHook):
    def __init__(self, *args, **kwargs):
        super(PreWriteHook, self).__init__(
            descriptors=[MemoryProtectionDescriptor(
                protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_WRITE.value,
                size=8192)], *args, **kwargs)


class PreCallMain(MemoryProtectionHook, ShelfPreCallingShellcodeMainHook):
    def __init__(self, shellcode, *args, **kwargs):
        segments = shellcode.get_segments_in_memory()
        descriptors = [
            MemoryProtectionDescriptor(
                protection=MemoryProtection.PROT_READ.value | MemoryProtection.PROT_EXEC.value,
                size=shellcode.post_build_length)
        ]
        for segment in segments:
            assert isinstance(segment, MemorySection)
            descriptors.append(
                MemoryProtectionDescriptor(
                    protection=segment.memory_protection,
                    size=segment.vsize_aligned,
                    address=segment.start,
                )
            )
        super(PreCallMain, self).__init__(shellcode=shellcode,
                                          descriptors=descriptors, *args, **kwargs)
