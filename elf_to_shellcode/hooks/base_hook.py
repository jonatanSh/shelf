from elf_to_shellcode.lib.consts import HookTypes, Arches, ArchEndians


class _BaseShelfHook(object):
    def __init__(self, hook_type,
                 shellcode):
        assert isinstance(hook_type, HookTypes)
        self.shellcode = shellcode

    def hook_get_attributes(self):
        return

    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(arch, ArchEndians)
        raise NotImplementedError()


class ShelfStartupHook(_BaseShelfHook):
    def __init__(self, *args, **kwargs):
        super(ShelfStartupHook, self).__init__(hook_type=HookTypes.STARTUP_HOOKS,
                                               *args, **kwargs)