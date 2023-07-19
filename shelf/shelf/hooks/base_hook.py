from shelf.lib.consts import HookTypes, Arches, ArchEndians


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


class ShelfPreRelocateWriteHook(_BaseShelfHook):
    def __init__(self, *args, **kwargs):
        super(ShelfPreRelocateWriteHook, self).__init__(hook_type=HookTypes.PRE_RELOCATE_WRITE_HOOKS,
                                                        *args, **kwargs)


class ShelfPreRelocateExecuteHook(_BaseShelfHook):
    def __init__(self, *args, **kwargs):
        super(ShelfPreRelocateExecuteHook, self).__init__(hook_type=HookTypes.PRE_RELOCATE_EXECUTE_HOOKS,
                                                          *args, **kwargs)


class ShelfPreCallingShellcodeMainHook(_BaseShelfHook):
    def __init__(self, *args, **kwargs):
        super(ShelfPreCallingShellcodeMainHook, self).__init__(hook_type=HookTypes.PRE_CALLING_MAIN_SHELLCODE_HOOKS,
                                                               *args, **kwargs)


class _BuiltinHookDescriptor(object):
    def __init__(self, path):
        self.path = path

    def add_support(self, args):
        return args
