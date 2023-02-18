from copy import deepcopy
class HookTypes(object):
    STARTUP_HOOKS = 1


class ShellcodeHooks(object):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self._shellcode_hooks_descriptor_cls = self.shellcode.mini_loader.structs.mini_loader_hooks_descriptor
        self._startup_hooks = []

    def _add_hook(self, relative_address, hook_type):
        hook = self.shellcode.mini_loader.structs.hook(relative_address=relative_address)

        if hook_type == HookTypes.STARTUP_HOOKS:
            self._startup_hooks.append(hook)

        else:
            raise NotImplementedError("Error hook type: {}".format(hook_type))

    def add_startup_hook(self, relative_address):
        self._add_hook(relative_address, HookTypes.STARTUP_HOOKS)

    def _pad_list(self, plst):
        lst = deepcopy(plst)
        while len(lst) < self._shellcode_hooks_descriptor_cls.size / self.shellcode.ptr_size:
            lst.append(0x0)
        return lst

    @property
    def startup_hooks(self):
        return self._pad_list(self._startup_hooks)

    @property
    def shellcode_hooks_descriptor(self):
        return self._shellcode_hooks_descriptor_cls(
            startup_hooks=self.startup_hooks
        )
