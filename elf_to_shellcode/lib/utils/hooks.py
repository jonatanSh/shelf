from copy import deepcopy
from elf_to_shellcode.lib.five import array_join, is_python3
import logging


class HookTypes(object):
    STARTUP_HOOKS = 1


class ShellcodeHooks(object):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.number_of_hooks_per_descriptor = 1
        self._shellcode_hooks_descriptor_cls = self.shellcode.mini_loader.structs.mini_loader_hooks_descriptor
        self._startup_hooks = []
        self._hooks_shellcode_data = []

    def _add_hook(self, shellcode_data, hook_type):
        """
        Adding all hooks relative to the end of the relocations
        :param shellcode_data:
        :return:
        """
        relative_to_relocation_end = len(self._hooks_shellcode_data)
        self._hooks_shellcode_data.append(shellcode_data)
        hook = self.shellcode.mini_loader.structs.hook(relative_address=relative_to_relocation_end)

        logging.info("Adding hook shellcode, type: {} size: {}".format(
            hook_type,
            len(shellcode_data)
        ))
        if hook_type == HookTypes.STARTUP_HOOKS:
            self._startup_hooks.append(hook)

        else:
            raise NotImplementedError("Error hook type: {}".format(hook_type))

    def add_startup_hook(self, shellcode_data):
        if is_python3:
            assert type(shellcode_data) is bytes
        self._add_hook(shellcode_data, HookTypes.STARTUP_HOOKS)

    def _pad_list(self, plst, cls):
        lst = deepcopy(plst)
        while len(lst) < self.number_of_hooks_per_descriptor:
            lst.append(cls())
        if self.number_of_hooks_per_descriptor:
            return lst[0]
        return lst

    @property
    def startup_hooks(self):
        return self._pad_list(self._startup_hooks, cls=self.shellcode.mini_loader.structs.hook)

    @property
    def shellcode_hooks_descriptor(self):
        return self._shellcode_hooks_descriptor_cls(
            size_of_hook_shellcode_data=len(self.get_hooks_data()),
            startup_hooks=self.startup_hooks
        )

    def get_hooks_data(self):
        return array_join(self._hooks_shellcode_data)

    def get_header(self):
        return self.shellcode_hooks_descriptor.pack()
