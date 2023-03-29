import logging
from copy import deepcopy
from shelf.lib import five
from shelf.lib.five import array_join, is_python3
from shelf.lib.consts import HookTypes


class ArchAlignedList(list):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        super(ArchAlignedList, self).__init__()

    def append(self, __object):
        super(ArchAlignedList, self).append(
            self.shellcode.address_utils.left_align(__object)
        )


class ShellcodeHooks(object):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.number_of_hooks_per_descriptor = 1
        self._shellcode_hooks_descriptor_cls = self.shellcode.mini_loader.structs.mini_loader_hooks_descriptor
        self._startup_hooks = []
        self._pre_relocate_write_hooks = []
        self._pre_relocate_execute_hooks = []
        self._pre_calling_shellcode_main_hooks = []
        self._hooks_shellcode_data = ArchAlignedList(shellcode=self.shellcode)

    def _add_hook(self, shellcode_data, hook_type, attributes):
        """
        Adding all hooks relative to the end of the relocations
        :param shellcode_data:
        :return:
        """
        if not attributes:
            attributes = five.py_obj()
        relative_to_relocation_end = len(self.get_hooks_data())
        shellcode_data = self.shellcode.address_utils.left_align(shellcode_data)
        self._hooks_shellcode_data.append(shellcode_data)
        self._hooks_shellcode_data.append(attributes)
        """
            We add 0xff to all hooks in order to extinguish between real hooks and null ones 
        """
        hook = self.shellcode.mini_loader.structs.hook(
            relative_address=relative_to_relocation_end+0xff,
            attributes_size=len(attributes),
            shellcode_size=len(shellcode_data),
        )

        logging.info("Adding hook shellcode, type: {} size: {}".format(
            hook_type,
            len(shellcode_data)
        ))
        if hook_type == HookTypes.STARTUP_HOOKS:
            self._startup_hooks.append(hook)
        elif hook_type == HookTypes.PRE_RELOCATE_WRITE_HOOKS:
            self._pre_relocate_write_hooks.append(hook)
        elif hook_type == HookTypes.PRE_RELOCATE_EXECUTE_HOOKS:
            self._pre_relocate_execute_hooks.append(hook)
        elif hook_type == HookTypes.PRE_CALLING_MAIN_SHELLCODE_HOOKS:
            self._pre_calling_shellcode_main_hooks.append(hook)
        else:
            raise NotImplementedError("Error hook type: {}".format(hook_type))

    def add_hook(self, shellcode_data, hook_type, attributes=None):
        if is_python3:
            assert type(shellcode_data) is bytes
        self._add_hook(shellcode_data, hook_type, attributes=attributes)

    def _pad_list(self, plst, cls):
        lst = deepcopy(plst)
        while len(lst) < self.number_of_hooks_per_descriptor:
            lst.append(cls())
        if self.number_of_hooks_per_descriptor:
            return lst[0]
        return lst

    @property
    def startup_hooks(self):
        return self.get_hooks_from_lst(lst=self._startup_hooks)

    @property
    def pre_relocate_write_hooks(self):
        return self.get_hooks_from_lst(lst=self._pre_relocate_write_hooks)

    @property
    def pre_relocate_execute_hooks(self):
        return self.get_hooks_from_lst(lst=self._pre_relocate_execute_hooks)

    @property
    def pre_calling_shellcode_main_hooks(self):
        return self.get_hooks_from_lst(lst=self._pre_calling_shellcode_main_hooks)

    def get_hooks_from_lst(self, lst):
        return self._pad_list(lst, cls=self.shellcode.mini_loader.structs.hook)

    @property
    def shellcode_hooks_descriptor(self):
        return self._shellcode_hooks_descriptor_cls(
            size_of_hook_shellcode_data=len(self.get_hooks_data()),
            startup_hooks=self.startup_hooks,
            pre_relocate_write_hooks=self.pre_relocate_write_hooks,
            pre_relocate_execute_hooks=self.pre_relocate_execute_hooks,
            pre_calling_shellcode_main_hooks=self.pre_calling_shellcode_main_hooks
        )

    def get_hooks_data(self):
        return array_join(self._hooks_shellcode_data)

    def get_header(self):
        return self.shellcode_hooks_descriptor.pack()

