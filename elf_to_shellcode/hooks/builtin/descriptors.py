from elf_to_shellcode.hooks.base_hook import _BuiltinHookDescriptor
from elf_to_shellcode.hooks.builtin import rwx_bypass
from elf_to_shellcode.lib.consts import LoaderSupports


class RwxHooksDescriptor(_BuiltinHookDescriptor):
    def __init__(self):
        super(RwxHooksDescriptor, self).__init__(path=rwx_bypass.__file__)

    def add_support(self, args):
        if LoaderSupports.HOOKS not in args.loader_supports:
            args.loader_supports.append(LoaderSupports.HOOKS)

        return args


def get_descriptor(descriptor_name):
    return globals()[descriptor_name]()
