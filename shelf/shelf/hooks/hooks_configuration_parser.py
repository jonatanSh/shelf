import os
import inspect
import logging
from shelf.lib import five
from shelf import hooks


def is_base_class_of(value, cls):
    try:
        for m in inspect.getmro(value):
            if m == cls:
                return True
    except:
        return False


class HookConfiguration(object):
    def __init__(self, path):
        path = os.path.abspath(path)
        self.package = ".".join(path.split(os.path.sep))
        if self.package.startswith("."):
            self.package = self.package[1:]
        self.module = five.load_source(self.package, path).load_module()
        self.startup_hooks = []
        self.pre_relocate_write_hooks = []
        self.pre_relocate_execute_hooks = []
        self.pre_calling_main_shellcode_hooks = []
        self.not_hooks = hooks.__dict__.values()
        for attribute_name, attribute_value in self.module.__dict__.items():
            if attribute_value in self.not_hooks:
                continue
            if is_base_class_of(attribute_value, hooks.ShelfStartupHook):
                logging.info("Found startup hook: {}".format(
                    attribute_name
                ))
                self.startup_hooks.append(attribute_value)
            elif is_base_class_of(attribute_value, hooks.ShelfPreRelocateWriteHook):
                logging.info("Found pre relocate write hook: {}".format(
                    attribute_name
                ))
                self.pre_relocate_write_hooks.append(attribute_value)
            elif is_base_class_of(attribute_value, hooks.ShelfPreRelocateExecuteHook):
                logging.info("Found pre relocate execute hook: {}".format(
                    attribute_name
                ))
                self.pre_relocate_execute_hooks.append(attribute_value)
            elif is_base_class_of(attribute_value, hooks.ShelfPreCallingShellcodeMainHook):
                logging.info("Found pre calling shellcode main hook: {}".format(
                    attribute_name
                ))
                self.pre_calling_main_shellcode_hooks.append(attribute_value)

    def validate(self):
        return


def is_valid_hooks_file(path):
    try:
        # Trying to create the hook Parser
        hook = HookConfiguration(path)
    except Exception as error:
        logging.error("Hook configuration parsing error: {}".format(
            error
        ))
        return False

    error = hook.validate()
    if error:
        logging.error("Hook configuration parsing error: {}".format(
            error
        ))
    return True
