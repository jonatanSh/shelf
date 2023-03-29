from shelf.hooks import ShelfStartupHook, ShelfPreRelocateWriteHook, ShelfPreCallingShellcodeMainHook, \
    ShelfPreRelocateExecuteHook, Arches, ArchEndians


class SimpleStringHook(object):
    def __init__(self, string, *args, **kwargs):
        self.string = string
        super(SimpleStringHook, self).__init__(*args, **kwargs)

    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(endian, ArchEndians)
        return "../outputs/{}_simple_hello_hook.hook".format(arch.value)

    def hook_get_attributes(self):
        message = self.string + b"\n"
        message_length = len(message) + 1
        message_length_packed = self.shellcode.address_utils.pack_pointer(
            message_length
        )
        message = self.shellcode.address_utils.pack(
            "{}s".format(message_length),
            message
        )

        packed = message_length_packed + message

        return packed


class SimpleSayHiHook(SimpleStringHook, ShelfStartupHook):
    def __init__(self, *args, **kwargs):
        super(SimpleSayHiHook, self).__init__(string=b"Hello from startup hook!",
                                              *args, **kwargs)


class PreExecuteHook(SimpleStringHook, ShelfPreRelocateExecuteHook):
    def __init__(self, *args, **kwargs):
        super(PreExecuteHook, self).__init__(string=b"Hello from pre execute hook!",
                                             *args, **kwargs)


class PreWriteHook(SimpleStringHook, ShelfPreRelocateWriteHook):
    def __init__(self, *args, **kwargs):
        super(PreWriteHook, self).__init__(string=b"Hello from pre write hook!",
                                           *args, **kwargs)


class PreCallMain(SimpleStringHook, ShelfPreCallingShellcodeMainHook):
    def __init__(self, *args, **kwargs):
        super(PreCallMain, self).__init__(string=b"Hello from pre call main hook!",
                                          *args, **kwargs)
