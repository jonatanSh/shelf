from elf_to_shellcode.hooks import ShelfStartupHook, Arches, ArchEndians


class SimpleSayHiHook(ShelfStartupHook):
    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(endian, ArchEndians)
        return "../outputs/{}_simple_hello_hook.hook".format(arch.value)

    def hook_get_attributes(self):
        message = b"Simple hello hook said hello!\n"
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
