## Extensions - hooks

Because this project is intended to work on large very of systems os independently the hook mechanism enable writing
your own shellcode code and hook loading functions.

### Use cases
In macOS for a memory region to have RWX (read write execute) permission.
The originated binary must have the JIT entitlement.
The mini loader relocates the shellcode.
To relocate the shellcode it writes read and execute memory,
to bypass this entitlement we can create a pre_relocate_write_hook and a pre_relocate_execute_hook
then change the memory permissions accordingly.
The reason we use hooks instead of implementing this logic inside the loader
is because this project is intended to support large variety of operating systems
and if this logic was inside the mini loader the mini loader will be os dependent.

### How to use

A hook must be a shellcode, you can take a look at the simple say hi hook

* [simple_hello_hook](../hooks/simple_hello_hook.c)
* [simple_hello_hook py](../hook_configurations/simple_hello_hook.py)

### The configuration file

The hook configuration file is a python file. The parser will parse this file and create the hooks accordingly. In the
hook file you can create the hook attributes by overriding the hook_get_attributes function. Then inside the hook (the
shellcode can access this attributes)

```python
"""
The library parses this file and find all the class inheriting from 
elf_to_shellcode.hooks import [... hook types (eg .. ShelfStartupHook)]
Then the library create all the hooks accordingly
"""
from elf_to_shellcode.hooks import ShelfStartupHook, Arches, ArchEndians


class SimpleSayHiHook(ShelfStartupHook):
    def hook_get_shellcode_path(self, arch, endian):
        assert isinstance(arch, Arches)
        assert isinstance(endian, ArchEndians)
        return "../outputs/{}_simple_hello_hook.hook".format(arch.value)

    def hook_get_attributes(self):
        message = b"Simple hello hook said hello!"
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

```

Currently, the following hook types are supported:

* startup_hooks - Hooks that run upon mini_loader initialize
* pre_relocate_write_hooks
* pre_relocate_execute_hooks
* pre_calling_shellcode_main_hooks
#### Usage

```bash
# Add the following arguments
--loader-supports hooks --hooks-configuration ../hook_configurations/simple_hello_hook.py
```

#### Result

```bash
INFO:root:Stdout: Simple hello hook said hello! # This is returned from the hook
[ELF_FEATURES:INFO] elf_features.c main(line:86):main address=7f6d4734, argc=2, argv=7ffff6b4, total_args=4
[ELF_FEATURES:INFO] elf_features.c main(line:89):Elf in shellcode mode!
[ELF_FEATURES:INFO] elf_features.c main(line:94):Argv[0] = ../outputs/shellcode_loader_mips.out, argv[1] = ../outputs/elf_features_mipsbe.out.hooks.shellcode
[ELF_FEATURES:INFO] elf_features.c main(line:98):Hello from shellcode!
[ELF_FEATURES:INFO] elf_features.c main(line:99):Testing jump tables
[ELF_FEATURES:INFO] elf_features.c test_jump_table(line:67):Case is default
[ELF_FEATURES:INFO] elf_features.c main(line:101):Testing global ptr arrays
[ELF_FEATURES:INFO] elf_features.c say_hi(line:47):Hi
[ELF_FEATURES:INFO] elf_features.c say_hello(line:51):Hello
[ELF_FEATURES:INFO] elf_features.c main(line:120):__Test_output_Success
Loading ../outputs/elf_features_mipsbe.out.hooks.shellcode
```

#### Supported architectures

* mips
* intel x32
* intel x64
* arm
* aarch64