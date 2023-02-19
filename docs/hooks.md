## Extensions - hooks

Because this project is intended to work on large very of systems os independently the hook mechanism enable writing
your own assembly code and hook loading functions.

### How to use
A hook must be a shellcode, you can take a look at the simple say hi hook

* [simple_hello_hook](../hooks/simple_hello_hook.c)
* [simple_hello_hook json](../hook_configurations/test.json)

Currently, the following hook types are supported:
* startup_hooks - Hooks that run upon mini_loader initialize

#### Usage
```bash
# Add the following arguments
--loader-supports hooks --hooks-configuration ../hook_configurations/test.json
```

#### Result
```bash
INFO:root:Stdout: hello from hook! # This is returned from the hook
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

