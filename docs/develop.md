# Key concepts
* The mini loader can't use functions (if functions are used the mini loader may contain relocations)

## Development features
* For development, it is advised to use the [eshelf output format](eshelf.md)
* you can specify the loader in the command line arguments and compile a debug loader


### Specify the loader
```bash
--loader-path <path_to_loader> --loader-symbols-path <path_to_loader_symbols>
```

### Run tests
```bash
# Run all tests
python run_tests.py
# A specific test 
python run_tests.py --arch mips --verbose --test elf_features
 ```
The tests will try to do their best to show where errors occurred.

For example the following output is provided on segfault:
```bash
Stdout:
Loading ../outputs/mips_elf_features.out.shellcode
Shellcode size = 613080
Allocating shellcode buffer, size = 614400
Mapping new memory, size = 614400
Jumping to shellcode, address = 0x7f6d2000 
Segmentation fault occurred at address: 0x4107e0
Dumping memory at 0x410780
0x8e 0x59 0x00 0x40 0x03 0x20 0xf8 0x09 0x03 0xc0 0x20 0x25 0x02 0x00 0x10 0x25 0x10 0x00 0x00 0x7f 0x8f 0xbc 0x00 0x20 0x14 0x43 0xff 0x88 0x00 0x62 0x10 0x2b 0x24 0x02 0x00 0x01 0xaf 0xa2 0x00 0x2c 0x8f 0xc2 0x00 0x00 0x30 0x42 0x08 0x00
Opcodes parser for: mips

[!!!!] Disassembly may be incorrect !

_IO_file_read:
      0x410780:	lw	$t9, 0x40($s2)
      0x410784:	jalr	$t9
      0x410788:	move	$a0, $fp
      0x41078c:	move	$v0, $s0
      0x410790:	b	0x410990
----> 0x410794:	lw	$gp, 0x20($sp)
      0x410798:	bne	$v0, $v1, 0x4105bc
      0x41079c:	sltu	$v0, $v1, $v0
      0x4107a0:	addiu	$v0, $zero, 1
      0x4107a4:	sw	$v0, 0x2c($sp)
      0x4107a8:	lw	$v0, ($fp)
      0x4107ac:	andi	$v0, $v0, 0x800
```