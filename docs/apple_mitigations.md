# Apple mitigations 

Apple has RWX memory protection mitigation, the shellcode must run in RWX memory area because it realocates itslef.
If you want to run this project on apple systems compile the loader as follows:

```bash
make shellcode_loader_apple
# Then run it:
./outputs/shellcode_loader_apple.out ./outputs/no_relocations_aarch64.out.shellcode
```

Post compiling it will add the JIT entitlement to the output mach-o binary.
Then RWX memory can be allocated