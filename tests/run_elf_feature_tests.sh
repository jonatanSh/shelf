echo Running mips shellcode
qemu-mips-static ../outputs/shellcode_loader_mips.out ../outputs/elf_features_mipsbe.out.shellcode
echo Running intel x32 shellcode
qemu-i386-static ../outputs/shellcode_loader_intel_x32.out ../outputs/elf_features_intel_x32.out.shellcode
echo Running intel x64 shellcode
qemu-x86_64-static ../outputs/shellcode_loader_intel_x64.out ../outputs/elf_features_intel_x64.out.shellcode
echo Running arm 32 tests
qemu-arm-static ../outputs/shellcode_loader_arm_32.out ../outputs/no_relocations_arm_32.out.shellcode 
echo Running no relocation tests
qemu-i386-static ../outputs/shellcode_loader_intel_x32.out ../outputs/no_relocations_intel_x32.out.shellcode 
echo Running no relocation tests
qemu-aarch64-static ../outputs/shellcode_loader_aarch_64.out ../outputs/no_relocations_aarch64.out.shellcode 