echo Running mips shellcode
qemu-mips-static ./outputs/shellcode_loader_mips.out ./outputs/mips_example.out.shellcode intel x32 shellcode | grep -i "hello"
echo Running intel x32 shellcode
qemu-i386-static ./outputs/shellcode_loader_intel_x32.out ./outputs/intel_x32_example.out.shellcode | grep -i "hello"
echo Running intel x64 shellcode
qemu-x86_64-static ./outputs/shellcode_loader_intel_x64.out ./outputs/intel_x64_example.out.shellcode | grep -i "hello"
echo Running arm shellcode
qemu-arm-static ./outputs/shellcode_loader_arm32.out ./outputs/arm32_example.out.shellcode | grep -i "hello"
echo Running aarch64 shellcode
qemu-aarch64-static ./outputs/shellcode_loader_aarch64.out ./outputs/aarch64_example.out.shellcode | grep -i "hello"