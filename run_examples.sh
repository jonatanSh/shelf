echo Running mips shellcode
qemu-mips-static ./outputs/shellcode_loader_mips.out ./outputs/example_mipsbe.out.shellcode | grep -i "hello from shellcode"
echo Running intel x32 shellcode
qemu-i386-static ./outputs/shellcode_loader_intel_x32.out ./outputs/example_intel_x32.out.shellcode |grep -i "hello from shellcode"
echo Running intel x64 shellcode
qemu-x86_64-static ./outputs/shellcode_loader_intel_x64.out ./outputs/example_intel_x64.out.shellcode | grep -i "hello from shellcode"
echo Running arm 32 bit shellcode
qemu-arm-static ./outputs/shellcode_loader_arm_32.out ./outputs/example_arm_32.out.shellcode | grep -i "hello from shellcode"