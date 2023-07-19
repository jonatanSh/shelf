from shelf.mips.mips import mips_make_shellcode, MipsShellcode
from shelf.intel.x32 import intel_x32_make_shellcode, IntelX32Shellcode
from shelf.intel.x64 import intel_x64_make_shellcode, IntelX64Shellcode
from shelf.arm.x32 import arm_x32_make_shellcode, ArmX32Shellcode
from shelf.arm.x64 import arm_x64_make_shellcode, ArmX64Shellcode
from shelf.riscv.riscv64 import riscv64_make_shellcode, Riscv64Shellcode
from shelf.lib.consts import StartFiles, Arches, ArchEndians

ENDIANS = [ArchEndians.big.value, ArchEndians.little.value]

shellcode_handlers = {
    Arches.mips.value: mips_make_shellcode,
    Arches.intel_x32.value: intel_x32_make_shellcode,
    Arches.intel_x64.value: intel_x64_make_shellcode,
    Arches.arm32.value: arm_x32_make_shellcode,
    Arches.aarch64.value: arm_x64_make_shellcode,
    Arches.riscv64.value: riscv64_make_shellcode,

}

shellcode_classes = {
    Arches.mips.value: MipsShellcode,
    Arches.intel_x32.value: IntelX32Shellcode,
    Arches.intel_x64.value: IntelX64Shellcode,
    Arches.arm32.value: ArmX32Shellcode,
    Arches.aarch64.value: ArmX64Shellcode,
    Arches.riscv64.value: Riscv64Shellcode,
}


def make_shellcode(arch, endian, start_file_method, args):
    assert endian in ENDIANS, 'Chose endain from: {}'.format(ENDIANS)
    assert arch in shellcode_handlers, 'Chose arch from: {}, got arch: {}'.format(
        shellcode_handlers.keys(),
        arch
    )
    assert start_file_method in StartFiles.__all__
    return shellcode_handlers[arch](args=args)
