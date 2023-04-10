import capstone
from test_runner.consts import Arches

ARCHES = {
    Arches.MIPS.value: capstone.CS_ARCH_MIPS,
    Arches.intel_x32.value: capstone.CS_ARCH_X86,
    Arches.intel_x64.value: capstone.CS_ARCH_X86,
    Arches.aarch64.value: capstone.CS_ARCH_ARM64,
    Arches.arm32.value: capstone.CS_ARCH_ARM
}

ENDIAN = {
    Arches.MIPS.value: capstone.CS_MODE_BIG_ENDIAN,
    Arches.intel_x32.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.intel_x64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.aarch64.value: capstone.CS_MODE_LITTLE_ENDIAN,
    Arches.arm32.value: capstone.CS_MODE_LITTLE_ENDIAN,
}

BITS = {
    Arches.MIPS.value: capstone.CS_MODE_32,
    Arches.intel_x32.value: capstone.CS_MODE_32,
    Arches.intel_x64.value: capstone.CS_MODE_64,
    Arches.aarch64.value: capstone.CS_MODE_ARM,
    Arches.arm32.value: capstone.CS_MODE_ARM,
}
