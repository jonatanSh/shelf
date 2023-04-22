import os
from enum import Enum
import sys


def get_args():
    return sys.modules['__global_args']


class TestFeatures(Enum):
    DYNAMIC = "dynamic"
    ESHELF = "eshelf"
    NORWX = "rwx_bypass"


class Arches(Enum):
    MIPS = "mips"
    intel_x32 = "intel_x32"
    intel_x64 = "intel_x64"
    arm32 = "arm32"
    aarch64 = "aarch64"
    riscv64 = "riscv64"


class CONSTS(Enum):
    DEBUG_PORT = 1234
    execution_timeout_seconds = 3


_arch = os.uname()[-1]
QEMUS = {
    Arches.MIPS.value: "qemu-mips-static",
    Arches.intel_x32.value: "qemu-i386-static",
    Arches.intel_x64.value: "qemu-x86_64-static",
    Arches.arm32.value: "qemu-arm-static",
    Arches.aarch64.value: "qemu-aarch64-static",
    Arches.riscv64: "qemu-riscv64-static"
}
# Prefer no emulation if running on x64 host !
if _arch == 'x86_64':
    QEMUS[Arches.intel_x64] = ""


class LoaderTypes(Enum):
    RWX_LOADER = "rwx"
    RX_LOADER = "rx"


LOADERS = {
    LoaderTypes.RWX_LOADER: "../outputs/shellcode_loader_{}.out",
    LoaderTypes.RX_LOADER: "../outputs/shellcode_loader_no_rwx_{}.out"

}


class ShellcodeLoader(object):
    MemoryDumpStart = "MemDmpStart"
    MemoryDumpEnd = "MemDmpEnd"
    DumpAddressStart = "Dumping memory at "
    DumpAddressEnd = "\n"


class Resolver(object):
    @staticmethod
    def get_qemu(arch):
        return QEMUS[arch]

    @staticmethod
    def get_loader(loader_type, arch):
        assert isinstance(loader_type, LoaderTypes)
        return LOADERS[loader_type].format(arch)
