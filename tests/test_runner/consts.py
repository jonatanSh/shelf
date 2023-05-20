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


class LoaderTypes(Enum):
    RWX_LOADER = "rwx"
    RX_LOADER = "rx"


class ShellcodeLoader(object):
    MemoryDumpStart = "MemDmpStart"
    MemoryDumpEnd = "MemDmpEnd"
    DumpAddressStart = "Dumping memory at "
    DumpAddressEnd = "\n"
