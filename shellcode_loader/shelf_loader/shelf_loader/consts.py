import os
from enum import Enum
from shelf.lib.consts import Arches

BASE_DIR = os.path.dirname(__file__)
QEMUS = {
    Arches.mips.value: "qemu-mips-static",
    Arches.intel_x32.value: "qemu-i386-static",
    Arches.intel_x64.value: "qemu-x86_64-static",
    Arches.arm32.value: "qemu-arm-static",
    Arches.aarch64.value: "qemu-aarch64-static",
    Arches.riscv64.value: "qemu-riscv64-static"
}

GDB_ARCHES = {
    Arches.mips.value: "mips",
    Arches.intel_x32.value: 'i386'
}


class LoaderTypes(Enum):
    REGULAR = "regular"
    NO_RWX = "no_rwx"
    ESHELF = "eshelf"


class ShellcodeLoader(object):
    MemoryDumpStart = "MemDmpStart"
    MemoryDumpEnd = "MemDmpEnd"
    DumpAddressStart = "Dumping memory at "
    DumpAddressEnd = "\n"
