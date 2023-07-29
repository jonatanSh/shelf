import capstone
import enum


class HookTypes(enum.Enum):
    STARTUP_HOOKS = 1
    PRE_RELOCATE_WRITE_HOOKS = 2
    PRE_RELOCATE_EXECUTE_HOOKS = 3
    PRE_CALLING_MAIN_SHELLCODE_HOOKS = 4


class RelocationAttributes(enum.Enum):
    generic_relocate = (1 << 0)
    call_to_resolve = (1 << 1)
    relative_to_loader_base = (1 << 2)
    relative = (1 << 3)
    riscv64_lui_ld_opcode_relocation = (1 << 4)

class RELOC_TYPES(object):
    JMP_SLOT = "JMP_SLT"
    RELATIVE = "RELATIVE"
    GLOBAL_SYM = "GLOBAL_SYM"
    EXTERN = "EXTERN"
    GLOBAL_DAT = "GLOBAL_DAT"
    DO_NOT_HANDLE = "DO_NOT_HANDLE",
    ARCH_SPECIFIC = "ARCH_SPECIFIC"
    PASS = lambda **kwargs: None


class StartFiles(object):
    glibc = "glibc"
    no_start_files = "no"

    __all__ = [
        glibc,
        no_start_files
    ]


class LoaderSupports(object):
    DYNAMIC = 'dynamic'
    HOOKS = 'hooks'
    choices = {
        DYNAMIC: ('dynamic', 0),
        HOOKS: ('hooks', 0)
    }

    @staticmethod
    def resolve_choice(key):
        return LoaderSupports.choices[key]


class OUTPUT_FORMAT_MAP(object):
    eshelf = 'eshelf'
    shelf = 'shelf'


class Arches(enum.Enum):
    mips = "mips"
    intel_x32 = "intel_x32"
    intel_x64 = "intel_x64"
    arm32 = "arm32"
    aarch64 = "aarch64"
    riscv64 = "riscv64"
    __all__ = [
        mips,
        intel_x32,
        intel_x64,
        arm32,
        aarch64,
        riscv64
    ]
    from_idents = {
        'EM_MIPS': mips,
        'EM_386': intel_x32,
        'EM_X86_64': intel_x64,
        'EM_ARM': arm32,
        'EM_AARCH64': aarch64,
        ('EM_RISCV', "ELFCLASS64"): riscv64,

    }

    @staticmethod
    def translate_from_ident(ident, elfclass=None):
        ident_with_class = (ident, elfclass)
        if ident_with_class in Arches.from_idents.value:
            return Arches.from_idents.value[ident_with_class]
        if ident in Arches.from_idents.value:
            return Arches.from_idents.value[ident]
        else:
            raise Exception("Not supported for arch: {}".format(
                ident_with_class
            ))


class ArchEndians(enum.Enum):
    little = 'little'
    big = 'big'


class RELOCATION_OFFSETS(enum.Enum):
    table_magic = 0
    padding_between_table_and_loader = 1


class MitigationBypass(enum.Enum):
    rwx = 'RwxHooksDescriptor'


class MemoryProtection(enum.Enum):
    PROT_READ = (2 << 0)
    PROT_WRITE = (2 << 1)
    PROT_EXEC = (2 << 2)


OUTPUT_FORMATS = [OUTPUT_FORMAT_MAP.eshelf, OUTPUT_FORMAT_MAP.shelf]


class DisassemblerConsts(object):
    ARCHES = {
        Arches.mips.value: capstone.CS_ARCH_MIPS,
        Arches.intel_x32.value: capstone.CS_ARCH_X86,
        Arches.intel_x64.value: capstone.CS_ARCH_X86,
        Arches.aarch64.value: capstone.CS_ARCH_ARM64,
        Arches.arm32.value: capstone.CS_ARCH_ARM,
    }

    ENDIAN = {
        Arches.mips.value: capstone.CS_MODE_BIG_ENDIAN,
        Arches.intel_x32.value: capstone.CS_MODE_LITTLE_ENDIAN,
        Arches.intel_x64.value: capstone.CS_MODE_LITTLE_ENDIAN,
        Arches.aarch64.value: capstone.CS_MODE_LITTLE_ENDIAN,
        Arches.arm32.value: capstone.CS_MODE_LITTLE_ENDIAN,

    }

    BITS = {
        Arches.mips.value: capstone.CS_MODE_32,
        Arches.intel_x32.value: capstone.CS_MODE_32,
        Arches.intel_x64.value: capstone.CS_MODE_64,
        Arches.aarch64.value: capstone.CS_MODE_ARM,
        Arches.arm32.value: capstone.CS_MODE_ARM,

    }

    OBJDUMP_BACKENDS = {
        Arches.riscv64.value: 'riscv64-linux-gnu-objdump'
    }
    OBJDUMP_ARCHES = {
        Arches.riscv64.value: "riscv:rv64"
    }


class ShelfFeatures(enum.Enum):
    DYNAMIC = (2 << 0)
    HOOKS = (2 << 1)
    ARCH_MAPPING = {
        Arches.mips.value: (2 << 2),
        Arches.intel_x32.value: (2 << 3),
        Arches.intel_x64.value: (2 << 4),
        Arches.arm32.value: (2 << 5),
        Arches.aarch64.value: (2 << 6),
        Arches.riscv64.value: (2 << 7),

    }


class ShellcodeMagics(enum.Enum):
    arch32 = 0xaabbccdd
    arch64 = 0x8899aabbccddeeff


class Process(object):
    timeout = 3
