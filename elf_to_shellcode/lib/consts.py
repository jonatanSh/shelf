import enum


class HookTypes(enum.Enum):
    STARTUP_HOOKS = 1
    PRE_RELOCATE_WRITE_HOOKS = 2
    PRE_RELOCATE_EXECUTE_HOOKS = 3
    PRE_CALLING_MAIN_SHELLCODE_HOOKS = 4


class RelocationAttributes(enum.Enum):
    generic_relocate = 0
    call_to_resolve = 1
    relative_to_loader_base = 2
    relative = 3


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
    __all__ = [
        mips,
        intel_x32,
        intel_x64,
        arm32,
        aarch64
    ]
    from_idents = {
        'EM_MIPS': mips,
        'EM_386': intel_x32,
        'EM_X86_64': intel_x64,
        'EM_ARM': arm32,
        'EM_AARCH64': aarch64

    }

    @staticmethod
    def translate_from_ident(ident):
        if ident in Arches.from_idents.value:
            return Arches.from_idents.value[ident]
        else:
            raise Exception("Not supported for arch: {}".format(
                ident
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
