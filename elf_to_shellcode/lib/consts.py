class Arches(object):
    MIPS_32 = "mips"
    INTEL_X32 = "intel_x32"
    INTEL_X64 = "intel_x64"
    ARM_32 = "arm32"
    ARM_64 = "aarch64"
    __all__ = [
        MIPS_32,
        INTEL_X32,
        INTEL_X64,
        ARM_32,
        ARM_64
    ]


ENDIANS = ["big", "little"]
ENDIAN_MAP = {
    "big": ">",
    "little": "<"
}

PTR_SIZES = {
    4: "I",
    8: "Q"
}


class RelocationAttributes(object):
    call_to_resolve = 1
    relative_to_loader_base = 2
    relative = 3


class RELOC_TYPES(object):
    JMP_SLOT = "JMP_SLT"
    RELATIVE = "RELATIVE"
    GLOBAL_SYM = "GLOBAL_SYM"
    GLOBAL_DAT = "GLOBAL_DAT"
    DO_NOT_HANDLE = "DO_NOT_HANDLE"


class StartFiles(object):
    glibc = "glibc"
    no_start_files = "no"

    __all__ = [
        glibc,
        no_start_files
    ]


class LoaderSupports(object):
    choices = {
        "dynamic": ('dynamic', 0)
    }

    @staticmethod
    def resolve_choice(key):
        return LoaderSupports.choices[key]


class OUTPUT_FORMAT_MAP(object):
    eshelf = 'eshelf'
    shelf = 'shelf'


OUTPUT_FORMATS = [OUTPUT_FORMAT_MAP.eshelf, OUTPUT_FORMAT_MAP.shelf]
