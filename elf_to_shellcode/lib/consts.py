class RelocationAttributes(object):
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
