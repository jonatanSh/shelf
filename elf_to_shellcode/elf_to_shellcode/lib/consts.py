class RelocationAttributes(object):
    call_to_resolve = 1
    relative_to_loader_base = 2
    relative = 3


class RELOC_TYPES(object):
    JMP_SLOT = "JMP_SLT"
    RELATIVE = "RELATIVE"
    GLOBAL_SYM = "GLOBAL_SYM"
    GLOBAL_DAT = "GLOBAL_DAT"


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
