class RelocationAttributes(object):
    call_to_resolve = 1
    relative_to_loader_base = 2


class RELOC_TYPES(object):
    JMP_SLOT = "JMP_SLT"


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
