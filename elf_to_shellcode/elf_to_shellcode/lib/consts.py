class RelocationAttributes(object):
    call_to_resolve = 1


class StartFiles(object):
    glibc = "glibc"
    no_start_files = "no"

    __all__ = [
        glibc,
        no_start_files
    ]
