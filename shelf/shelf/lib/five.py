import sys

version = int(sys.version[0])
is_python3 = version == 3
JSONDecodeError = None
if is_python3:
    from json.decoder import JSONDecodeError
else:
    JSONDecodeError = ValueError


def get_lief():
    import lief
    from lief.ELF import SECTION_FLAGS

    return lief, SECTION_FLAGS


def load_source(*args):
    if is_python3:
        from importlib.machinery import SourceFileLoader
        return SourceFileLoader(*args)
    else:
        import imp
        return imp.load_source(*args)


def to_disasm(obj):
    if is_python3:
        if type(obj) is not bytes:
            obj = obj.encode("utf-8")
        return obj
    return obj


def to_file(obj):
    if is_python3:
        return bytes(obj)
    return obj


def py_obj():
    if is_python3:
        return b''
    else:
        return ''


def array_join(array):
    joined = py_obj()
    for obj in array:
        joined += obj
    return joined


def ljust(source, size, by):
    length = (size - len(source))
    if length < 0:
        length = 0
    if length < 0:
        raise Exception("Can't ljust data, size: {}, just: {}".format(len(source), by))
    source += by * length
    assert len(source) == size, "Error size: {}, len(source) = {}, by = {}".format(size, len(source), by)
    return source


# Do not remove this function is api function
# Used in tests
def convert_python2_bytes_string_to3(bstr):
    return bytes(bytearray([ord(b) for b in bstr]))
