import sys

version = int(sys.version[0])
is_python3 = version == 3


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
    source += by * length
    assert len(source) == size
    return source