import gdb
from shelf_loader import consts
from shelf_loader.extractors.utils import extract_int16

HEADER = "SHELF LOADER GDB INTEGRATION"
print(HEADER)


# Define a Python function as a GDB macro
def get_stdout():
    with open(consts.debugger_stdout, 'r') as fp:
        data = fp.read()
    print(data)


def get_shellcode_address():
    with open(consts.debugger_stdout, 'r') as fp:
        data = fp.read()

    if consts.ShellcodeLoader.JumpingToShellcode in data:
        return extract_int16(
            data,
            consts.ShellcodeLoader.JumpingToShellcode,
            '\n'
        )
    return None


def execute_shellcode():
    address = get_shellcode_address()
    if not address:
        gdb.execute("b *execute_shellcode")
        gdb.execute("c")
        last_ms = gdb.execute("mni", to_string=True)
        while last_ms != gdb.execute("mni", to_string=True):
            address = get_shellcode_address()
            if address:
                break
            last_ms = gdb.execute("mni", to_string=True)

    if address:
        print("Shellcode loaded to: {}".format(hex(address)))
        gdb.execute("b *{}".format(address))
        gdb.execute("c")
        print("Shellcode loaded displaying stdout")
        get_stdout()
    else:
        print("Address not found, probably crashed before ?")
