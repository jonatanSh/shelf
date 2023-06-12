import gdb
from shelf_loader import consts
from shelf_loader.extractors.utils import extract_int16, extract_int10

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


def get_shellcode_mapped_size():
    with open(consts.debugger_stdout, 'r') as fp:
        data = fp.read()

    if consts.ShellcodeLoader.JumpingToShellcode in data:
        return extract_int10(
            data,
            "Mapping new memory, size = ",
            '\n',
        )
    return None


def get_memory_dump_for_shellcode():
    shellcode_address = get_shellcode_address()
    shellcode_size = get_shellcode_mapped_size()
    if not shellcode_address or not shellcode_size:
        print("Error shellcode not mapped yet !")
        return
    # Read the memory
    memory_data = gdb.selected_inferior().read_memory(shellcode_address, shellcode_size)
    # Convert the memory data to a byte string
    memory_bytes = memory_data.tobytes()
    print("Extracted memory dump, size: {}".format(hex(len(memory_bytes))))
    return memory_bytes


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
