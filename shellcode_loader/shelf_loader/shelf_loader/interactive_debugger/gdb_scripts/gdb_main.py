import gdb
from shelf_loader import consts
from shelf_loader.extractors.utils import extract_int16, extract_int10
from shelf.api import ShelfApi
from shelf_loader.interactive_debugger.gdb_scripts.shelf_debug_flow import DebugFlowManager

HEADER = "SHELF LOADER GDB INTEGRATION"
print(HEADER)

shelf = None
shelf_dump = None
symbols = None

debug_flow_manager = DebugFlowManager()


def debug_flow_manager_generate_flow():
    debug_flow_manager.run()


def create_shelf(source_elf_path):
    global shelf
    shelf_kwargs = {'loader_supports': []}
    shelf = ShelfApi(binary_path=source_elf_path, **shelf_kwargs)


def get_dump():
    global shelf_dump

    if not shelf_dump:
        address = get_shellcode_address()
        memory_dump = get_memory_dump_for_shellcode()

        if not shelf or not address or not memory_dump:
            return
        shelf_dump = shelf.shelf.memory_dump_plugin.construct_shelf_from_memory_dump(
            memory_dump=memory_dump,
            dump_address=address,
            loading_address=address
        )

    return shelf_dump


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


def display_shellcode_symbols(name=None, only_return_address=False):
    syms = get_symbols()
    if not syms:
        print("Shellcode not executed yet !")
        return

    for symbol_object in syms:
        symbol_name, symbol_address, symbol_size = symbol_object
        if name and name != symbol_name:
            continue
        if only_return_address:
            return symbol_address
        print("{}-{}: {}".format(
            hex(symbol_address),
            hex(symbol_address + symbol_size),
            symbol_name
        ))


def get_symbols():
    global symbols
    dump = get_dump()
    if not dump:
        return

    if not symbols:
        symbols = dump.get_symbol_by_name()
    return symbols


def find_symbol_at_address(address):
    dump = get_dump()
    if not dump:
        return
    return dump.find_symbol_at_address(address=address)


def add_symbols_to_disassembly(disassembly):
    lines = []
    for line in disassembly.split("\n"):
        address_start = line.find(" ") + 1
        while line[address_start:].startswith(" "):
            address_start += 1

        address_end = line[address_start:].find(" ") + address_start
        address_other_end = line[address_start:].find(":") + address_start
        address_end = min(address_other_end, address_end)
        address = line[address_start: address_end].strip()
        if address.startswith(" "):
            address = address[1:]
        if not address:
            continue
        address = int(address, 16)
        symbol_name = find_symbol_at_address(address)
        symbol_end = line.find(":")
        symbol_start = line[:symbol_end].rfind(' ') + 1
        potential_symbol_part = line[symbol_start:symbol_end]
        if potential_symbol_part.startswith("<") and potential_symbol_part.endswith(">"):
            # Found gdb symbol
            pass
        else:
            line = line[:symbol_start] + "<{}>".format(symbol_name) + line[symbol_end:]
        lines.append(line)
    return "\n".join(lines)


def break_on_symbol(sym_name):
    address = display_shellcode_symbols(only_return_address=True, name=sym_name)
    if address:
        gdb.execute("b *{}".format(hex(address)))
    else:
        print("Address for symbol: {} not found !".format(sym_name))


def disassm():
    disassembly = gdb.execute("x/10i $pc", to_string=True)
    try:
        disassembly = add_symbols_to_disassembly(disassembly)
    except Exception as e:
        print("Disassembly exception: {}".format(e))
        pass
    print(disassembly)
