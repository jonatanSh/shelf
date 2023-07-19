import traceback
import copy
import gdb
from shelf_loader import consts
from shelf_loader.extractors.utils import extract_int16, extract_int10
from shelf.api import ShelfApi
from shelf_loader.interactive_debugger.gdb_scripts.shelf_debug_flow import DebugFlowManager
import cProfile

HEADER = "SHELF LOADER GDB INTEGRATION"
print(HEADER)

debug_flow_manager = DebugFlowManager()


class GdbGeneralCommandsApi(object):
    def __init__(self):
        self.verbose_exceptions = None
        self.profiling_enabled = None
        self._symbols = None
        self.source_elf_path = None
        self._shelf_api = None
        self._dump = None
        self._shellcode_address = None
        self._shellcode_mapped_size = None
        self._shellcode_memory = None

    def construct(self, source_elf_path):
        """
        Called within the initialization script
        :param source_elf_path:
        :return:
        """
        self.source_elf_path = source_elf_path
        shelf_kwargs = {'loader_supports': []}
        self._shelf_api = ShelfApi(binary_path=source_elf_path, **shelf_kwargs)

    @staticmethod
    def debug_flow_manager_generate_flow():
        debug_flow_manager.run()

    @property
    def shelf(self):
        return self._shelf_api.shelf

    @property
    def found_shellcode_address(self):
        try:
            return self.shellcode_address is not None
        except:
            return False

    @property
    def shellcode_address(self):
        """
        Parse the shellcode address from the loader stdout
        :return: Shellcode address
        """
        if not self._shellcode_address:
            stdout = self.get_stdout(should_print=False)

            if consts.ShellcodeLoader.JumpingToShellcode in stdout:
                self._shellcode_address = extract_int16(
                    stdout,
                    consts.ShellcodeLoader.JumpingToShellcode,
                    '\n'
                )
            raise Exception("Shellcode not loaded yet !")
        return self._shellcode_address

    @property
    def shellcode_mapped_size(self):
        """
        Parse and return the shellcode size
        :return: shellcode size
        """
        if not self._shellcode_mapped_size:
            stdout = self.get_stdout(should_print=False)
            if consts.ShellcodeLoader.JumpingToShellcode in stdout:
                return extract_int10(
                    stdout,
                    "Mapping new memory, size = ",
                    '\n',
                )
            raise Exception("Shellcode not loaded yet !")
        return self._shellcode_mapped_size

    @property
    def shellcode_memory(self):
        """
        Extract and return shellcode memory
        :return:
        """
        if not self._shellcode_memory:
            # Read the memory
            memory_data = gdb.selected_inferior().read_memory(self.shellcode_address,
                                                              self.shellcode_mapped_size)
            # Convert the memory data to a byte string
            memory_bytes = memory_data.tobytes()
            self._shellcode_memory = memory_bytes
        return self._shellcode_memory

    @property
    def dump(self):
        """
        Create shelf dump object
        :return: shelf dump
        """
        if not self._dump:
            self._dump = self.shelf.memory_dump_plugin.construct_shelf_from_memory_dump(
                memory_dump=self.shellcode_memory,
                dump_address=self.shellcode_address,
                loading_address=self.shellcode_address
            )

        return self._dump

    def execute_shellcode(self):
        """
        Step instructions in the mini loader until shellcode is found
        :return: None
        """
        if not self.found_shellcode_address:
            gdb.execute("b *execute_shellcode")
            gdb.execute("mc")
            last_ms = gdb.execute("mni", to_string=True)
            while last_ms != gdb.execute("mni", to_string=True):
                if self.found_shellcode_address:
                    break
                last_ms = gdb.execute("mni", to_string=True)

        if self.found_shellcode_address:
            print("Shellcode loaded to: {}".format(hex(self.shellcode_address)))
            gdb.execute("b *{}".format(self.shellcode_address))
            gdb.execute("mc")
            print("Shellcode loaded displaying stdout")
            self.get_stdout()
        else:
            print("Address not found, probably crashed before ?")

    @property
    def symbols(self):
        """
        Return shellcode symbols
        :return:
        """
        if not self._symbols:
            self._symbols = self.dump.get_symbol_by_name()
        return self._symbols

    def display_shellcode_symbols(self, name=None, only_return_address=False):
        """
        Display shellcode symbols
        :param name: symbol name
        :param only_return_address: only return symbol address and do not display
        :return: None
        """
        for symbol_object in self.symbols:
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

    def find_symbol_at_address(self, address, **kwargs):
        """
        Locate and find symbol at address
        :param address:
        :param kwargs:
        :return:
        """
        return self.dump.find_symbol_at_address(address=address, **kwargs)

    def add_sym_address_to_line(self, line, address, with_symbol=False):
        """
        Add to gdb line a symbol representation
        :param line: Gdb line
        :param address: gdb address
        :param with_symbol:
        :return:
        """
        address = int(address, 16)
        original_name, symbol_name = self.find_symbol_at_address(address, with_original=True)
        symbol_end = line.find(":")
        symbol_start = line[:symbol_end].rfind(' ') + 1
        potential_symbol_part = line[symbol_start:symbol_end]
        if potential_symbol_part.startswith("<") and potential_symbol_part.endswith(">"):
            # Found gdb symbol
            pass
        else:
            sym_add = self.display_shellcode_symbols(only_return_address=True, name=original_name)
            if sym_add:
                off = "+{}".format(hex(address - sym_add))
            else:
                off = hex(address)
            symbol_name = "{} {}".format(symbol_name, off)
            line = line[:symbol_start] + "<{}>".format(symbol_name) + line[symbol_end:]
            if sym_add:
                line = "{} {}".format(hex(address), line)
        if with_symbol:
            line = (line, symbol_name)
        return line

    def add_symbols_to_disassembly(self, disassembly, with_symbols=False):
        """
        Add symbols to gdb disassembly
        :param disassembly:
        :param with_symbols:
        :return:
        """
        lines = []
        symbols = []
        for line in disassembly.split("\n"):
            address_start = line.find(" ") + 1
            while line[address_start:].startswith(" "):
                address_start += 1
            matches = [line[address_start:].find(" "), line[address_start:].find(":")]
            while -1 in matches:
                matches.remove(-1)
            if not matches:
                lines.append(line)
                continue

            address_end = min(matches) + address_start
            address = line[address_start: address_end].strip()
            if address.startswith(" "):
                address = address[1:]
            if not address:
                continue
            line = self.add_sym_address_to_line(line, address, with_symbol=with_symbols)
            if with_symbols:
                line, symbol = line
                symbols.append(symbol)
            lines.append(line)

        out = "\n".join(lines)
        if with_symbols:
            out = (out, symbols)
        return out

    def break_on_symbol(self, sym_name, to_string=False):
        """
        Add a breakpoint on gdb symbol
        :param sym_name:
        :param to_string:
        :return:
        """
        address = self.display_shellcode_symbols(only_return_address=True, name=sym_name)
        if address:
            return gdb.execute("b *{}".format(hex(address)), to_string=to_string)
        else:

            message = "Address for symbol: {} not found !".format(sym_name)
            if not to_string:
                print(message)
            return message

    def get_current_symbol(self):
        """
        Get symbol at pc
        :return:
        """
        disassembly = gdb.execute("x/1i $pc", to_string=True)
        data, symbols = self.add_symbols_to_disassembly(disassembly, True)
        if symbols:
            return symbols[0]

    def my_continue(self):
        """
        Gdb continue wrapper
        :return:
        """
        gdb.execute("c")
        sym = self.get_current_symbol()
        if sym:
            print("----> {}".format(sym))

    def disassm(self):
        """
        Disassembly wrapper at pc
        :return:
        """
        return self._disassm("$pc")

    def _disassm(self, add):
        """
        Disassemble and display symbols
        :param add:
        :return:
        """
        try:
            add = eval(add)
        except Exception as e:
            pass
        disassembly = gdb.execute("x/10i {}".format(add), to_string=True)
        try:
            disassembly = self.add_symbols_to_disassembly(disassembly)
        except Exception as e:
            print("Disassembly exception: {}".format(e))
            pass
        print(disassembly)

    @staticmethod
    def exit():
        """
        Exit and return
        :return:
        """
        try:
            gdb.execute("detach")
        except:
            pass
        gdb.execute("quit")

    @staticmethod
    def get_stdout(should_print=True):
        """
        :return: Shellcode standard output
        """
        with open(consts.debugger_stdout, 'r') as fp:
            data = fp.read()
        if should_print:
            print(data)
        return data

    def enable_profiling(self):
        self.profiling_enabled = True

    def disable_profiling(self):
        self.profiling_enabled = False

    def enable_verbose_exceptions(self):
        self.verbose_exceptions = True
        print("[*] Verbose exceptions enabled")

    @staticmethod
    def error_occurred(message):
        errors = ['Program received signal', 'Program terminated']
        for error in errors:
            if error in message:
                return True
        return False

    def generic_execute_until_error(self, cmd):
        try:
            gdb.execute("set pagination off", to_string=False)
            last_mni = gdb.execute(cmd, to_string=True)
            current_mni = gdb.execute(cmd, to_string=True)
            print(current_mni)
            while last_mni != current_mni or self.error_occurred(current_mni):
                last_mni = copy.copy(current_mni)
                current_mni = gdb.execute(cmd, to_string=True)
                print(current_mni)
        finally:
            gdb.execute("set pagination on", to_string=True)

    def step_to_end(self):
        self.generic_execute_until_error("mni")

    def shellcode_debug(self):
        gdb.execute("break_on_shellcode_main")
        for symbol in self.symbols:
            sym_name, sym_address, sym_size = symbol
            self.break_on_symbol(sym_name, to_string=True)
        self.generic_execute_until_error("mc")

    def execute(self, instruction, *args, **kwargs):
        if hasattr(self, instruction):
            handler = getattr(self, instruction)
        else:
            print("No handler for instruction: {} found".format(instruction))
            return

        try:
            pr = None
            if self.profiling_enabled:
                pr = cProfile.Profile()
                pr.enable()
            handler(*args, **kwargs)
            if self.profiling_enabled:
                pr.disable()
                pr.print_stats(sort=1)
        except Exception as e:
            if self.verbose_exceptions:
                traceback.print_exc()
            print("Error executing: {}, {}, try help user-defined".format(instruction, e))


api_handler = GdbGeneralCommandsApi()
