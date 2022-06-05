from elf_to_shellcode.elf_to_shellcode.resources import get_resource_path


class ShellcodeLoader(object):
    def __init__(self, loader_path):
        self.loader_symbols = get_resource_path(loader_path + ".symbols")
        self.symbols = {}
        self.base_address = 0
        with open(self.loader_symbols) as fp:
            for symbol in fp.readlines():
                try:
                    symbols = [sym for sym in symbol.split(" ") if sym]
                    name = symbols[-1]
                    address = int(symbols[1], 16)
                    self.symbols[name.strip()] = address
                except:
                    pass

        self.base_address = self.symbols['loader_main']

    def get_relative_symbol_address(self, symbol_name):
        return self.symbols[symbol_name] - self.base_address
