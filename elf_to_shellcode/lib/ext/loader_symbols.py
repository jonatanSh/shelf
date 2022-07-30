from elf_to_shellcode.resources import get_resource_path


class ShellcodeLoader(object):
    def __init__(self, symbols_path, loader_size):
        self.loader_symbols = symbols_path
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
        self.loader_size = loader_size
        self.base_address = self.symbols['loader_main']

    def get_relative_symbol_address(self, symbol_name):
        sym_rel = self.get_symbol_address(symbol_name) - self.base_address
        return sym_rel

    def has_symbol(self, symbol_name):
        return symbol_name in self.symbols

    def get_symbol_address(self, symbol_name):
        return self.symbols[symbol_name]