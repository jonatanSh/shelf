from shelf.api import ShelfApi


def extract_relative_symbol_address(binary_path):
    api = ShelfApi(binary_path=binary_path)
    shelf = api.shelf
    loading_virtual_address = shelf.loading_virtual_address
    symbols = []
    for symbol in shelf.find_symbols():
        symbol_name, symbol_address, symbol_size = symbol
        if symbol_address < loading_virtual_address:
            continue
        symbols.append(
            (symbol_name, symbol_address - loading_virtual_address, symbol_size)
        )
    return symbols
