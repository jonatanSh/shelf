# Shelf python api

#### Usage

```python
from shelf.api import ShelfApi

api = ShelfApi("/bin/sh")

print(api.shelf.arch)

# Do objdump:
api.shelf.do_objdump(api.shelf.shellcode_data)

# Get segments loaded into memory
api.shelf.get_segments_in_memory()

# Get symbol name for its address:
api.shelf.get_symbol_name_from_address(address=0xdeadbeef)

# Get symbol address
print(api.shelf.find_symbols("test"))
# Get relative symbol address
print(api.shelf.find_symbols("test", return_relative_address=True))
# Get all symbols:
for symbol_name, symbol_address, symbol_size in api.shelf.find_symbols():
    print("Symbol: {} at: {} size: {}".format(
        symbol_name,
        hex(symbol_address),
        symbol_size
    ))
```