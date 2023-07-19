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

### Plugins:

##### Memory dump plugin
Shelf provide api to examine memory containing shelf binary.
if a dump is occurred then you can create a dump object and interact with it
```python
from shelf.api import ShelfApi
api = ShelfApi("/bin/sh")
dump_data = b'<dump_data>'
dump = api.shelf.memory_dump_plugin.construct_shelf_from_memory_dump(
    memory_dump=dump_data,
    dump_address=0x20,
    loading_address=0x10
)

# Provide disassembly of the dump
dump.dissamble()

# Compute absolute memory addresses
matching_symbols = api.shelf.find_symbols(symbol_name='main')
symbol_name, symbol_address, function_size = matching_symbols[0]
absolute_address = dump.compute_absolute_address(symbol_address)
compute_absolute_address()
```