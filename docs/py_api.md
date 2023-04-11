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
```