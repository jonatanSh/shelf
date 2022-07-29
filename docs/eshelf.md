# ESHELF - Elf Shellcode ELF
This format wrap the output SHELF shellcode into a standalone elf.
This format is used for debug pruposes


```mermaid
  classDiagram
    ELF --|> TextSection
    TextSection: SHELF (shellcode)
```

## how to use
just add the following outputing option
```python
--output-fmt eshelf
```