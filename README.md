# Elf to shellcode
Convert standard elf files to standalone shellcodes

# Who does this work ?
The python library parses the elf and create a simple relocatable file format
Then the mini loader is inserted as the entry point of the elf the mini loader
will load the relocatable format and execute it