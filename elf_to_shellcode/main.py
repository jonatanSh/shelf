import sys
from elf_to_shellcode.relocate import make_shellcode

if len(sys.argv) < 3:
    print("Usage <input> <arch> <endian> <output|optional>")
    sys.exit(1)
input_file = sys.argv[1]
arch = sys.argv[2]
endian = sys.argv[3]

if len(sys.argv) > 4:
    output_file = sys.argv[4]
else:
    output_file = input_file + "{0}.out.shell".format(arch)

with open(output_file, "wb") as fp:
    fp.write(make_shellcode(input_file, arch=arch, endian=endian))

print("Created: {}".format(output_file))
