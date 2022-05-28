import sys
from elf_to_shellcode.relocate import make_shellcode

if len(sys.argv) < 4:
    print("Usage <input> <arch> <endian> <glibc|no_startfiles> <output|optional>")
    sys.exit(1)
input_file = sys.argv[1]
arch = sys.argv[2]
endian = sys.argv[3]
libc = sys.argv[4]
if libc not in ['no', 'glibc']:
    print("Please use:\nglibc - for glibc start files")
    print("no - for no start files usage")
    sys.exit(1)

if len(sys.argv) > 5:
    output_file = sys.argv[5]
else:
    output_file = input_file + "{0}.out.shell".format(arch)

with open(output_file, "wb") as fp:
    fp.write(make_shellcode(input_file, arch=arch, endian=endian,
                            start_file_method=libc))

print("Created: {}".format(output_file))
