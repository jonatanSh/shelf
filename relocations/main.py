import sys
from relocations import relocate

if len(sys.argv) < 3:
    print("Usage <input> <new_base> <output|optional>")
    sys.exit(1)
input_file = sys.argv[1]
new_base = int(sys.argv[2], 16)

if len(sys.argv) > 3:
    output_file = sys.argv[3]
else:
    output_file = input_file + "relocated_{0}.out.shell".format(hex(new_base))

with open(output_file, "wb") as fp:
    fp.write(relocate(input_file, new_base))