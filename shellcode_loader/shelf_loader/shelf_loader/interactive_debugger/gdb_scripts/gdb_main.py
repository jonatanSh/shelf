import gdb

HEADER = "SHELF LOADER GDB INTEGRATION"
print(HEADER)
gdb_ms = """
x/20i $pc
si
"""


def gdb_define(command_name, gdb_command):
    gdb.execute("define {}\n{}\nend".format(command_name, "\n".format(gdb_command)))


gdb_define('ms', gdb_ms)
