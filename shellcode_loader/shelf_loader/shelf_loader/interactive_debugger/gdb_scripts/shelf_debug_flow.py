import gdb


class DebugFlowManager(object):
    def __init__(self, api):
        self.api = api
        self.breakpoints = [
            'loader_main',
            'loader_handle_relocation_table',
            'loader_call_main',
        ]

    def install_breakpoints(self):
        for breakpoint_symbol in self.breakpoints:
            print("Installing breakpoint on: {}".format(breakpoint_symbol))
            self.add_breakpoint_for_symbol(breakpoint_symbol)

    def run(self):
        print("Going to mini loader entry point")
        self.execute("execute_shellcode")
        print("Running Shelf interactive flow manager")
        self.install_breakpoints()
        print("Executing")
        self.execute("mc")

    def add_breakpoint_for_symbol(self, sym_name):
        self.api.break_on_symbol(sym_name)

    @staticmethod
    def execute(f):
        gdb.execute(f)
