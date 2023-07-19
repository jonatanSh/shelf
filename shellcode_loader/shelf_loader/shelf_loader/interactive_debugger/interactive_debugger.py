import logging
import os.path
import subprocess
from shelf_loader import consts

BANNER = """
    Interactive shell, to view all commands use ?
"""


class InteractiveDebugger(object):
    def __init__(self, loader):
        self.should_break = False
        self.loader = loader
        self.commands = {
            '?': self.help,
            'help': self.help,
            'rebase': self.rebase,
            'gdb': self.gdb,
            'exit': self.exit,
            'ipython': self.ipython
        }

    @staticmethod
    def shell_print(args):
        print(args)

    def embed(self):
        self.shell_print(BANNER)
        while not self.should_break:
            try:
                self.handle_commands()
            except KeyboardInterrupt:
                self.should_break = True

    @staticmethod
    def shell_read_arguments(prompt):
        return input("{} ".format(prompt))

    def handle_commands(self):
        input_line = self.shell_read_arguments(">")
        command = self.commands.get(input_line)
        if not command:
            self.shell_print("Unknown command: {} use ? for help".format(input_line))
        else:
            command()

    def help(self):
        self.shell_print(BANNER)
        self.shell_print("Commands:")
        for command in self.commands:
            self.shell_print(command)

    def rebase(self):
        value = int(self.shell_read_arguments('> Enter the loading address in hex'), 16)
        self.shell_print("Rebasing to: {}".format(hex(value)))
        self.base_address = value

    def gdb(self):
        script_directory = os.path.join(consts.BASE_DIR, 'interactive_debugger',
                                        'gdb_scripts')
        gdb_main_script = os.path.join(script_directory, 'gdb_main.py')
        gdb_utils_script = os.path.join(script_directory, 'gdb_utils.gdb')

        """
            Basic gdb setup command including setting the architecture
            and initializing gdb scripts
        """
        setup_commands = ['set architecture {}'.format(consts.GDB_ARCHES[self.loader.arch]),
                          'source {}'.format(gdb_main_script),
                          'source {}'.format(gdb_utils_script),
                          ]

        # Adding intel disassembly flavor
        if self.loader.arch in [consts.Arches.intel_x32.value, consts.Arches.intel_x64.value]:
            setup_commands.append('set disassembly-flavor intel')

        # Add loader symbols, think about eshelf ?
        if self.loader.loader:
            setup_commands.append("file {}".format(self.loader.loader))

        # This must be the last setup command
        setup_commands.append('target extended-remote localhost:{}'.format(self.loader.args.debugger_port))
        setup_commands.append("python api_handler.construct(r'{}')".format(self.loader.args.source_elf))
        command = ["gdb-multiarch"]
        for setup_command in setup_commands:
            command += ['-iex', "{}".format(setup_command)]

        logging.info("Executing: {}".format(command))
        subprocess.call(command)
        self.exit()

    def ipython(self):
        print("Embeding ipython interactive shell")
        import IPython
        IPython.embed()

    def exit(self):
        self.should_break = True

    def terminate(self):
        # Termination methods for shell
        pass
