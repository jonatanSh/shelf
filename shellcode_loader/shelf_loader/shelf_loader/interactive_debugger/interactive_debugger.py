import sys
import logging
import os.path
import readline
import subprocess
from shelf_loader import consts

BANNER = """
    Interactive shell, to view all commands use ?
"""


def get_auto_complete(options):
    def complete(text, state):
        matches = [option for option in options if option.startswith(text)]
        return matches[state] if state < len(matches) else None

    return complete


class InteractiveDebugger(object):
    def __init__(self, loader):
        self.should_break = False
        self.loader = loader
        self.commands = {
            '?': self.help,
            'help': self.help,
            'rebase': self.rebase,
            'gdb': self.gdb,
            'exit': self.exit
        }
        self.auto_complete = get_auto_complete(self.commands.keys())
        readline.parse_and_bind("history")
        readline.set_completer(self.auto_complete)

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
        setup_commands = ['set architecture {}'.format(consts.GDB_ARCHES[self.loader.arch])]
        command = ["gdb-multiarch", '-iex', '"source {}"'.format(gdb_main_script)
                   ]
        for setup_command in setup_commands:
            command += ['-iex', "{}".format(setup_command)]
        logging.info("Executing: {}".format(command))
        subprocess.call(command)

    def exit(self):
        self.should_break = True
