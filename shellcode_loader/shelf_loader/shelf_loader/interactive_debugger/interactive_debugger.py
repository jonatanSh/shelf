import readline

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
        self.loader = loader
        self.commands = {
            '?': self.help,
            'help': self.help,
            'rebase': self.rebase
        }
        self.auto_complete = get_auto_complete(self.commands.keys())
        self.base_address = 0x0
        readline.parse_and_bind("history")
        readline.set_completer(self.auto_complete)

    @staticmethod
    def shell_print(args):
        print(args)

    def embed(self):
        should_break = False
        self.shell_print(BANNER)
        while not should_break:
            try:
                self.handle_commands()
            except KeyboardInterrupt:
                should_break = True

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
