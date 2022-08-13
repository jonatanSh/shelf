import logging
from elf_to_shellcode.arguments import ARGUMENTS, change_argument


def setup_logging():
    if ARGUMENTS.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.info("Verbose level: DEBUG")


def setup_output_files():
    if ARGUMENTS.output:
        output_file = ARGUMENTS.output
    else:
        output_file = ARGUMENTS.input + "{0}.out.shell".format(ARGUMENTS.arch)

    change_argument("output_file", output_file)


def setup():
    setup_logging()
    setup_output_files()
