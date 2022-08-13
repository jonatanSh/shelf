from elf_to_shellcode.arguments import ARGUMENTS
from elf_to_shellcode.arches import get_shellcode_class
from elf_to_shellcode.lib import five
from elf_to_shellcode.cli import setup_cli
from elf_to_shellcode.lib.utils import OsUtils, try_and_log, FunctionDescriptor

try:
    from IPython import embed
except ImportError:
    embed = None


def embed_exception():
    raise Exception("IPython.embed not found, try to install ipython")


if not embed:
    embed = embed_exception()


def main():
    setup_cli()

    with open(ARGUMENTS.output_file, "wb") as fp:
        shellcode = get_shellcode_class()

        if ARGUMENTS.interactive:
            embed()

        fp.write(five.to_file(shellcode.get_shellcode()))

        try_and_log(FunctionDescriptor(OsUtils.chmod_execute, file_path=ARGUMENTS.output_file))

    print("Created: {}".format(ARGUMENTS.output_file))


if __name__ == "__main__":
    main()
