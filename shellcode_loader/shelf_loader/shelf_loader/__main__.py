import os
import sys
import argparse
import logging
from shelf_loader.consts import LoaderTypes
from shelf_loader.loader import LOADER_CLS

parser = argparse.ArgumentParser("ShellcodeLoader")
parser.add_argument('shellcode_path', help='Path to shellcode file to load')
parser.add_argument("--verbose", action="store_true", default=False, required=False,
                    help="Verbose logging")
parser.add_argument("--strace", help="Run strace against the shellcode", required=False,
                    default=False, action="store_true")

parser.add_argument("--loader-type", choices=[loader_type.value for loader_type in LoaderTypes],
                    required=False, default=LoaderTypes.REGULAR.value)
parser.add_argument("--timeout", help="Timeout for process to die in seconds", required=False,
                    type=int, default=5)
parser.add_argument("--source-elf", help="""Source elf file if you provide the source elf file
The library provide more useful debug information on case of crash
                                         """)
parser.add_argument("--no-rwx-memory", default=False, action="store_true",
                    help="Use a loader that doesn't allocate RWX memory")

parser.add_argument("--disable-extractors", default=False, action="store_true",
                    help="Disable text extractors running on shellcode stdout such as the segfault handler extractor")
parser.add_argument("--attach-debugger", help="Run with qemu gdb support", required=False, action="store_true")
parser.add_argument("--debugger-port", required=False, type=int, default=1234,
                    help="used with --attach-debugger chooses the debugger port")
parser.add_argument("--limit-stdout", type=int, required=False, default=-1,
                    help="Limit stdout up to limit-stdout bytes")
parser.add_argument("--verbose-exceptions", required=False, action="store_true",
                    help="Print full traceback on exception")
args, unknown = parser.parse_known_args()

if args.verbose:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.CRITICAL)


def exit(message=None):
    if message:
        print(message)
    sys.exit(1)


def main():
    if not os.path.exists(args.shellcode_path):
        exit("Shellcode path doesn't exists")
    cls = LOADER_CLS[args.loader_type]
    loader = cls(args=args, argv=unknown, parser=parser)
    loader.run()


if __name__ == "__main__":
    main()
