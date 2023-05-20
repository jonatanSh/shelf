import os
import sys
import argparse
import logging
from shellcode_loader.library.shelf_loader.consts import LoaderTypes
from shellcode_loader.library.shelf_loader.loader import LOADER_CLS

parser = argparse.ArgumentParser("ShellcodeLoader")
parser.add_argument('shellcode_path', help='Path to shellcode file to load')
parser.add_argument("--originating-binary", help="The binary the shellcode was converted from"
                                                 "This argument is not required but for some features"
                                                 "Such as disassembly this argument is required")
parser.add_argument("--verbose", action="store_true", default=False, required=False,
                    help="Verbose logging")
parser.add_argument("--strace", help="Run strace against the shellcode", required=False,
                    default=False, action="store_true")

parser.add_argument("--loader-type", choices=[loader_type.value for loader_type in LoaderTypes],
                    required=False, default=LoaderTypes.REGULAR.value)
parser.add_argument("--timeout", help="Timeout for process to die in seconds", required=False,
                    type=int, default=5)

args = parser.parse_args()

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
    loader = cls(args=args, parser=parser)
    loader.run()


if __name__ == "__main__":
    main()
