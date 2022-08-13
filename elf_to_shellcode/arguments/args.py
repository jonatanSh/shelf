import sys
from elf_to_shellcode.arguments.parser import parser

ARGS_KEY = "__shelf_cached_arguments"


def _get_args():
    args = parser.parse_args()

    if any([args.loader_path, args.loader_symbols_path]) and not all([args.loader_path, args.loader_symbols_path]):
        parser.error("--loader-path and --loader-symbols-path must be used together")
        sys.exit(1)

    return args


def get_args():
    if ARGS_KEY not in sys.modules:
        sys.modules[ARGS_KEY] = _get_args()
    return sys.modules[ARGS_KEY]


def change_argument(key, value):
    setattr(sys.modules[ARGS_KEY], key, value)


arguments = get_args()
