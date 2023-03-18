import sys
import os
import stat
import logging
from argparse import ArgumentParser
from elf_to_shellcode.relocate import make_shellcode, Arches, ENDIANS, StartFiles
from elf_to_shellcode.lib.consts import LoaderSupports, OUTPUT_FORMATS
from elf_to_shellcode.lib import five
from elf_to_shellcode.hooks.hooks_configuration_parser import is_valid_hooks_file
from elftools.elf.elffile import ELFFile

parser = ArgumentParser("ElfToShellcode")
parser.add_argument("--input", help="elf input file", required=True)
parser.add_argument("--output", default=None, help="Output file path")
parser.add_argument("--start-method", default=StartFiles.no_start_files,
                    choices=StartFiles.__all__, help="Start method required for full glibc usage")
parser.add_argument("--verbose", default=False, action="store_true", help="Verbose output")
parser.add_argument("--loader-supports",
                    choices=LoaderSupports.choices.keys(),
                    nargs="+",
                    required=False,
                    help="Loader additional features, this will increase the size of the static loader",
                    default=[])
parser.add_argument("--interactive",
                    default=False,
                    action="store_true",
                    help="Debug mode to open interactive cli with the shellcode class")
parser.add_argument("--output-format",
                    choices=OUTPUT_FORMATS,
                    required=False,
                    default='shelf',
                    help="Output format for shellcode, read more in the docs/output_format.md")
parser.add_argument("--loader-path",
                    help="Loader to use while creating the target shellcode",
                    default=None, required=False)
parser.add_argument("--loader-symbols-path",
                    required=False,
                    default=None,
                    help="Loader symbols to use while creating the shellcode"
                    )
parser.add_argument("--hooks-configuration", required=False,
                    help="Hooks configuration file, must be a valid python hook configuration file"
                         "for examples look at hook_configurations/simple_hello_hook.py under the project github page")
args = parser.parse_args()

if not os.path.exists(args.input):
    parser.error("--input does not exists")

with open(args.input, 'rb') as fp:
    elf = ELFFile(fp)
    setattr(args, "arch", Arches.translate_from_ident(elf.header.e_machine))
    endian = elf.header.e_ident.EI_DATA
    endians = {
        'ELFDATA2MSB': 'big',
        'ELFDATA2LSB': 'little'
    }
    endian = endians.get(endian)
    if not endian:
        raise Exception("Endian: {} not supported".format(endian))
    setattr(args, "endian", endian)


if args.hooks_configuration:
    if not os.path.exists(args.hooks_configuration):
        parser.error("--hook-configuration path: {} does not exists".format(
            args.hooks_configuration
        ))
    if not is_valid_hooks_file(args.hooks_configuration):
        parser.error(
            "--hook-configuration file {} is invalid, "
            "take a look at the github page under hook_configurations/simple_hello_hook.py".format(
                args.hooks_configuration
            ))
if any([args.loader_path, args.loader_symbols_path]) and not all([args.loader_path, args.loader_symbols_path]):
    parser.error("--loader-path and --loader-symbols-path must be used together")
    sys.exit(1)


sys.modules["global_args"] = args
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Verbose level: DEBUG")
else:
    logging.basicConfig(level=logging.CRITICAL)
if args.output:
    output_file = args.output
else:
    output_file = args.input + "{0}.out.shell".format(args.arch)

with open(output_file, "wb") as fp:
    shellcode, shellcode_repr = make_shellcode(arch=args.arch, endian=args.endian,
                                               start_file_method=args.start_method, args=args)
    fp.write(five.to_file(shellcode))
    st = os.stat(output_file)
    os.chmod(output_file, st.st_mode | stat.S_IEXEC)

print("Created: {}, from: {}".format(output_file, shellcode_repr))
