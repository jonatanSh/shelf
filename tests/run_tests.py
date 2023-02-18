import os
import subprocess
from subprocess import PIPE
from argparse import ArgumentParser
import logging

parser = ArgumentParser("testRunner")

arch = os.uname()[-1]

QEMUS = {
    "mips": "qemu-mips-static",
    "intel_x32": "qemu-i386-static",
    "intel_x64": "qemu-x86_64-static",
    "arm32": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static"
}
# Prefer no emulation if running on x64 host !
if arch == 'x86_64':
    QEMUS['intel_x64'] = ""

test_cases = {
    'elf_features': ["../outputs/elf_features_{}.out.shellcode", ['all'], "__Test_output_Success"],
    'no_relocations': ["../outputs/no_relocations_{}.out.shellcode", ['intel_x32', 'aarch64'], 'Hello'],
    'eshelf': ['../outputs/elf_features_{}.out.shellcode.eshelf', ['intel_x64', 'intel_x32', 'mips', 'arm32'], 'Hello'],
    'dynamic_elf_features': ['../outputs/dynamic_elf_features_{}.out.shellcode', ['mips', 'intel_x32'], 'Hello'],

}


def translate_to_binary_name(arch):
    if arch != "mips":
        return arch
    else:
        return "mipsbe"


def run_arch_tests(arch, case):
    qemu = QEMUS[arch]
    loader = "../outputs/shellcode_loader_{}.out".format(arch)
    tests = [case]
    if case == "all":
        tests = test_cases.keys()
    for test_case in tests:
        case, supported_arches, success = test_cases[test_case]
        if supported_arches != ['all']:
            if arch not in supported_arches:
                continue
        test = case.format(translate_to_binary_name(arch))
        db_arg = "-g 1234" if args.debug else ""
        assert os.path.exists(loader), "Error loader doesn't exists for: {}".format(arch)
        assert os.path.exists(test), "Error test for: {}_{} does not exists".format(
            arch,
            case
        )
        if test_case != 'eshelf':
            command = "{} {} {} {}".format(qemu, db_arg, loader, test)
        else:
            command = '{} {} {} "First_Argument_for_argv" "Second argument for argv"'.format(qemu, db_arg, test)
        if not args.only_stdout:
            print("-" * 30)
        if args.debug:
            print("Waiting for debugger at: {}".format(1234))
            print(command)
        logging.info("Running command: {}".format(command))
        stdout, stderr = subprocess.Popen(command, shell=True, stdout=PIPE, stderr=PIPE).communicate()
        if args.only_stdout:
            print(stdout)
            print(stderr)
            continue
        if success in stdout and ('core dumped' not in stderr and 'core dumped' not in stdout):
            key = "Shellcode returned: "
            index = stdout.find(key)
            final_status = "Failure, reason: RC"

            if index != -1:
                index += len(key)
                loader_output = stdout[index:]
                value = loader_output[:loader_output.find("\n") + 1].strip()
                value = int(value.strip(), 16)
                if value == 0x12468:
                    final_status = "Success"
                else:
                    final_status = "Failure, reason: RC"
            """
            We don't check the return code in eshelf modes due to it being irrelevant
            """
            if 'ESHELF exit, RC is irrelevant' in stdout:
                final_status = "Success"
            print("test: {}({}) ... {}".format(test_case, arch, final_status))
        else:
            print("test: {} for: {} ... Failure, use --verbose-on-failed to see output".format(test_case, arch))
            if args.verbose_on_failed:
                print stdout, stderr
        if args.verbose:
            logging.info("Stdout: {}".format(
                stdout
            ))
            logging.info("Stderr: {}".format(
                stderr
            ))
        print("-" * 30)
        print("\n")


def main(arch, case, *args):
    if arch == "all":
        for key in QEMUS.keys():
            run_arch_tests(key, case)
    else:
        run_arch_tests(arch, case)


usage_printed = False

arch_choices = QEMUS.keys() + ["all"]
tests = test_cases.keys() + ['all']
parser.add_argument("--arch", choices=arch_choices, required=False, default="all")
parser.add_argument("--test", choices=tests, required=False, default="all")
parser.add_argument("--debug", default=False, action="store_true", required=False, help="Run qemu on local port 1234")
parser.add_argument("--verbose", default=False, action="store_true", required=False)
parser.add_argument("--only-stdout", default=False, required=False, action="store_true",
                    help="Run and only display stdout and stderr")
parser.add_argument("--verbose-on-failed", default=False, action="store_true", required=False)

args = parser.parse_args()
if args.verbose:
    assert not args.only_stdout, "error --only-stdout and --verbose dont work togther"
    logging.basicConfig(level=logging.INFO)
main(arch=args.arch, case=args.test)
