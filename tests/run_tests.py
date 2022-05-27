import subprocess
from subprocess import Popen, PIPE
import sys

QEMUS = {
    "mips": "qemu-mips-static",
    "intel_x32": "qemu-i386-static",
    "intel_x64": "qemu-x86_64-static",
    "arm_32": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static"
}
test_cases = {
    'elf_features': ["../outputs/elf_features_{}.out.shellcode", ['all'], "Hello"],
    'no_relocations': ["../outputs/no_relocations_{}.out.shellcode", ['intel_x32', 'aarch64'], 'Hello']
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
        command = "{} {} {}".format(qemu, loader, test)
        stdout, stderr = subprocess.Popen(command, shell=True, stdout=PIPE, stderr=PIPE).communicate()
        if success in stdout:
            print("test: {} for: {} ... Success".format(test_case, arch))
        else:
            print("test: {} for: {} ... Failure, output:".format(test_case, arch))
            print stdout, stderr


def main(arch, case, *args):
    if arch == "all":
        for key in QEMUS.keys():
            run_arch_tests(key, case)
    else:
        run_arch_tests(arch, case)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.argv.append("all")
    if len(sys.argv) < 3:
        sys.argv.append("all")
    main(*sys.argv[1:])
