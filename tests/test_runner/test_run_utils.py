import os
import time
import subprocess
import itertools
import logging
from test_runner.consts import Resolver, CONSTS, TestFeatures, LoaderTypes


class TestOutput(object):
    def __init__(self, description, arch):
        self.description = description
        self.arch = arch
        self.reason = ""
        self.success = False
        self.has_reason = False
        self.stdout = ""
        self.stderr = ""

    def prepare(self, success, reason, stdout="", stderr=""):
        self.reason = reason
        self.success = success
        self.stderr = stderr
        self.stdout = stdout
        self.has_reason = True
        return self

    def __str__(self):
        if self.success:
            self.reason = "Success"
        if not self.success:
            self.reason = "Failure {}".format(
                self.reason
            )
        return "{} - {} ... {}".format(self.arch, self.description,
                                       self.reason)


def get_test_command(test_file, description, loader_type, arch, is_debug, is_strace, is_eshelf, **kwargs):
    test_output = TestOutput(description=description, arch=arch)
    assert not all([is_strace, is_debug]), "Only --strace or --debug is available"
    command = [Resolver.get_qemu(arch)]
    if is_debug:
        command.append("-g")
        command.append(str(CONSTS.DEBUG_PORT))

    if is_strace:
        command.append("-strace")

    if not is_eshelf:
        loader = Resolver.get_loader(loader_type, arch)
        command.append(loader)
        if not os.path.exists(loader):
            return None, test_output.prepare(reason="Loader {} not found".format(
                loader
            ), success=False)

    if not os.path.exists(test_file):
        return None, test_output.prepare(
            reason="File: {} not found".format(test_file),
            success=False
        )
    command.append(test_file)

    if is_eshelf:
        command.append("First_Argument_for_argv")
        command.append("Second argument for argv")

    return command, test_output


def is_return_code_ok(stdout):
    key = "Shellcode returned: "
    index = stdout.find(key)

    if index != -1:
        index += len(key)
        loader_output = stdout[index:]
        value = loader_output[:loader_output.find("\n") + 1].strip()
        value = int(value.strip(), 16)
        if value == 0x12468:
            return True
        else:
            return False
    """
    We don't check the return code in eshelf modes due to it being irrelevant
    """
    if 'ESHELF exit, RC is irrelevant' in stdout:
        return True


def generic_success_method(stdout, parameters):
    success = True
    reason = ""
    if not is_return_code_ok(stdout):
        return False, "RC"

    for success_param in parameters['success']:
        if success_param not in stdout:
            success = False

    return success, reason


def test_find_file(test_fmt, arch, features):
    if not features:
        return test_fmt.format(arch, "")
    for perm in itertools.permutations(features):
        t_f = test_fmt.format(arch,
                              ".{}".format(".".join([p.value for p in perm])))
        logging.info("Checking test file: {}".format(t_f))
        if os.path.exists(t_f):
            return t_f
    return None


def run_test(key, test_parameters, test_features, description, arch, is_strace, is_debug,
             is_verbose=False,
             success_method=generic_success_method):
    test_file = test_find_file(test_parameters['test_file_fmt'], arch, test_features)
    if not test_file:
        raise Exception("Error test for: {} with features: {} not found".format(
            key,
            test_features,
        ))
    loader_type = LoaderTypes.RWX_LOADER
    if TestFeatures.NORWX in test_features:
        loader_type = LoaderTypes.RX_LOADER
    command, test_output = get_test_command(
        test_file=test_file,
        arch=arch,
        description=description,
        is_eshelf=TestFeatures.ESHELF in test_features,
        loader_type=loader_type,
        is_debug=is_debug,
        is_strace=is_strace

    )
    if test_output.has_reason:
        return test_output
    command = " ".join(command)
    if is_verbose:
        print(command)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    start = time.time()
    timeout_passed = False

    while process.poll() is None:
        if (time.time() - start) > CONSTS.execution_timeout_seconds.value:
            timeout_passed = True
            break
    if timeout_passed:
        subprocess.call("kill -9 {}".format(process.pid), shell=True)
        return test_output.prepare(
            success=False,
            reason="Timed out"
        )

    stdout, stderr = process.communicate()
    if 'core dumped' in stderr or 'core dumped' in stdout:
        return test_output.prepare(
            success=False,
            reason="Crash!",
            stdout=stdout,
            stderr=stderr
        )
    is_success, reason = success_method(stdout, test_parameters)
    return test_output.prepare(success=is_success,
                               stdout=stdout,
                               stderr=stderr,
                               reason=reason)


def test_banner():
    print("-" * 30)
    print("\n")


def arch_banner(arch):
    lsize = 15
    rsize = 15 + int(len(arch) % 2)
    asize = (lsize + rsize + len(arch) + 2)
    banner = ["@" * asize,
              "@" + " " * lsize + arch + " " * rsize + "@",
              "@" * asize
              ]
    print("\n".join(banner))


def display_output(test_output, is_verbose):
    print(test_output)
    if is_verbose:
        print("Stdout:")
        print(test_output.stdout)
        print("Stderr:")
        print(test_output.stderr)
