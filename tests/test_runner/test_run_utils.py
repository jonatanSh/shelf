import os
import time
import subprocess
import itertools
import logging
from test_runner.consts import CONSTS, TestFeatures, LoaderTypes


class TestOutput(object):
    def __init__(self, description, arch, test_file, loader_file, args):
        self.description = description
        self.arch = arch
        self.reason = ""
        self.success = False
        self.has_reason = False
        self._stdout = ""
        self._stderr = ""
        self.test_file = test_file
        self.loader_file = loader_file
        self.args = args

        self._parsed = ""
        self.test_file_elf = test_file[:test_file.find(".out") + len(".out")]
        self.context = {
            'arch': arch,
            'shellcode': test_file,
            'elf': self.test_file_elf,
            'loader_file': loader_file if loader_file else self.test_file_elf
        }

    def prepare(self, success, reason, stdout="", stderr=""):
        self.reason = reason
        self.success = success
        self._stderr = stderr
        self._stdout = stdout
        self.has_reason = True
        return self

    @property
    def parsed(self):
        if not self._parsed:
            if self.success:
                self.reason = "Success"
            if not self.success:
                self.reason = "Failure {}".format(
                    self.reason
                )
            self._parsed = "{} - {} ... {}".format(self.arch, self.description,
                                                   self.reason)

        return self._parsed

    @property
    def stderr(self):
        return self._stderr

    @property
    def stdout(self):
        stdout_extracted = self._stdout
        return stdout_extracted

    def __str__(self):
        return self.parsed


def get_test_command(test_file, description, loader_type, arch, is_debug, is_strace, is_eshelf, **kwargs):
    loader = None
    test_output = TestOutput(description=description, arch=arch, test_file=test_file,
                             loader_file=loader,
                             args=kwargs)
    assert not all([is_strace, is_debug]), "Only --strace or --debug is available"

    if not os.path.exists(test_file):
        return None, test_output.prepare(
            reason="File: {} not found".format(test_file),
            success=False
        )
    test_elf = test_file[:test_file.find(".out") + len(".out")]
    command = ["python3", "-m", 'shelf_loader', test_file, '--source-elf', test_elf]
    if loader_type == LoaderTypes.RX_LOADER:
        command += ["--no-rwx-memory"]
    if is_eshelf:
        command.append("First_Argument_for_argv")
        command.append("Second argument for argv")
    command = [str(v) for v in command]
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
    check_rc = parameters.get("check_rc", True)
    if check_rc and not is_return_code_ok(stdout):
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
        is_strace=is_strace,
        is_verbose=is_verbose

    )
    if test_output.has_reason:
        return test_output
    command = " ".join(command)
    if is_verbose:
        print(command)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    start = time.time()
    timeout_passed = False
    stdout, stderr = b"", b""
    while process.poll() is None:
        stdout = process.stdout.read()
        stderr += process.stderr.read()

        if (time.time() - start) > CONSTS.execution_timeout_seconds.value:
            if is_debug:
                continue
            timeout_passed = True
            break
    if timeout_passed:
        subprocess.call("kill -9 {}".format(process.pid), shell=True)
        return test_output.prepare(
            success=False,
            reason="Timed out"
        )

    stdout = stdout.decode('utf-8')
    stderr = stderr.decode('utf-8')
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
