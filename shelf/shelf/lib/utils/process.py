import select
import time
from shelf.lib.consts import Process


class ProcessExecutionOutput(object):
    def __init__(self, stdout, stderr, timeout_passed):
        self.stdout = stdout
        self.stderr = stderr
        self.timeout_passed = timeout_passed

    def __str__(self):
        return "Process(stdout_len={}, stderr_len={}, timeout_passed={})".format(
            len(self.stdout),
            len(self.stderr),
            self.timeout_passed
        )


def process_selective_read(process):
    stdout = b''
    stderr = b''
    rlist, _, _ = select.select([process.stdout, process.stderr], [], [], 0.0001)
    if process.stdout in rlist:
        stdout += process.stdout.read()
    if process.stderr in rlist:
        stderr += process.stderr.read()

    return stdout, stderr


def communicate_with_timeout(process, timeout=Process.timeout):
    stdout = b''
    stderr = b''
    start = time.time()
    timeout_passed = False
    while process.poll() is None:
        new_stdout, new_stderr = process_selective_read(process)
        stdout += new_stdout
        stderr += new_stderr
        if (time.time() - start) > timeout:
            timeout_passed = True
            break
    # Finally, performing last selective read
    new_stdout, new_stderr = process_selective_read(process)
    stdout += new_stdout
    stderr += new_stderr
    return ProcessExecutionOutput(
        stdout=stdout,
        stderr=stderr,
        timeout_passed=timeout_passed
    )
