import time
import subprocess
import sys
import consts
import os


def get_loader(args):
    return os.path.join(args.loader_directory, "shellcode_loader_{}.out".format(
        args.arch
    ))


class ShellcodeLoaderGeneric(object):
    def __init__(self, args, parser):
        self.args = args
        self.disable_timeout = False
        self.loader = get_loader(args)
        if not os.path.exists(self.loader):
            parser.error("Shellcode loader: {} not found change loader directory".format(
                self.loader
            ))

    def _get_loading_command(self, prefix=[]):
        raise NotImplemented()

    def get_loading_command(self):
        prefix = []
        if self.args.strace:
            prefix += ["-strace"]

        return " ".join(self._get_loading_command(prefix))

    def run(self):
        command = self.get_loading_command()
        print(command)
        process = subprocess.Popen(command, shell=True, stdout=sys.stdout, stderr=sys.stderr)
        start = time.time()
        timeout_passed = False
        while process.poll() is None:

            if (time.time() - start) > self.args.timeout:
                if self.disable_timeout:
                    continue
                timeout_passed = True
                break
        if timeout_passed:
            subprocess.call("kill -9 {}".format(process.pid), shell=True)


class RegularShellcodeLoader(ShellcodeLoaderGeneric):
    def _get_loading_command(self, prefix=[]):
        command = []
        qemu = consts.QEMUS[self.args.arch]
        command.append(qemu)
        command += prefix
        command.append(self.loader)
        command.append(self.args.shellcode_path)
        return command


LOADER_CLS = {
    consts.LoaderTypes.REGULAR.value: RegularShellcodeLoader
}
