import time
import subprocess
import sys
import os
import logging
from shelf.api import ShelfBinaryApi
from shelf_loader.resources import get_resource_path
from shelf_loader import consts
from shelf_loader.extractors import all as extractors

def get_loader(arch):
    return get_resource_path("shellcode_loader_{}.out".format(
        arch
    ))


class ShellcodeLoaderGeneric(object):
    def __init__(self, args, parser):
        self.args = args
        self.disable_timeout = False
        with open(self.args.shellcode_path, 'rb') as fp:
            self.binary_api = ShelfBinaryApi(
                fp.read()
            )
        self.version, self.features = self.binary_api.format_utils.get_shelf_features()
        logging.info("Shel version: {}, shelf features: {}".format(
            self.version,
            self.features
        ))
        self.arch = self.features.arch.value
        setattr(self.args, 'arch', self.arch)

        self.loader = get_loader(self.arch)
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
        stdout, stderr = b'', b''
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start = time.time()
        timeout_passed = False
        while process.poll() is None:
            stdout += process.stdout.read()
            stderr += process.stdout.read()

            if (time.time() - start) > self.args.timeout:
                if self.disable_timeout:
                    continue
                timeout_passed = True
                break
        if timeout_passed:
            subprocess.call("kill -9 {}".format(process.pid), shell=True)
        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        extractor_data = {}
        for extractor_cls in extractors:
            extractor = extractor_cls(stdout, self.args,
                                      extractor_data)

            stdout, extractor_context = extractor.parsed
            extractor_data.update(extractor_context)

        sys.stdout.write(stdout)
        sys.stderr.write(stderr)


class RegularShellcodeLoader(ShellcodeLoaderGeneric):
    def _get_loading_command(self, prefix=[]):
        command = []
        qemu = consts.QEMUS[self.arch]
        command.append(qemu)
        command += prefix
        command.append(self.loader)
        command.append(self.args.shellcode_path)
        return command


LOADER_CLS = {
    consts.LoaderTypes.REGULAR.value: RegularShellcodeLoader
}
