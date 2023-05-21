import time
import subprocess
import sys
import os
import logging
import select
from elftools.elf.elffile import ELFFile
from shelf.lib.consts import Arches as ShelfArches
from shelf.api import ShelfBinaryApi
from shelf_loader.resources import get_resource_path
from shelf_loader import consts
from shelf_loader.extractors import all as extractors


def get_loader(mode, arch):
    if mode == consts.LoaderTypes.ESHELF:
        return ""
    postfix = ""
    if mode == consts.LoaderTypes.NO_RWX:
        postfix = "no_rwx_"

    return get_resource_path("shellcode_loader_{}{}.out".format(
        postfix,
        arch
    ))


class ShellcodeLoaderGeneric(object):
    def __init__(self, args, argv, parser):
        self.args = args
        self._argv = argv
        self.disable_timeout = False
        mode = consts.LoaderTypes.REGULAR
        with open(self.args.shellcode_path, 'rb') as fp:
            arch = "Unknown"
            data = fp.read()
            if data.startswith(b'\x7fELF'):
                logging.info("Assuming eshelf mode")
                mode = consts.LoaderTypes.ESHELF
                fp.seek(0)
                elf = ELFFile(fp)
                arch = ShelfArches.translate_from_ident(elf.header.e_machine,
                                                        elf.header.e_ident.EI_CLASS)
            else:
                binary_api = ShelfBinaryApi(
                    data
                )
                version, features = binary_api.format_utils.get_shelf_features()
                logging.info("Shelf version: {}, shelf features: {}".format(
                    version,
                    features
                ))
                arch = features.arch.value
        if self.args.no_rwx_memory:
            if not mode == consts.LoaderTypes.REGULAR:
                print("Error --no-rwx-memory can't be used with loader type: {}".format(mode))
                sys.exit(1)
            mode = consts.LoaderTypes.NO_RWX
        self.arch = arch
        setattr(self.args, 'arch', self.arch)

        self.loader = get_loader(mode, self.arch)
        if self.loader and not os.path.exists(self.loader):
            parser.error("Shellcode loader: {} not found change loader directory".format(
                self.loader
            ))

    @property
    def argv(self):
        return self._argv

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
            rlist, _, _ = select.select([process.stdout, process.stderr], [], [], 0.0001)
            if process.stdout in rlist:
                stdout += process.stdout.read()
            if process.stderr in rlist:
                stderr += process.stderr.read()

            if (time.time() - start) > self.args.timeout:
                if self.disable_timeout:
                    continue
                timeout_passed = True
                break
        if timeout_passed:
            subprocess.call("kill -9 {}".format(process.pid), shell=True)
            print("Timeout reached, use --timeout to extend execution time")

        rlist, _, _ = select.select([process.stdout, process.stderr], [], [], 0.0001)
        if process.stdout in rlist:
            stdout += process.stdout.read()
        if process.stderr in rlist:
            stderr += process.stderr.read()

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
        if self.loader:
            command.append(self.loader)
        command.append(self.args.shellcode_path)
        command += self.argv
        return command


LOADER_CLS = {
    consts.LoaderTypes.REGULAR.value: RegularShellcodeLoader
}
