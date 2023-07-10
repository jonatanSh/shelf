import signal
import time
import subprocess
import sys
import os
import logging
import select
import traceback
from elftools.elf.elffile import ELFFile
from shelf.lib.consts import Arches as ShelfArches
from shelf.lib.consts import LoaderSupports
from shelf.api import ShelfBinaryApi
from shelf_loader.resources import get_resource_path
from shelf_loader import consts
from shelf_loader.extractors import all as extractors
from shelf_loader.interactive_debugger.interactive_debugger import InteractiveDebugger


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
        self.disable_timeout = self.args.attach_debugger
        self.shell = InteractiveDebugger(self)
        mode = consts.LoaderTypes.REGULAR
        self.shelf_kwargs = {'loader_supports': []}

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
                if features.is_dynamic:
                    self.shelf_kwargs['loader_supports'].append(LoaderSupports.DYNAMIC)
                if features.has_hooks:
                    self.shelf_kwargs['loader_supports'].append(LoaderSupports.HOOKS)

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
            assert not self.args.attach_debugger, "Error --strace and --attach-debugger can't be used together"
            prefix += ["-strace"]
        if self.args.attach_debugger:
            prefix += ["-g", str(self.args.debugger_port)]

        return self._get_loading_command(prefix)

    def run(self):
        command = self.get_loading_command()
        print(" ".join(command))
        stdout, stderr = b'', b''
        stdout_f = subprocess.PIPE
        stderr_f = subprocess.PIPE
        if self.args.attach_debugger:
            stdout_f = open(consts.debugger_stdout, 'w')
            stderr_f = open(consts.debugger_stderr, 'w')
        process = subprocess.Popen(command, stdout=stdout_f, stderr=stderr_f)
        start = time.time()
        timeout_passed = False
        if self.args.attach_debugger:
            try:
                self.shell.embed()
            except Exception as error:
                if self.args.verbose_exceptions:
                    traceback.print_exc()
                else:
                    logging.error("In occurred in shell: {}".format(error))
        try:
            while process.poll() is None and not self.args.attach_debugger:
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
        except KeyboardInterrupt:
            timeout_passed = True
            pass
        self.shell.terminate()
        if process.poll() is None:
            logging.info("Killing pid: {}".format(process.pid))
            os.kill(process.pid, signal.SIGKILL)
        if timeout_passed:
            print("Timeout reached, use --timeout to extend execution time")
        if self.args.attach_debugger:
            stdout_f.close()
            stderr_f.close()
            return
        rlist, _, _ = select.select([process.stdout, process.stderr], [], [], 0.0001)
        if process.stdout in rlist:
            stdout += process.stdout.read()
        if process.stderr in rlist:
            stderr += process.stderr.read()

        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        extractor_data = {'shelf_kwargs': self.shelf_kwargs}
        if not self.args.disable_extractors:
            for extractor_cls in extractors:
                try:
                    extractor = extractor_cls(stdout, self.args,
                                              extractor_data)

                    stdout, extractor_context = extractor.parsed
                    extractor_data.update(extractor_context)
                except Exception as e:
                    logging.error("Extractor error: {}".format(e))
                    if self.args.verbose_exceptions:
                        traceback.print_exc()
                    pass

        sys.stdout.write(stdout[:self.args.limit_stdout])
        if self.args.limit_stdout > 0 and self.args.limit_stdout < len(stdout):
            sys.stdout.write(" ... output truncated\nto disable use --limit-stdout -1\n")
            sys.stdout.write("\n")
        if stderr:
            sys.stderr.write("\n")
            sys.stderr.write(stderr)
        sys.stdout.flush()
        sys.stderr.flush()


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
