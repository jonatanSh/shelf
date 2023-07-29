import binascii
import os
from logging import getLogger
import subprocess
import tempfile
import re
from distutils.spawn import find_executable
from shelf.lib.consts import DisassemblerConsts
from shelf.lib.utils.process import communicate_with_timeout


class TempFileWrapper(object):
    def __init__(self, mode):
        self.mode = mode
        self.fp = None
        self.path = None

    def __enter__(self):
        self.path = tempfile.mktemp('.shelf.temp')
        self.fp = open(self.path, self.mode)
        return self

    def write(self, raw_bytes):
        self.fp.write(raw_bytes)

    def close(self):
        self.fp.close()

    def try_close(self):
        try:
            self.close()
        except:
            pass

    def try_unlink(self):
        try:
            os.unlink(self.path)
        except:
            pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.try_close()
        self.try_unlink()


class CapstoneInstructionApi(object):
    def __init__(self, address, instruction_bytes, instruction_str, base_address):
        self.instruction_str = instruction_str
        iparts = self.instruction_str.split(" ")
        while len(iparts) < 2:
            iparts.append(None)

        self.mnemonic = iparts[0]
        self.op_str = iparts[1]
        self.bytes = instruction_bytes
        self._base_address = base_address
        self.address = self._base_address + int(address, 16)

    def is_valid(self):
        if not self.mnemonic or not self.op_str:
            return False

        return True


class ObjdumpDisassemblerBackend(object):
    def __init__(self, architecture):
        self.architecture = architecture
        self.backend = DisassemblerConsts.OBJDUMP_BACKENDS[architecture]
        self.objdump_arch = DisassemblerConsts.OBJDUMP_ARCHES[architecture]
        self.logger = getLogger(self.__class__.__name__)

    def does_backend_exists(self):
        return find_executable(self.backend) is not None

    def disassemble_file(self, input_file, offset):
        if not self.does_backend_exists():
            raise Exception("A feature you are using uses the objdump backend and "
                            "requires: {0} to be installed on the system "
                            "{0} was not found, probably you can bypass this with --force due it is not "
                            "recommended and the output can result in corrupted shellcode".format(
                self.backend
            ))
        assert os.path.exists(input_file)
        command = [
            self.backend,
            '-b',
            'binary',
            '-D',
            '-m',
            self.objdump_arch,
            input_file

        ]
        self.logger.info("Executing: {}".format(" ".join(command)))
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output = communicate_with_timeout(process)

        return self.parse_instructions(output.stdout.decode("utf-8"),
                                       off=offset)

    @staticmethod
    def parse_instruction(line):
        pattern = r'\s*(\w+):\s+([\da-f]+)\s+([^\n]+)'
        match = re.match(pattern, line)
        if match:
            address = match.group(1)
            instruction_bytes = match.group(2)
            instruction = match.group(3)
            return address, instruction_bytes, re.sub(r'\s+', ' ', instruction)
        else:
            return None, None, None

    def parse_instructions(self, output, off):
        instructions = []
        for line in output.split("\n"):
            if ':' not in line:
                continue

            address, instruction_bytes, instruction = self.parse_instruction(line)
            if None in [address, instruction_bytes, instruction]:
                self.logger.error("Error parsing: {}".format(line))
                continue
            instruction_bytes = binascii.unhexlify(instruction_bytes)  # TODO change Its little endian

            instruction = CapstoneInstructionApi(
                address=address,
                instruction_bytes=[b for b in reversed(instruction_bytes)],
                instruction_str=instruction,
                base_address=off
            )
            if instruction.is_valid():
                instructions.append(instruction)

        return instructions

    def disasm(self, raw_bytes, offset=0x0):
        with TempFileWrapper('wb') as fp:
            fp.write(raw_bytes)
            fp.try_close()
            return self.disassemble_file(fp.path, offset)
