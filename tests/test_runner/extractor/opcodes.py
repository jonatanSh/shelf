import logging

import capstone
from test_runner.extractor.utils import extract_text_between, Binary, extract_int16, address_in_region
from test_runner.consts import ShellcodeLoader
from test_runner.extractor.disassembler_consts import ENDIAN, BITS, ARCHES


class SegfaultHandler(object):
    def __init__(self, elf, arch, opcodes, dump_address, relative_dump_address, faulting_address,
                 error_message="No error", bad_fault=False, additional_messages=[]):
        self.elf = elf
        self.opcodes = opcodes
        self.dump_address = dump_address
        self.faulting_address = faulting_address
        self.arch = arch
        self.bad_fault = bad_fault
        self.error_message = error_message
        self.relative_dump_address = relative_dump_address
        mode = BITS[self.arch]
        self.cs = capstone.Cs(
            ARCHES[self.arch],
            ENDIAN[self.arch] | mode
        )
        self.additional_messages = additional_messages

    @classmethod
    def create(cls,
               other_context,
               arch,
               shellcode_elf,
               loader_elf,
               opcodes, dump_address, faulting_address):
        shellcode_address = other_context['shellcode_address']
        mapped_size = other_context['mapped_memory_size']

        loader_binary = Binary(binary_path=loader_elf)
        shellcode_binary = Binary(binary_path=shellcode_elf,
                                  loading_address=shellcode_address)
        relative_dump_address = dump_address

        if address_in_region(address=faulting_address,
                             start=shellcode_address,
                             size=mapped_size):
            elf = shellcode_binary
            relative_dump_address = elf.translate_to_relative_off(dump_address)
        elif loader_binary.in_region_of_loading_addresses(
                address=faulting_address,
        ):
            elf = loader_binary
        else:
            return cls(
                elf=None,
                arch=arch,
                opcodes=None,
                dump_address=dump_address,
                faulting_address=faulting_address,
                relative_dump_address=relative_dump_address,
                error_message="Address not in region of loader nor shellcode",
                bad_fault=True
            )
        return cls(
            elf=elf,
            arch=arch,
            opcodes=opcodes,
            dump_address=dump_address,
            relative_dump_address=relative_dump_address,
            faulting_address=faulting_address
        )

    def is_output_correct(self):
        if self.bad_fault:
            return False
        opcodes = self.elf.get_bytes_at_virtual_address(
            size=len(self.opcodes),
            address=self.relative_dump_address,
        )
        if not opcodes:
            self.additional_messages.append(
                'Output may be incorrect faulting address is only runtime relvant'
            )
        elif not (opcodes == self.opcodes):
            logging.info("Gdb out: {}".format(opcodes.encode('hex')))
            logging.info("mem dump out: {}".format(self.opcodes.encode('hex')))

            self.error_message = "Disassembly error opcodes do not match !"
            return False

        return True

    def disassemble(self, opcodes, off):
        _instructions = [instruction for instruction in self.cs.disasm(
            opcodes,
            off,
        )]
        relative_off = off
        if self.dump_address != self.relative_dump_address:
            relative_off = self.elf.translate_to_relative_address(off)
        sym = self.elf.get_symbol(address=relative_off)
        if not sym:
            sym = "UNKNOWN_SYMBOL"
        instructions = self.additional_messages + ["\n{}:\n   S:{}:RA:{}".format(
            self.elf.binary_path,
            sym,
            hex(relative_off))]
        for i, instruction in enumerate(_instructions):
            rpr = "      "
            if instruction.address == self.faulting_address:
                rpr = "----> "
            dis_out = self.instruction_repr(instruction)
            rpr += dis_out
            instructions.append(rpr)
        return "\n".join(instructions)

    @staticmethod
    def instruction_repr(instruction):
        dis = "0x%x:    %s    %s    " % (instruction.address,
                                         instruction.mnemonic,
                                         instruction.op_str)
        ins_bytes = " ".join([hex(c) for c in instruction.bytes])

        dis = dis.ljust(50, " ") + "# {}".format(ins_bytes)
        return dis

    @property
    def summary(self):
        if not self.is_output_correct():
            return "Disassembly error message: {}".format(
                self.error_message
            )
        else:
            return self.disassemble(
                off=self.dump_address,
                opcodes=self.opcodes
            )


class OpcodesExtractor(object):
    def __init__(self, stream, test_context, extractor_data):
        self.stream = stream
        self.extractor_data = extractor_data
        self.memory_dumps = extract_text_between(self.stream, ShellcodeLoader.MemoryDumpStart,
                                                 ShellcodeLoader.MemoryDumpEnd)
        self.text_context = test_context

    @property
    def parsed(self):
        parsed_data = {
            'segfaults': []
        }
        for memory_dump in self.memory_dumps:
            opcodes, address, segfault_address = self.extract_bytes_address(memory_dump)
            segfault = SegfaultHandler.create(
                other_context=self.extractor_data,
                arch=self.text_context['arch'],
                shellcode_elf=self.text_context['elf'],
                loader_elf=self.text_context['loader_file'],
                opcodes=opcodes,
                dump_address=address,
                faulting_address=segfault_address
            )
            parsed_data['segfaults'].append(segfault)

            dmp_full = "{}{}{}".format(ShellcodeLoader.MemoryDumpStart,
                                       memory_dump,
                                       ShellcodeLoader.MemoryDumpEnd)
            parsed = "{}\nOpcodes parser for: {}\n{}".format(
                memory_dump.strip(),
                self.text_context['arch'],
                segfault.summary
            )
            self.stream = self.stream.replace(
                dmp_full,
                parsed
            )

        return self.stream, parsed_data

    @staticmethod
    def extract_bytes_address(stream):
        segfault_address = extract_int16(
            stream,
            'Segmentation fault occurred at address: ',
            '\n'
        )
        address = extract_int16(stream, ShellcodeLoader.DumpAddressStart,
                                ShellcodeLoader.DumpAddressEnd)
        dump_bytes = extract_text_between(stream.strip(),
                                          '\n',
                                          "",
                                          times=1,
                                          rindex_start=True)
        dump_bytes = "".join([chr(int(b, 16)) for b in dump_bytes.split(" ") if b.startswith("0x") if len(b) == 0x4])
        return dump_bytes, address, segfault_address
