import logging
from shelf_loader.extractors.utils import extract_text_between, Binary, extract_int16, address_in_region
from shelf_loader.consts import ShellcodeLoader
from shelf.lib import five
from shelf_loader.extractors.base_extractor import BaseExtractor


class SegfaultHandler(object):
    def __init__(self, elf, arch, opcodes, dump_address, relative_dump_address, faulting_address,
                 error_message="No error", bad_fault=False, additional_messages=[]):
        self.elf = elf
        self.opcodes = five.convert_python2_bytes_string_to3(opcodes)
        self.dump_address = dump_address
        self.faulting_address = faulting_address
        self.arch = arch
        self.bad_fault = bad_fault
        self.error_message = error_message
        self.relative_dump_address = relative_dump_address
        self.additional_messages = additional_messages

    @classmethod
    def create(cls,
               other_context,
               arch,
               shellcode_elf,
               opcodes, dump_address, faulting_address, **shelf_kwargs):
        shellcode_address = other_context['shellcode_address']
        mapped_size = other_context['mapped_memory_size']
        shellcode_binary = Binary(binary_path=shellcode_elf,
                                  loading_address=shellcode_address, **shelf_kwargs)
        if address_in_region(address=faulting_address,
                             start=shellcode_address,
                             size=mapped_size):
            elf = shellcode_binary
            relative_dump_address = elf.translate_to_relative_off(dump_address)

        else:
            raise NotImplementedError("Address: {} <= {} <= {} not within".format(
                hex(shellcode_address),
                hex(faulting_address),
                hex(shellcode_address + mapped_size)
            ))

        return cls(
            elf=elf,
            arch=arch,
            opcodes=opcodes,
            dump_address=dump_address,
            relative_dump_address=relative_dump_address,
            faulting_address=faulting_address,
        )

    def is_output_correct(self):
        if self.bad_fault:
            return False

        return True

    def disassemble(self, opcodes, off):
        dump = self.elf.shelf.shelf.memory_dump_plugin.construct_shelf_from_memory_dump(
            memory_dump=opcodes,
            dump_address=off,
            loading_address=self.elf.loading_address
        )
        _, main_address, _ = dump.get_symbol_by_name("main")
        logging.info("Disassembly information loading_address={}, "
                     "dump_address={}, *main={}".format(
            hex(self.elf.loading_address),
            hex(off),
            hex(main_address)
        ))

        dump.disassemble(mark=self.faulting_address)

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


class OpcodesExtractor(BaseExtractor):
    def __init__(self, stream, args, extractor_data):
        super(OpcodesExtractor, self).__init__(
            stream=stream,
            args=args,
            extractor_data=extractor_data
        )
        self.memory_dumps = extract_text_between(self.stream, ShellcodeLoader.MemoryDumpStart,
                                                 ShellcodeLoader.MemoryDumpEnd,
                                                 allow_end_on_terminated_string=True,
                                                 return_mapped=True)

    @property
    def parsed(self):
        parsed_data = {
            'segfaults': []
        }
        for dmp_full, memory_dump in self.memory_dumps.items():
            if not self.args.source_elf:
                logging.critical("Critical information can't be parsed because --source-elf is missing")
                self.stream = self.stream.replace(dmp_full, dmp_full[:400] +
                                                  "....\n[This line is truncated by the loader to view the full line use --disable-extractors]\n"
                                                  "To view a full disassembly use --source-elf")
                continue

            opcodes, address, segfault_address = self.extract_bytes_address(memory_dump)
            segfault = SegfaultHandler.create(
                other_context=self.extractor_data,
                arch=self.args.arch,
                shellcode_elf=self.args.source_elf,
                opcodes=opcodes,
                dump_address=address,
                faulting_address=segfault_address,
                **self.extractor_data['shelf_kwargs']
            )
            parsed_data['segfaults'].append(segfault)

            parsed = "Faulting address: {}\n{}\n{}".format(
                hex(segfault_address),
                self.args.arch,
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
