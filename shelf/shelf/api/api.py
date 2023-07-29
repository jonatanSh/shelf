from elftools.elf.elffile import ELFFile
from shelf.lib.consts import Arches, StartFiles, OUTPUT_FORMATS, OUTPUT_FORMAT_MAP
from shelf.relocate import shellcode_classes
from shelf.api.utilities.binary import ShelfBinaryUtils
from argparse import Namespace
import logging


class ShelfApi(object):
    def __init__(self, binary_path,
                 start_method=StartFiles.no_start_files,
                 hooks_configuration=[],
                 loader_supports=[],
                 loader_symbols_path=None,
                 loader_path=None,
                 output_format=OUTPUT_FORMAT_MAP.shelf):
        assert output_format in OUTPUT_FORMATS
        self.binary_path = binary_path
        with open(self.binary_path, 'rb') as fp:
            elf = ELFFile(fp)
            self.arch = Arches.translate_from_ident(elf.header.e_machine,
                                                    elf.header.e_ident.EI_CLASS)
            endian = elf.header.e_ident.EI_DATA
            endians = {
                'ELFDATA2MSB': 'big',
                'ELFDATA2LSB': 'little'
            }
            endian = endians.get(endian)
            if not endian:
                raise Exception("Endian: {} not supported".format(endian))
            self.endian = endian
            self.shelf_cls = shellcode_classes[self.arch]
            self.fd = open(self.binary_path, 'rb')
            elffile = ELFFile(self.fd)
            with open(self.binary_path, "rb") as fp:
                shellcode_data = fp.read()
            self.shelf = self.shelf_cls(elffile=elffile,
                                        shellcode_data=shellcode_data,
                                        args=Namespace(
                                            input=self.binary_path,
                                            start_method=start_method,
                                            endian=self.endian,
                                            arch=self.arch,
                                            hooks_configuration=hooks_configuration,
                                            loader_supports=loader_supports,
                                            loader_symbols_path=loader_symbols_path,
                                            loader_path=loader_path,
                                            output_format=output_format,
                                            relocate_opcodes=True,
                                            force=False
                                        ))

    @staticmethod
    def enable_logging():
        """
        Enable api logging
        :return:
        """
        logging.basicConfig(level=logging.INFO)

    def __del__(self):
        try:
            self.fd.close()
        except:
            pass


class ShelfBinaryApi(object):
    def __init__(self, binary_data):
        self.binary_data = binary_data
        self.format_utils = ShelfBinaryUtils(
            self.binary_data
        )
