from elftools.elf.elffile import ELFFile
from shelf.lib.consts import Arches, StartFiles
from shelf.relocate import shellcode_classes
from argparse import Namespace


class ShelfApi(object):
    def __init__(self, binary_path,
                 start_method=StartFiles.no_start_files,
                 hooks_configuration=[],
                 loader_supports=[]):
        self.binary_path = binary_path
        with open(self.binary_path, 'rb') as fp:
            elf = ELFFile(fp)
            self.arch = Arches.translate_from_ident(elf.header.e_machine)
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
                                            loader_supports=loader_supports
                                        ))

    def __del__(self):
        try:
            self.fd.close()
        except:
            pass
