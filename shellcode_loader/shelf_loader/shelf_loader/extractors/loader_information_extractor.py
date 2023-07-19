from shelf_loader.extractors.utils import extract_int16
from shelf_loader.extractors.base_extractor import BaseExtractor


class LoaderInformationExtractor(BaseExtractor):

    @property
    def parsed(self):
        shellcode_size = extract_int16(
            self.stream,
            "Shellcode size = ",
            '\n',
        )
        mapped_memory = extract_int16(
            self.stream,
            "Mapping new memory, size = ",
            '\n',
        )
        shellcode_address = extract_int16(
            self.stream,
            'Jumping to shellcode, address = ',
            '\n'
        )
        return self.stream, {'shellcode_size': shellcode_size,
                             'mapped_memory_size': mapped_memory,
                             "shellcode_address": shellcode_address}
