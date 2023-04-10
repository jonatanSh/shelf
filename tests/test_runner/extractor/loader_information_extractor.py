from test_runner.extractor.utils import extract_int16


class LoaderInformationExtractor(object):
    def __init__(self, stream, test_context, extractor_data):
        self.stream = stream
        self.test_context = test_context
        self.extractor_data = extractor_data

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
