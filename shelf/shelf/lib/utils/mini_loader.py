import json
import itertools
import os.path
from logging import getLogger

from shelf.lib.consts import StartFiles, OUTPUT_FORMAT_MAP
from shelf.resources import get_resource_path, get_resource
from shelf.lib.ext.loader_symbols import ShellcodeLoader
from py_elf_structs import load_structs


class MiniLoader(object):
    def __init__(self, shellcode):
        self._symbols = None
        self._structs = None
        self.shellcode = shellcode
        self.logger = getLogger(self.__class__.__name__)
        self._path = None

    def format_loader(self, ld):
        """
        Decide what is the name of the loader it can vary depending on the features enabled.
        eg ...
        --support-dynamic uses different loader
        :param ld: The loader base name
        :return:
        """
        loader_path = None
        found_loader = None
        features_map = sorted(self.shellcode.args.loader_supports, key=lambda lfeature: lfeature[1])
        features = features_map

        if StartFiles.glibc == self.shellcode.args.start_method:
            features.append("glibc")
        for feature in features_map:
            value = getattr(self.shellcode, "support_{}".format(feature))
            if not value:
                raise Exception("Arch does not support: {}".format(feature))
        if self.shellcode.args.output_format == OUTPUT_FORMAT_MAP.eshelf:
            features.append("eshelf")

        all_features = [feature for feature in itertools.permutations(features, len(features))]
        for permutation in all_features:
            permutation = "_" + "_".join(permutation)
            loader_path = ld.format(permutation)
            loader_full_path = get_resource_path(loader_path)
            if os.path.exists(loader_full_path):
                found_loader = True
                break
        if not features:
            loader_path = ld.format("")
            loader_full_path = get_resource_path(loader_path)
            if os.path.exists(loader_full_path):
                found_loader = True
        if not found_loader:
            raise Exception("Loader for features: {} not found".format(features))
        self.logger.info("Using loader: {}".format(loader_path))
        return loader_path

    def _get_path(self):
        """
        Format and return the loader path acorridng to all its features
        :return:
        """
        resource_path = None
        if self.shellcode.args.loader_path:
            self.logger.info("Using loader resources from user")
            return self.shellcode.args.loader_path

        if self.shellcode.args.endian == "big":
            if self.shellcode.mini_loader_big_endian:
                resource_path = self.format_loader(self.shellcode.mini_loader_big_endian)
        else:
            if self.shellcode.mini_loader_little_endian:
                resource_path = self.format_loader(self.shellcode.mini_loader_little_endian)

        path = get_resource_path(resource_path)

        assert os.path.exists(path), "Mini loader not found in: {}".format(
            path
        )

        return path

    @property
    def path(self):
        if not self._path:
            self._path = self._get_path()
        return self._path

    @property
    def symbols_path(self):
        """
        Format and return the loader symbols path according to all its features
        :return:
        """
        if self.shellcode.args.loader_symbols_path:
            self.logger.info("Using loader symbol resources from user")
            path = self.shellcode.args.loader_symbols_path
        else:
            path = self.path + ".symbols"

        assert os.path.exists(path)
        return path

    @property
    def relative_symbols_path(self):
        path = self.path + ".relative.symbols"

        assert os.path.exists(path)
        return path

    @property
    def structs_file(self):
        if self.shellcode.args.loader_symbols_path:
            raise Exception("Not implemented yet !")
        else:
            return self.path + ".structs.json"

    @property
    def loader(self):
        """
        Format and return the loader binary
        :return:
        """
        loader = get_resource(self.path)
        assert self.shellcode.address_utils.pack_pointer(self.shellcode.shellcode_table_magic) not in loader
        return loader

    @property
    def symbols(self):
        """
        Return the loader symbols representing classs
        :return:
        """
        return ShellcodeLoader(self.symbols_path,
                               loader_size=len(self.loader))

    def iterate_relative_symbols(self):
        if not self._symbols:
            with open(self.relative_symbols_path, 'rb') as fp:
                self._symbols = json.load(fp)
    
        return self._symbols

    def get_relative_symbol_at_offset(self, off):
        for symbol in self.iterate_relative_symbols():
            symbol_name, symbol_relative_off, symbol_size = symbol

            if symbol_relative_off <= off <= symbol_relative_off + symbol_size:
                return symbol_name

    @property
    def structs(self):
        if not self._structs:
            self._structs = load_structs(self.structs_file)
        return self._structs

    @property
    def function_descriptor_header(self):
        functions = self.structs.loader_function_descriptor.__fields__
        kwargs = {}
        for function in functions:
            kwargs[function] = self.symbols.get_relative_symbol_address(
                function
            )
        return self.structs.loader_function_descriptor(
            **kwargs
        ).pack()
