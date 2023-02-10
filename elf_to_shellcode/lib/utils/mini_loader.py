import os.path
from logging import getLogger
from elf_to_shellcode.lib.consts import StartFiles, OUTPUT_FORMAT_MAP
from elf_to_shellcode.resources import get_resource_path, get_resource
from elf_to_shellcode.lib.ext.loader_symbols import ShellcodeLoader


class MiniLoader(object):
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.logger = getLogger(self.__class__.__name__)

    def format_loader(self, ld):
        """
        Decide what is the name of the loader it can vary depending on the features enabled.
        eg ...
        --support-dynamic uses different loader
        :param ld: The loader base name
        :return:
        """
        if StartFiles.no_start_files == self.shellcode.args.start_method:
            ld_base = ""
        elif StartFiles.glibc == self.shellcode.args.start_method:
            ld_base = "_glibc"
        else:
            raise Exception("Unknown start method: {}".format(
                self.shellcode.args.start_method
            ))
        features_map = sorted(self.shellcode.args.loader_supports, key=lambda lfeature: lfeature[1])
        for feature in features_map:
            value = getattr(self.shellcode, "support_{}".format(feature))
            if not value:
                raise Exception("Arch does not support: {}".format(feature))
        loader_additional = "_".join([feature for feature in features_map])
        if loader_additional:
            loader_additional = "_" + loader_additional
        if self.shellcode.args.output_format == OUTPUT_FORMAT_MAP.eshelf:
            loader_additional += "_eshelf"
        ld_name = ld.format(ld_base + loader_additional)

        self.logger.info("Using loader: {}".format(ld_name))
        return ld_name

    @property
    def path(self):
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

        assert os.path.exists(path)

        return path

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
