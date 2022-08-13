import os.path
from itertools import permutations
from elf_to_shellcode.lib.consts import StartFiles, OUTPUT_FORMAT_MAP
from elf_to_shellcode.arguments import ARGUMENTS
from elf_to_shellcode.resources import get_resource_path


class ShellcodeLoader(object):
    def __init__(self):
        self.base_name = "mini_loader_{}".format(ARGUMENTS.arch)
        self._loader_path = None
        self.features = []
        self.build_loader_features()
        self._bytes = None

    @property
    def loader_path(self):
        if not self._loader_path:
            name = self.get_loader_name()
            self._loader_path = get_resource_path(name)

        if not os.path.exists(self._loader_path):
            raise Exception("Loader path: {} does not exists".format(
                self._loader_path
            ))
        return self._loader_path

    def build_loader_features(self):
        if StartFiles.glibc == ARGUMENTS.start_method:
            self.features.append("glibc")

        for argument in ARGUMENTS.loader_supports:
            self.features.append(argument)

        if ARGUMENTS.output_format == OUTPUT_FORMAT_MAP.eshelf:
            self.features.append("eshelf")

    def get_loader_name(self):
        name = self.base_name + "_{}"
        if not self.features:
            return self.base_name + ".shellcode"
        for permutation in permutations(self.features):
            feature_map = "_".join(permutation)
            current_name = name.format(feature_map) + ".shellcode"
            path = get_resource_path(current_name)
            if os.path.exists(path):
                return current_name
        raise Exception("Loader with features: {} not found !".format(
            self.features
        ))

    @property
    def bytes(self):
        if not self._bytes:
            with open(self.loader_path, 'rb') as fp:
                self._bytes = fp.read()
        return self._bytes

    def __len__(self):
        return len(self.bytes)
