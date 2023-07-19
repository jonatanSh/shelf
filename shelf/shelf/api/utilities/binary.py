import logging

from shelf.lib.utils.address_utils import AddressUtils
from shelf.lib import consts


class FeaturesDescriptor(object):
    def __init__(self, features_mask):
        self.features_mask = features_mask
        self.is_dynamic = (features_mask & consts.ShelfFeatures.DYNAMIC.value) > 0
        self.has_hooks = (features_mask & consts.ShelfFeatures.HOOKS.value) > 0
        self.arch = None
        for arch in consts.Arches:
            if type(arch.value) is dict:
                continue
            if features_mask & consts.ShelfFeatures.ARCH_MAPPING.value[arch.value]:
                self.arch = arch
        if not self.arch:
            raise Exception("Arch not found bitmap: {}".format(
                features_mask
            ))

    def __str__(self):
        return "ShelfFeatures(dynamic={}, hooks={}, arch={})".format(
            self.is_dynamic,
            self.has_hooks,
            self.arch.value
        )


class ShelfBinaryUtils(object):
    def __init__(self, memory_dump):
        self.memory_dump = memory_dump
        self._all_address_utils = [
            AddressUtils.for_32_bit_little_endian(),
            AddressUtils.for_32_bit_big_endian(),
            AddressUtils.for_64_bit_little_endian(),
            AddressUtils.for_64_bit_big_endian()

        ]
        self.address_utils = None
        self.shellcode_table_magic = None
        self.mini_loader_start_index = None
        self.found_mini_loader = False
        self.shelf_version = None
        self.shelf_features = None
        self.find_utils_and_magics()
        self.find_mini_loader()

    def find_utils_and_magics(self):
        """
        Figure out address utils by shellcode magic
        This function tries to find the first occurrence of shellcode magic
        and match it to the best address util.
        futher more if there is a match for larger ptr size it will be always chosen
        :return:
        """
        ptr_size = min(self._all_address_utils, key=lambda x: x.ptr_size).ptr_size
        index_first = 2 ** 32
        best_magic = -1
        best_util = self._all_address_utils[0]
        for util in self._all_address_utils:
            if util.ptr_size == 8:
                magic = consts.ShellcodeMagics.arch64.value
            elif util.ptr_size == 4:
                magic = consts.ShellcodeMagics.arch32.value
            else:
                raise Exception("Unknown arch")
            # Skip all address utils with ptr size then the current one
            if util.ptr_size < ptr_size:
                continue
            index = self.memory_dump.find(util.pack_pointer(magic))
            if index >= 0:
                if ptr_size > util.ptr_size:
                    continue
                # We use <= because it can be matched for 32 bit and 64 bit
                if index_first >= index or ptr_size < util.ptr_size:
                    best_util = util
                    best_magic = magic
                    index_first = index
                    ptr_size = max([ptr_size, util.ptr_size])

        assert index_first != 2 ** 32
        self.address_utils = best_util
        self.shellcode_table_magic = best_magic
        logging.info("Magic: {}, utils: {}".format(
            hex(best_magic),
            best_util
        ))

    def find_mini_loader(self):
        """
        Parses the dump and finds the mini loader within the dump
        :return:
        """
        magic = self.address_utils.pack_pointer(self.shellcode_table_magic)
        self.mini_loader_start_index = self.memory_dump.find(magic)
        if self.mini_loader_start_index >= 0:
            self.found_mini_loader = True

    def get_shelf_features(self):
        """
        This function finds and returns shelf features
        :return:
        """
        if all([self.shelf_features, self.shelf_version]):
            return self.shelf_version, self.shelf_features

        magic, version_and_features, padding, total_size, header_size, \
        padding_between_table_and_loader, self.elf_header_size, loader_size = self.address_utils.unpack_pointers(
            self.memory_dump[self.mini_loader_start_index:],
            8
        )

        self.shelf_features = FeaturesDescriptor((version_and_features & ((2 ** 16) - 1)))
        _version = (version_and_features >> 16)
        self.shelf_version = _version / 100.0

        return self.shelf_version, self.shelf_features
