import binascii
import os
import struct
import sys
import logging
import tempfile
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from shelf.lib import five
from elftools.elf.elffile import ELFFile

from shelf.lib.utils.address_utils import AddressUtils
from shelf.lib.utils.mini_loader import MiniLoader
from shelf.lib.consts import StartFiles, OUTPUT_FORMAT_MAP, LoaderSupports, Arches, ArchEndians, \
    RELOCATION_OFFSETS, RelocationAttributes, HookTypes, ShelfFeatures
from shelf.lib.utils.hooks import ShellcodeHooks
from shelf.lib.utils.general import get_binary
from shelf.hooks.hooks_configuration_parser import HookConfiguration
from shelf.hooks.base_hook import _BaseShelfHook
from shelf.lib.utils.memory_section import MemorySection, MemoryProtection
from shelf.lib.plugins.memory_dump.shelf_memory_dumps_plugin import MemoryDumpPlugin
from shelf.lib.utils.disassembler import Disassembler
from shelf.lib.exceptions import AddressNotInShelf
from shelf.__version__ import VERSION_FOR_PACK

PTR_SIZES = {
    4: "I",
    8: "Q"
}


def api_function(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


class Shellcode(object):
    def __init__(self, elffile,
                 shellcode_data,
                 args,
                 arch,
                 mini_loader_little_endian,
                 mini_loader_big_endian,
                 shellcode_table_magic,
                 ptr_fmt,
                 sections_to_relocate=None,
                 supported_start_methods=None,
                 reloc_types=None,
                 support_dynamic=False,
                 **kwargs):
        self._symbols = None
        self.shellcode_compiled = False
        self._ptr_size = None
        self._loading_virtual_addr = None
        self._linker_base = None
        self.support_hooks = True
        if reloc_types is None:
            reloc_types = {}
        if supported_start_methods is None:
            supported_start_methods = []
        if sections_to_relocate is None:
            sections_to_relocate = {}

        self.args = args
        self.support_dynamic = support_dynamic
        self.mini_loader_little_endian = mini_loader_little_endian
        self.mini_loader_big_endian = mini_loader_big_endian
        self.logger = logging.getLogger("[{}]".format(
            self.__class__.__name__
        ))

        self.elffile = elffile
        self._lief_elf = None
        self.shellcode_table_magic = shellcode_table_magic
        # Key is the file offset, value is the offset to correct to
        self.addresses_to_patch = {}
        self.patched_symbols_mapping = {}
        self.sections_to_relocate = sections_to_relocate

        self.shellcode_data = shellcode_data
        self.ptr_fmt = ptr_fmt
        self.ptr_signed_fmt = self.ptr_fmt.lower()
        self.relocation_handlers = []
        self.shellcode_formatters = []

        self.supported_start_methods = supported_start_methods
        if StartFiles.no_start_files not in self.supported_start_methods:
            self.supported_start_methods.append(
                StartFiles.no_start_files
            )
        assert args.start_method in self.supported_start_methods, "Error, start method: {} not supported for arch, supported methods: {}".format(
            args.start_method,
            self.supported_start_methods
        )

        if args.endian == "big":
            self.endian = ">"
        else:
            self.endian = "<"

        self.arch = arch
        try:
            self.disassembler = Disassembler(self)
        except Exception as error:
            logging.error("Disassembler not supported for architecture!")
            logging.info(error)
        self.address_utils = AddressUtils(shellcode=self)
        self.mini_loader = MiniLoader(shellcode=self)
        self.hooks_configuration = None
        if args.hooks_configuration:
            if not LoaderSupports.HOOKS in self.args.loader_supports:
                raise Exception("Error hook configuration must be used with --loader-supports hooks")
            self.hooks_configuration = [HookConfiguration(config) for config in args.hooks_configuration]

        if LoaderSupports.HOOKS in self.args.loader_supports:
            self.hooks = ShellcodeHooks(shellcode=self)
        else:
            self.hooks = None

        # Keep track of offsets inside the relocation table
        self.offsets_in_header = {}
        """
        Shelf plugin
        """
        self.memory_dump_plugin = MemoryDumpPlugin(self)

    def add_shellcode_formatter(self, formatter_method):
        self.shellcode_formatters.append(formatter_method)

    def dispatch_shellcode_formatters(self, shellcode_data):
        for formatter in self.shellcode_formatters:
            self.logger.info("Dispatching: {}".format(formatter))
            shellcode_data = formatter(shellcode_data)

        return shellcode_data

    def _get_lief_imports(self, library=False, section_flags=False):
        lib, flags = five.get_lief()
        if library:
            return lib
        if section_flags:
            return flags

    @property
    def lief_elf(self):
        lief = self._get_lief_imports(library=True)
        if not self._lief_elf:
            self._lief_elf = lief.parse(self.args.input)

        return self._lief_elf

    def _generic_do_hooks(self, hooks, hook_type):
        self.logger.info("Adding hooks to: {}".format(hook_type))
        for hook_cls in hooks:
            hook = hook_cls(shellcode=self)
            assert isinstance(hook, _BaseShelfHook)
            self.hooks.add_hook(
                shellcode_data=get_binary(hook.hook_get_shellcode_path(
                    arch=Arches[self.args.arch],
                    endian=ArchEndians[self.args.endian]
                )),
                hook_type=hook_type,
                attributes=hook.hook_get_attributes()
            )

    def do_hooks(self):
        if not self.hooks_configuration:
            return
        self.logger.info("Handling hooks")
        for hook_configuration in self.hooks_configuration:
            self._generic_do_hooks(
                hooks=hook_configuration.startup_hooks,
                hook_type=HookTypes.STARTUP_HOOKS
            )
            self._generic_do_hooks(
                hooks=hook_configuration.pre_relocate_write_hooks,
                hook_type=HookTypes.PRE_RELOCATE_WRITE_HOOKS
            )
            self._generic_do_hooks(
                hooks=hook_configuration.pre_relocate_execute_hooks,
                hook_type=HookTypes.PRE_RELOCATE_EXECUTE_HOOKS
            )
            self._generic_do_hooks(
                hooks=hook_configuration.pre_calling_main_shellcode_hooks,
                hook_type=HookTypes.PRE_CALLING_MAIN_SHELLCODE_HOOKS
            )

    def arch_find_relocation_handler(self, relocation_type):
        """
        Hook for specific arch relocation handler
        :param relocation_type: the
        :return: Function relocation handler(shellcode, shellcode_data, relocation) -> None
        """
        raise NotImplementedError()

    def arch_handle_relocation(self, shellcode, shellcode_data, relocation):
        """
        Helper to find arch relocation handler
        :param shellcode: processing shellcode
        :param shellcode_data: the current shellcode data
        :param relocation: the object
        :return: None
        """
        handler = self.arch_find_relocation_handler(relocation.type)
        if not handler:
            raise Exception(
                "Error relocation handler for: {} not found, extended {}".format(relocation.type, relocation))
        self.logger.info("Calling relocation handler: {}".format(
            handler.__name__
        ))
        handler(shellcode=shellcode, shellcode_data=shellcode_data, relocation=relocation)

    def add_relocation_handler(self, func):
        self.relocation_handlers.append(func)

    @property
    def ptr_size(self):
        if not self._ptr_size:
            self._ptr_size = struct.calcsize(self.ptr_fmt)
        return self._ptr_size

    def sizeof(self, tp):
        if tp == "short":
            return 2
        else:
            raise NotImplementedError()

    def pack_and_get_relocations_for_type(self, relocation_type):
        packed = five.py_obj()
        i = 0
        for key, value in self.addresses_to_patch.items():
            if type(value) is not list:
                value = [value, RelocationAttributes.generic_relocate]
            value, reloc_type = value
            if reloc_type == relocation_type:
                bitmask = 0x0
                if key < 0:
                    bitmask |= (2 << 0)
                    key = key * -1
                if value < 0:
                    bitmask |= (2 << 1)
                    value = value * -1
                table_entry = self.mini_loader.structs.table_entry(f_offset=key,
                                                                   v_offset=value,
                                                                   bitmask=bitmask)
                packed += table_entry.pack()
                i += 1

        return packed, i

    @property
    def version_and_features(self):
        features = 0
        if LoaderSupports.HOOKS in self.args.loader_supports:
            features |= ShelfFeatures.HOOKS.value
        if self.support_dynamic:
            features |= ShelfFeatures.DYNAMIC.value
        features |= ShelfFeatures.ARCH_MAPPING.value[self.args.arch]
        version_and_features = (VERSION_FOR_PACK << 16) + features
        logging.info("features: {}, version: {}, fused: {}-{}".format(
            hex(features),
            hex(VERSION_FOR_PACK),
            hex(version_and_features),
            bin(version_and_features)
        ))
        return version_and_features

    def relocation_table(self, padding=0x0):
        table = five.py_obj()

        for relocation_type in RelocationAttributes:
            packed, num_of_attributes = self.pack_and_get_relocations_for_type(relocation_type)
            relocation_entry = self.mini_loader.structs.entry_attributes(
                number_of_entries_related_to_attribute=num_of_attributes,
                relocation_type=relocation_type.value
            ).pack()
            relocation_entry += packed
            if num_of_attributes:
                table += relocation_entry

        # Pack the following format: {size_t padding, size_t table_length, size_t header_length}
        sizes = self.address_utils.pack_pointers(padding,
                                                 len(table),
                                                 len(self.get_shellcode_header()))

        header = self.address_utils.pack_pointers(self.shellcode_table_magic, self.version_and_features) + sizes
        self.offsets_in_header[RELOCATION_OFFSETS.table_magic] = 0x0
        self.offsets_in_header[RELOCATION_OFFSETS.padding_between_table_and_loader] = len(header)
        header += self.address_utils.pack_pointer(0x0)  # padding_between_table_and_loader
        header += self.pre_table_header
        if LoaderSupports.HOOKS in self.args.loader_supports:
            header += self.hooks.get_header()
        header += table
        return header

    @property
    def pre_table_header(self):
        header = five.py_obj()
        sht_entry_header_size = 2 * self.sizeof("short")  # two shorts
        header += self.address_utils.pack_pointer(
            self.elffile.header.e_ehsize + sht_entry_header_size
        )
        if self.args.output_format != OUTPUT_FORMAT_MAP.eshelf:
            header += self.address_utils.pack_pointer(len(self.mini_loader.loader))
        else:
            # In eshelf the elf is the loader therefor it is incorrect to add header size
            header += self.address_utils.pack_pointer(0x0)
        header += self.mini_loader.function_descriptor_header

        return header

    def correct_symbols(self, shellcode_data):
        for section, attributes in self.sections_to_relocate.items():
            self.section_build_relocations_table(
                section_name=section,
                shellcode_data=shellcode_data
            )
        return shellcode_data

    def add_to_relocation_table(self, virtual_offset, offset):
        self.addresses_to_patch[virtual_offset] = offset

    def add_symbol_relocation_to_relocation_table(self, virtual_offset, offset, symbol_name):
        self.patched_symbols_mapping[symbol_name] = [virtual_offset, offset]
        self.add_to_relocation_table(virtual_offset, offset)

    def section_build_relocations_table(self, section_name, shellcode_data):
        data_section = self.elffile.get_section_by_name(section_name)
        if data_section:
            data_section_header = data_section.header
            index = 0
            for data_section_start in range(data_section_header.sh_offset,
                                            data_section_header.sh_offset + data_section_header.sh_size,
                                            self.ptr_size):
                data_section_end = data_section_start + self.ptr_size
                data_section_value = \
                    struct.unpack("{}{}".format(self.endian, self.ptr_fmt),
                                  shellcode_data[data_section_start:data_section_end])[0]
                sym_offset = data_section_value - self.loading_virtual_address
                if sym_offset < 0:
                    continue
                symbol_relative_offset = data_section_start - data_section_header.sh_offset
                virtual_offset = data_section_header.sh_addr - self.loading_virtual_address
                virtual_offset += symbol_relative_offset
                self.logger.info("|{}| Relative(*{}={}), Absolute(*{}={})".format(
                    section_name,
                    hex(virtual_offset),
                    hex(sym_offset),
                    hex(self.address_utils.make_absolute(virtual_offset)),
                    hex(self.address_utils.make_absolute(sym_offset)),
                ))
                virtual_offset, sym_offset = self.relocation_hook(section_name, virtual_offset, sym_offset, index)
                self.add_to_relocation_table(virtual_offset, sym_offset)
                index += 1

        return shellcode_data

    def relocation_hook(self, section_name, virtual_offset, sym_offset, index):
        return virtual_offset, sym_offset

    def do_objdump(self, data):
        # We want the first virtual address
        new_binary = five.py_obj()
        for segment in self.get_segments_in_memory():
            new_binary = five.ljust(new_binary, segment.vsize, b'\x00')
            segment_data = data[segment.f_start:segment.f_end]
            new_binary = new_binary[:segment.start] + segment_data + new_binary[segment.start + len(segment_data):]

        return new_binary  # TODO check if the elf header is really required

    def in_range_of_shellcode(self, address):
        segments = self.get_segments_in_memory()
        if not segments:
            raise Exception("No segments found")
        first_segment = segments[0]
        start = first_segment.v_start
        end = start
        for segment in segments:
            if segment.v_start < start:
                start = segment.v_start
            new_end = segment.v_start + segment.vsize_aligned
            if new_end > end:
                end = new_end
        return start <= address <= end

    def convert_to_shelf_relative_offset(self, address):
        """
        Take address as input and convert to relative offset inside the shelf output
        :param address: Input address
        :return: int
        """
        relative_offset = 0x0
        for segment in self.get_segments_in_memory():
            if segment.v_start <= address <= segment.v_start + segment.vsize_aligned:
                off = address - segment.v_start
                return relative_offset + off
            else:
                relative_offset += segment.vsize
        raise AddressNotInShelf(address=address)

    def get_segments_in_memory(self):
        sections_in_memory = []
        # We want the first virtual address
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                segment_size = header.p_memsz
                start = (header.p_vaddr - self.loading_virtual_address)
                end = start + segment_size
                f_start = header.p_offset
                f_end = f_start + header.p_filesz
                protection = 0
                if segment.header.p_flags & P_FLAGS.PF_X:
                    protection |= MemoryProtection.PROT_EXEC.value
                if segment.header.p_flags & P_FLAGS.PF_R:
                    protection |= MemoryProtection.PROT_READ.value
                if segment.header.p_flags & P_FLAGS.PF_W:
                    protection |= MemoryProtection.PROT_WRITE.value
                sections_in_memory.append(
                    MemorySection(
                        v_start=header.p_vaddr,
                        start=start,
                        vsize=end,
                        vsize_aligned=AddressUtils.get_alignment(end, segment.header.p_align),
                        size=f_end - f_start,
                        f_start=f_start,
                        f_end=f_end,
                        protection=protection,
                    )
                )

        return sorted(sections_in_memory, key=lambda s: s.v_start)

    @staticmethod
    def aligned(a, b):
        return a + (a % b)

    def get_linker_base_address(self, check_x=True, attribute='p_offset'):
        if self.elffile.num_segments() == 0:
            return 0

        # This function return the offset for the first executable section
        min_s = 2 ** 32
        for segment in self.elffile.iter_segments():
            if segment.header.p_type in ['PT_LOAD']:
                header = segment.header
                if (header.p_flags & P_FLAGS.PF_X) or not check_x:
                    min_s = min(min_s, getattr(header, attribute))
        assert min_s != 2 ** 32
        return min_s

    def get_first_section(self, attribute='sh_offset', check_x=None,
                          section_name=None):
        # This function return the offset for the first executable section
        min_s = 2 ** 32

        for section in self.elffile.iter_sections():
            header = section.header
            if section_name and section.name == section_name:
                return getattr(header, attribute)
            if not header.sh_flags & SH_FLAGS.SHF_EXECINSTR and check_x:
                continue
            min_s = min(min_s, getattr(header, attribute))
        assert min_s != 2 ** 32
        return min_s

    @property
    def loading_virtual_address(self):
        if not self._loading_virtual_addr:
            self._loading_virtual_addr = self.get_linker_base_address(
                check_x=False,
                attribute="p_vaddr"
            )
        return self._loading_virtual_addr

    @property
    def linker_base_address(self):
        if not self._linker_base:
            self._linker_base = self.get_linker_base_address()

        return self._linker_base

    @property
    def symbols(self):
        symtab = self.elffile.get_section_by_name(".symtab")
        if not symtab:
            return []
        if not self._symbols:
            self._symbols = [sym for sym in symtab.iter_symbols()]
        return self._symbols

    def find_symbols(self, symbol_name=None,
                     return_relative_address=False, return_object=False,
                     symbol_filter=lambda s: True):
        if return_object:
            assert not return_relative_address, "Either return object nor return_relative_address is allowed"
        symbols = []
        objects = []
        symtab = self.elffile.get_section_by_name(".symtab")
        if not symtab:
            return symbols
        for sym in self.symbols:
            if not symbol_filter(sym):
                continue
            address = sym.entry.st_value
            if return_relative_address:
                address -= self.loading_virtual_address
            else:
                address = sym.entry.st_value
            symbols.append((sym.name, address, sym.entry.st_size))
            objects.append(sym)
        if return_object:
            return [s for s in filter(lambda o: o.name == symbol_name if symbol_name else True, objects)]

        if not symbols and symbol_name:
            raise Exception("Shelf symbol: {} not found".format(symbol_name))

        if symbol_name:
            return [s for s in filter(lambda s: s[0] == symbol_name, symbols)]
        return symbols

    def get_symbol_name_from_address(self, address):

        symtab = self.elffile.get_section_by_name(".symtab")
        if not symtab:
            return None
        for sym in symtab.iter_symbols():
            sym_address = sym.entry.st_value
            if sym_address == address:
                return sym.name

        return None

    def get_shellcode_header(self):
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.loading_virtual_address)
        self.shellcode_compiled = True
        return self.address_utils.pack_pointer(new_entry_point)

    def build_shellcode_from_header_and_code(self, header, code):
        return header + code

    def shellcode_get_full_header(self, padding=0x0):
        shellcode_header = self.get_shellcode_header()
        relocation_table = self.relocation_table(padding=padding)
        full_header = relocation_table + shellcode_header

        if self.args.output_format != OUTPUT_FORMAT_MAP.eshelf:
            full_header = self.mini_loader.loader + full_header
        logging.info("Alignment up to shellcode data: {}".format(
            hex(len(full_header))
        ))
        if LoaderSupports.HOOKS in self.args.loader_supports:
            hooks = self.hooks.get_hooks_data()
            logging.info("Adding hook shellcodes, size: {}".format(
                hex(len(hooks))
            ))
            full_header += hooks
        return full_header

    def get_shellcode(self):
        shellcode_data = self.shellcode_data
        shellcode_data = self.correct_symbols(shellcode_data)
        for handler in self.relocation_handlers:
            shellcode_data = handler(shellcode=self,
                                     shellcode_data=shellcode_data)

        shellcode_data = self.do_objdump(shellcode_data)
        shellcode_data = self.dispatch_shellcode_formatters(shellcode_data)

        # Calling the do hooks

        self.do_hooks()

        # This must be here !
        padding, shellcode_data = self.shellcode_handle_padding(shellcode_data)
        full_header = self.shellcode_get_full_header(padding=padding)

        formatted_shellcode = self.build_shellcode_from_header_and_code(full_header, shellcode_data)

        return self.post_make_shellcode_handle_format(formatted_shellcode)

    def shellcode_handle_padding(self, shellcode_data):
        return 0, shellcode_data

    def post_make_shellcode_handle_format(self, shellcode):
        shellcode_with_output_format = shellcode
        if self.args.output_format == OUTPUT_FORMAT_MAP.eshelf:
            shellcode_with_output_format = self.build_eshelf(
                shellcode_data=shellcode
            )
        return shellcode_with_output_format

    def remove_loader_from_shellcode(self, shellcode):
        index = shellcode.find(self.mini_loader.loader)
        assert index != -1
        return shellcode[:index] + shellcode[index + len(self.mini_loader.loader):]

    def build_eshelf(self, shellcode_data):
        lief = self._get_lief_imports(library=True)
        loader = lief.parse(self.mini_loader.path)
        segment = lief.ELF.Segment()
        segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        rwx = lief.ELF.SEGMENT_FLAGS(lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W | lief.ELF.SEGMENT_FLAGS.X)
        segment.flags = rwx
        segment.content = bytearray(shellcode_data)
        segment = loader.add(segment)

        tmp_path = tempfile.mktemp(".out")
        elf_buffer = None
        try:
            loader.write(tmp_path)
            with open(tmp_path, "rb") as fp:
                elf_buffer = fp.read()
        except Exception as e:
            self.logger.error("Error: {}".format(e))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        assert elf_buffer is not None, "Error"
        # Changing all offsets accordingly:
        for off, value in self.offsets_in_header.items():
            value += segment.file_offset
            self.offsets_in_header[off] = value
        loader_main_off = self.mini_loader.symbols.get_symbol_address("loader_main")
        magic_off = self.offsets_in_header[RELOCATION_OFFSETS.table_magic]
        padding_between_table_and_loader_off = self.offsets_in_header[
            RELOCATION_OFFSETS.padding_between_table_and_loader]
        # Checking the offset
        assert elf_buffer[magic_off:magic_off + self.ptr_size] == self.address_utils.pack_pointer(
            self.shellcode_table_magic), elf_buffer[magic_off:magic_off + self.ptr_size]
        padding_between_table_and_loader = segment.virtual_address - loader_main_off
        # Now replacing the padding_between_table_and_loader
        elf_buffer_p1 = elf_buffer[:padding_between_table_and_loader_off]
        elf_buffer_p2 = elf_buffer[padding_between_table_and_loader_off + self.ptr_size:]
        elf_buffer = elf_buffer_p1 + self.address_utils.pack_pointer(padding_between_table_and_loader) + elf_buffer_p2
        loader_symbol_address = self.mini_loader.loader.find(self.address_utils.pack_pointer(0xdeadbeff))
        assert loader_symbol_address == self.mini_loader.loader.rfind(
            self.address_utils.pack_pointer(0xdeadbeff)), "Error found more then one " \
                                                          "occurrence"
        shellcode_start = segment.virtual_address
        # Offset to where the shellcode starts
        self.logger.info("Setting shellcode base address at: {}->MINI_LOADER:MAIN".format(
            hex(shellcode_start)
        ))
        # Offset to the entry point of the loader
        elf_buffer_with_address = elf_buffer[:loader_symbol_address]

        # Setting the eshelf entry point to shellcode_start
        # Thats because the start of the shellcode is the relocation table
        elf_buffer_with_address += self.address_utils.pack_pointer(shellcode_start)
        self.logger.info("Setting relocation table address to: {}".format(hex(segment.virtual_address)))
        # Adding the rest of the shellcode into the buffer
        elf_buffer_with_address += elf_buffer[loader_symbol_address + self.ptr_size:]
        return elf_buffer_with_address

    def f_offset_get_matching_virtual_address(self, f_offset):
        for segment in self.get_segments_in_memory():
            if segment.f_start <= f_offset <= segment.f_end:
                distance = f_offset - segment.f_start
                return segment.v_start + distance
        raise Exception("f_offset not in binary")

    def make_relative(self, address):
        return address - self.loading_virtual_address

    def unpack_ptr(self, stream):
        assert len(stream) == self.ptr_size, "Error stream size: {}, required: {}".format(
            len(stream),
            self.ptr_size
        )
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt), stream[:self.ptr_size])[0]

    @property
    def opcodes_start_address(self):
        # Well this is actually the first objdump-ed section f_start
        return self.linker_base_address

    def stream_unpack_pointers(self, stream, num_of_ptrs):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt * num_of_ptrs), stream[:self.ptr_size * num_of_ptrs])

    def embed(self, **kwargs):
        for key, value in kwargs.items():
            globals()[key] = value
        import IPython
        IPython.embed()
        if not kwargs.get("do_not_exit"):
            sys.exit(1)

    @property
    def post_build_length(self):
        return len(self.do_objdump(self.shellcode_data))

    def __repr__(self):
        return "Shellcode(table_size={})".format(len(self.relocation_table(0x0)))


def get_shellcode_class(args, shellcode_cls):
    fd = open(args.input, 'rb')
    elffile = ELFFile(fd)
    with open(args.input, "rb") as fp:
        shellcode_data = fp.read()
    shellcode = shellcode_cls(elffile=elffile,
                              shellcode_data=shellcode_data,
                              args=args)
    return shellcode, fd


def make_shellcode(args, shellcode_cls):
    shellcode_handler, fd = get_shellcode_class(args=args, shellcode_cls=shellcode_cls)
    args = sys.modules["global_args"]
    if args.interactive:
        print("Opening interactive shell, Use shellcode to view the shellcode class")
        shellcode_handler.embed(shellcode=shellcode_handler)
        sys.exit(1)
    shellcode = shellcode_handler.get_shellcode()
    shellcode_repr = repr(shellcode_handler)

    fd.close()
    return shellcode, shellcode_repr


def create_make_shellcode(shellcode_cls):
    def wrapper(args):
        return make_shellcode(args=args, shellcode_cls=shellcode_cls)

    return wrapper
