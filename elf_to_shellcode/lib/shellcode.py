import os
import struct
import sys
import logging
import tempfile
from elftools.elf.constants import P_FLAGS
from elf_to_shellcode.lib import five
from elftools.elf.elffile import ELFFile
import lief
from lief.ELF import SECTION_FLAGS
from elf_to_shellcode.lib.utils.address_utils import AddressUtils
from elf_to_shellcode.lib.utils.mini_loader import MiniLoader
from elf_to_shellcode.lib.consts import StartFiles, OUTPUT_FORMAT_MAP, LoaderSupports, Arches, ArchEndians, \
    RELOCATION_OFFSETS, RelocationAttributes, HookTypes
from elf_to_shellcode.lib.utils.disassembler import Disassembler
from elf_to_shellcode.lib.ext.dynamic_symbols import DynamicRelocations
from elf_to_shellcode.lib.utils.hooks import ShellcodeHooks
from elf_to_shellcode.lib.utils.general import get_binary
from elf_to_shellcode.hooks.hooks_configuration_parser import HookConfiguration
from elf_to_shellcode.hooks.base_hook import _BaseShelfHook
from elf_to_shellcode.lib.utils.memory_section import MemorySection, MemoryProtection

PTR_SIZES = {
    4: "I",
    8: "Q"
}


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
                 add_dynamic_relocation_lib=True,
                 **kwargs):
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
        self.lief_elf = lief.parse(self.args.input)
        self.shellcode_table_magic = shellcode_table_magic
        # Key is the file offset, value is the offset to correct to
        self.addresses_to_patch = {}
        self.sections_to_relocate = sections_to_relocate

        self.shellcode_data = shellcode_data
        self.ptr_fmt = ptr_fmt
        self.ptr_signed_fmt = self.ptr_fmt.lower()
        self.relocation_handlers = []

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

        self.disassembler = Disassembler(self)
        if self.support_dynamic:
            if add_dynamic_relocation_lib:
                self.dynamic_relocs = DynamicRelocations(shellcode=self, reloc_types=reloc_types)
                self.add_relocation_handler(self.dynamic_relocs.handle)

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
        return struct.calcsize(self.ptr_fmt)

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
                packed += self.address_utils.pack_pointers(key, value)
                i += 1

        return packed, i

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

        header = self.address_utils.pack_pointer(self.shellcode_table_magic) + sizes
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
                relocate_all=attributes.get("relocate_all", False),
                shellcode_data=shellcode_data
            )
        return shellcode_data

    def section_build_relocations_table(self, section_name, relocate_all, shellcode_data):
        data_section = self.elffile.get_section_by_name(section_name)
        original_symbol_addresses = self.get_original_symbols_addresses()
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
                if data_section_value not in original_symbol_addresses and not relocate_all:
                    self.logger.info("[R_SKIPPED]{}".format(hex(data_section_value)))
                    continue
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
                self.addresses_to_patch[virtual_offset] = sym_offset
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
                        start=start,
                        vsize=end,
                        size=f_end - f_start,
                        f_start=f_start,
                        f_end=f_end,
                        protection=protection,
                    )
                )

        return sections_in_memory

    @staticmethod
    def aligned(a, b):
        return a + (a % b)

    def get_section_virtual_address(self, section_name):
        offset, first_section = self.get_first_executable_section_virtual_address()
        total_size = self.aligned(first_section.size, first_section.alignment) + offset
        should_skip = True
        for section in self.lief_elf.sections:
            if should_skip:
                should_skip = not (section.name == first_section.name)
                continue
            if section.flags & SECTION_FLAGS.ALLOC:
                if section.name == section_name:
                    return total_size
                else:
                    total_size += self.aligned(section.size, section.alignment)

        raise Exception("Section: {} is not allocatable".format(
            section_name
        ))

    def get_first_executable_section_virtual_address(self):
        """
         Trying to locate the first executable section
         """
        # calculate all the section size up to the first executable section
        exclude_sections = [
            '.reginfo',
        ]
        last_section = None
        for section in self.lief_elf.sections:
            if section.flags & SECTION_FLAGS.EXECINSTR:
                last_offset = 0
                if last_section:
                    last_offset = last_section.offset + last_section.size
                return [section.offset - last_offset, section]
            elif section.name not in exclude_sections and section.flags & SECTION_FLAGS.ALLOC:
                last_section = section

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

    @property
    def loading_virtual_address(self):
        return self.get_linker_base_address(
            check_x=False,
            attribute="p_vaddr"
        )

    @property
    def linker_base_address(self):
        return self.get_linker_base_address()

    def get_original_symbols_addresses(self):
        symtab = self.elffile.get_section_by_name(".symtab")
        addresses = []
        for sym in symtab.iter_symbols():
            address = sym.entry.st_value
            if address >= self.loading_virtual_address:
                addresses.append(address)

        return addresses

    def get_symbol_name_from_address(self, address):

        symtab = self.elffile.get_section_by_name(".symtab")
        for sym in symtab.iter_symbols():
            sym_address = sym.entry.st_value
            if sym_address == address:
                return sym.name

        return None

    def get_shellcode_header(self):
        original_entry_point = self.elffile.header.e_entry
        new_entry_point = (original_entry_point - self.loading_virtual_address)
        return self.address_utils.pack_pointer(new_entry_point)

    def build_shellcode_from_header_and_code(self, header, code):
        return header + code

    def shellcode_get_full_header(self, padding=0x0):
        shellcode_header = self.get_shellcode_header()
        relocation_table = self.relocation_table(padding=padding)
        full_header = relocation_table + shellcode_header

        if self.args.output_format != OUTPUT_FORMAT_MAP.eshelf:
            full_header = self.mini_loader.loader + full_header
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
        self.logger.info("Setting shellcode base address at: {}".format(
            hex(segment.virtual_address)
        ))
        # Offset to where the shellcode starts
        shellcode_start = self.address_utils.pack_pointer(segment.virtual_address)

        # Offset to the entry point of the loader
        elf_buffer_with_address = elf_buffer[:loader_symbol_address]

        # Setting the eshelf entry point to shellcode_start
        # Thats because the start of the shellcode is the relocation table
        elf_buffer_with_address += shellcode_start
        self.logger.info("Setting relocation table address to: {}".format(hex(segment.virtual_address)))
        # Adding the rest of the shellcode into the buffer
        elf_buffer_with_address += elf_buffer[loader_symbol_address + self.ptr_size:]
        return elf_buffer_with_address

    def make_relative(self, address):
        return address - self.loading_virtual_address

    def unpack_ptr(self, stream):
        return struct.unpack("{}{}".format(self.endian,
                                           self.ptr_fmt), stream[:self.ptr_size])[0]

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
