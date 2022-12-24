import logging
from elf_to_shellcode.lib.consts import RelocationAttributes
from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_MIPS
from elf_to_shellcode.lib.consts import RELOC_TYPES


class MipsShellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(MipsShellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            arch="mips",
            mini_loader_little_endian="mini_loader_mips{}.shellcode",
            mini_loader_big_endian="mini_loader_mipsbe{}.shellcode",
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.got': {'align_by': 'sh_entsize', 'relocate_all': True},
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            reloc_types={
                RELOC_TYPES.GLOBAL_SYM: ENUM_RELOC_TYPE_MIPS['R_MIPS_REL32'],
                RELOC_TYPES.DO_NOT_HANDLE: [
                    ENUM_RELOC_TYPE_MIPS['R_MIPS_NONE']
                ]

            },
            support_dynamic=True,
            **kwargs
        )

        self.got_sym_start = -1
        self.got_sym_num_entries = -1
        self.mips_local_got_ono = -1
        self.dynsym = self.elffile.get_section_by_name(".dynsym")
        self.can_handle_dynamic_got_relocs = False
        self.prepare_got_parsing()


    def prepare_got_parsing(self):
        dynamic = self.elffile.get_section_by_name(".dynamic")
        if not dynamic:
            return
        for tag in dynamic.iter_tags():
            if tag.entry['d_tag'] == 'DT_MIPS_GOTSYM':
                self.got_sym_start = tag.entry['d_val']
            if tag.entry['d_tag'] == 'DT_MIPS_SYMTABNO':
                self.got_sym_num_entries = tag.entry['d_val']
            if tag.entry['d_tag'] == 'DT_MIPS_LOCAL_GOTNO':
                self.mips_local_got_ono = tag.entry['d_val']

        if self.got_sym_start == -1:
            return
        if self.got_sym_num_entries < self.got_sym_start:
            return
        if self.mips_local_got_ono == -1:
            return

            # Now we should start fixing got entries !
        if self.dynsym:
            self.can_handle_dynamic_got_relocs = True

    def relocation_hook(self, section_name, virtual_offset, sym_offset, index):
        """
        There are 3 tags in mips DT_MIPS_GOTSYM which is the index of the first symbol
        in the .dynsym section of the got entry, eg DT_MIPS_GOTSYM.val = 7
        means that the first symbol in the got start at index 7 in the .dynsym section
        DT_MIPS_SYMTABNO number of entries in the got, eg DT_MIPS_SYMTABNO.val = 2
        meaning there are 2 symbols in the got where the first index is 7 then 8
        DT_MIPS_LOCAL_GOTNO number of entries in the got before the symbols start eg DT_MIPS_LOCAL_GOTNO.val = 7
        meaning there are got entries before symbols start and DT_MIPS_GOTSYM is used

        :param section_name:
        :param virtual_offset:
        :param sym_offset:
        :param index:
        :return:
        """
        if not self.can_handle_dynamic_got_relocs:
            return virtual_offset, sym_offset

        if index < self.mips_local_got_ono:
            return virtual_offset, sym_offset
        sym_index = self.got_sym_start + (index - self.mips_local_got_ono)  # ptr size is 4 bytes
        if sym_index > self.got_sym_num_entries:
            logging.warn("Mips .got fallback sym_index > self.got_sym_num_entries")
            return virtual_offset, sym_offset
        sym = self.dynsym.get_symbol(sym_index)
        if self.loader_symbols.has_symbol(sym.name):
            sym_offset = self.loader_symbols.get_relative_symbol_address(
                symbol_name=sym.name
            )
            sym_offset = [sym_offset,
             RelocationAttributes.relative_to_loader_base]
            was_loader_sym = True
        else:
            was_loader_sym = False

        self.logger.info("Handling got symbol: {} at virtual: {}, was_loader_sym={}".format(sym.name,
                                                                                            hex(virtual_offset),
                                                                                            was_loader_sym))

        return virtual_offset, sym_offset


mips_make_shellcode = create_make_shellcode(MipsShellcode)
