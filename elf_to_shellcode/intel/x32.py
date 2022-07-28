from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_i386
from elf_to_shellcode.lib.ext.irelative_relocations import IrelativeRelocs
from elf_to_shellcode.lib.consts import StartFiles
from elf_to_shellcode.lib.consts import RELOC_TYPES


def get_glibc_instructions_filter(address):
    def _filter(instruction):
        if hex(address) in instruction.op_str:
            return True
        return False

    return _filter


class IntelX32Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(IntelX32Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            arch="x32",
            mini_loader_little_endian="mini_loader_x32{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            supported_start_methods=[
                StartFiles.no_start_files,
                # StartFiles.glibc
            ],
            reloc_types={
                RELOC_TYPES.JMP_SLOT: ENUM_RELOC_TYPE_i386['R_386_JUMP_SLOT'],
                RELOC_TYPES.RELATIVE: ENUM_RELOC_TYPE_i386['R_386_RELATIVE'],
                RELOC_TYPES.GLOBAL_SYM: ENUM_RELOC_TYPE_i386['R_386_32'],
                RELOC_TYPES.GLOBAL_DAT: ENUM_RELOC_TYPE_i386['R_386_GLOB_DAT'],
                RELOC_TYPES.DO_NOT_HANDLE: [
                    ENUM_RELOC_TYPE_i386['R_386_PC32'],
                    ENUM_RELOC_TYPE_i386['R_386_TLS_TPOFF'],
                ]

            },
            support_dynamic=True,
            **kwargs
        )
        self.irelative = IrelativeRelocs(
            irelative_type=ENUM_RELOC_TYPE_i386['R_386_IRELATIVE'],
            jmp_slot_type=ENUM_RELOC_TYPE_i386['R_386_JUMP_SLOT'],
            get_glibc_instructions_filter=get_glibc_instructions_filter
        )
        self.add_relocation_handler(self.irelative.relocation_for_rel_plt_got_plt)

        if self.start_file_method == StartFiles.glibc:
            self.add_relocation_handler(self.glibc_patch_symbols)

    def glibc_patch_symbols(self, shellcode, shellcode_data):
        """
        Glibc smybols:
         __environ
         __libc_stack_end
         for some reason doesn't support pic mode.
         therefor we manually relocate them
        :param shellcode: shellcode object
        :param shellcode_data: shellcode data
        :return: new shellcode object
        """
        symtab = shellcode.elffile.get_section_by_name('.symtab')

        special_symbols = [s.name for s in symtab.iter_symbols()
                           if s.entry.st_info.bind == 'STB_GLOBAL'
                           and s.entry.st_info.type == 'STT_OBJECT']

        for sym_name in special_symbols:
            sym = symtab.get_symbol_by_name(sym_name)

            if not sym or len(sym) == 0:
                continue
            if len(sym) > 1:
                raise Exception("Unknown error")
            sym = sym[0]
            entry_address = sym.entry.st_value

            addresses = shellcode.disassembler.get_instruction_addresses(
                instruction_filter=get_glibc_instructions_filter(entry_address)
            )

            for address in addresses:
                self.logger.info("![GLIBC] |InstructionPatch| Sym({}) Relative({}), Absolute({})".format(
                    sym.name,
                    hex(address),
                    hex(shellcode.make_absolute(address))
                ))
                shellcode.addresses_to_patch[address] = self.make_relative(entry_address)
        return shellcode_data


intel_x32_make_shellcode = create_make_shellcode(IntelX32Shellcode)
