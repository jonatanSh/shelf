from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, RelocationAttributes, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_x64


class IntelX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian):
        super(IntelX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_x64.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            }
        )

        self.add_relocation_handler(self.relocation_for_rela_plt_got_plt)

    def relocation_for_rela_plt_got_plt(self, shellcode_data):
        """
        Specific handler for the .rela.plt and .got.plt relocations
        :return:
        """
        rela_plt = self.elffile.get_section_by_name('.rela.plt')
        got_plt = self.elffile.get_section_by_name(".got.plt")
        if not rela_plt:
            return shellcode_data
        if rela_plt and not got_plt:
            raise Exception("Relocation not supported yet")

        for relocation in rela_plt.iter_relocations():
            if relocation.entry.r_info != ENUM_RELOC_TYPE_x64['R_X86_64_IRELATIVE']:
                raise Exception("Relocation not supported yet")

            virtual_offset = relocation.entry.r_offset - self.linker_base_address
            function_offset = relocation.entry.r_addend - self.linker_base_address
            self.addresses_to_patch[virtual_offset] = [function_offset,
                                                       RelocationAttributes.call_to_resolve]
        return shellcode_data


intel_x64_make_shellcode = create_make_shellcode(IntelX64Shellcode)
