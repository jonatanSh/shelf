from elf_to_shellcode.elf_to_shellcode.lib.consts import RelocationAttributes


class IrelativeRelocs(object):
    def __init__(self, irelative_type):
        self.irelative_type = irelative_type

    def relocation_for_rela_plt_got_plt(self, shellcode, shellcode_data):
        """
        Specific handler for the .rela.plt and .got.plt relocations
        :return:
        """
        rela_plt = shellcode.elffile.get_section_by_name('.rela.plt')
        got_plt = shellcode.elffile.get_section_by_name(".got.plt")
        if not rela_plt:
            return shellcode_data
        if rela_plt and not got_plt:
            raise Exception("Relocation not supported yet")

        for relocation in rela_plt.iter_relocations():
            if relocation.entry.r_info != self.irelative_type:
                raise Exception("Relocation not supported yet")

            virtual_offset = relocation.entry.r_offset - shellcode.linker_base_address
            function_offset = relocation.entry.r_addend - shellcode.linker_base_address
            shellcode.addresses_to_patch[virtual_offset] = [function_offset,
                                                            RelocationAttributes.call_to_resolve]
        return shellcode_data
