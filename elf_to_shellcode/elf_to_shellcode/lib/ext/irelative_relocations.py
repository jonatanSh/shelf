from elf_to_shellcode.elf_to_shellcode.lib.consts import RelocationAttributes


class IrelativeRelocs(object):
    def __init__(self, irelative_type, jmp_slot_type=None):
        self.irelative_type = irelative_type
        self.jmp_slot_type = jmp_slot_type

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
                raise Exception("Relocation not supported yet: {}".format(
                    relocation.entry.r_info
                ))

            virtual_offset = shellcode.make_relative(relocation.entry.r_offset)
            function_offset = shellcode.make_relative(relocation.entry.r_addend)
            shellcode.addresses_to_patch[virtual_offset] = [function_offset,
                                                            RelocationAttributes.call_to_resolve]
        return shellcode_data

    def relocation_for_rel_plt_got_plt(self, shellcode, shellcode_data):
        """
        Specific handler for the .rela.plt and .got.plt relocations
        :return:
        """
        rel_plt = shellcode.elffile.get_section_by_name('.rel.plt')
        got_plt = shellcode.elffile.get_section_by_name(".got.plt")
        if not rel_plt:
            return shellcode_data
        if rel_plt and not got_plt:
            raise Exception("Relocation not supported yet")

        for relocation in rel_plt.iter_relocations():
            relocation_type = relocation.entry.r_info_type
            if relocation_type == self.irelative_type:

                self.do_irelative_rel_plt_got_plt(
                    shellcode=shellcode,
                    got_plt=got_plt,
                    relocation=relocation
                )
            elif relocation_type == self.jmp_slot_type:
                self.do_jmp_slot_relocation(
                    shellcode=shellcode,
                    got_plt=got_plt,
                    relocation=relocation
                )
            else:
                raise Exception("Relocation not supported yet: {}".format(
                    relocation.entry.r_info_type
                ))
        return shellcode_data

    @staticmethod
    def do_irelative_rel_plt_got_plt(shellcode, got_plt, relocation):
        virtual_offset = shellcode.make_relative(relocation.entry.r_offset)
        function_offset = shellcode.address_utils.section_get_ptr_at_address(
            section=got_plt,
            address=relocation.entry.r_offset,
            alignment=got_plt.header.sh_entsize
        )
        function_offset = shellcode.make_relative(function_offset)
        shellcode.addresses_to_patch[virtual_offset] = [function_offset,
                                                        RelocationAttributes.call_to_resolve]

    def do_jmp_slot_relocation(self, shellcode, got_plt, relocation):
        # This case is already integrated in to the default relocation algorithm
        pass
