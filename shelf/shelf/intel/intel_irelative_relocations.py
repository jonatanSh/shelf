from shelf.lib.consts import RelocationAttributes, StartFiles
import logging


class IntelIrelativeRelocs(object):
    def __init__(self, irelative_type,
                 jmp_slot_type=None,
                 get_glibc_instructions_filter=None):
        self.irelative_type = irelative_type
        self.jmp_slot_type = jmp_slot_type
        self.get_glibc_instructions_filter = get_glibc_instructions_filter
        self.glibc_irelative_first_reference = 2 ** 32
        self.glibc_last_reference = 0
        self.logger = logging.getLogger("[IRELATIVE-HELPER]")

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
                self.logger.error("Relocation not supported yet: {}".format(
                    relocation.entry.r_info
                ))
                continue

            virtual_offset = shellcode.make_relative(relocation.entry.r_offset)
            function_offset = shellcode.make_relative(relocation.entry.r_addend)
            self.logger.info("| IRELATIVE CALL TO RESOLVE | Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(virtual_offset),
                hex(function_offset),
                hex(shellcode.address_utils.make_absolute(virtual_offset)),
                hex(shellcode.address_utils.make_absolute(function_offset))
            ))
            shellcode.add_to_relocation_table(virtual_offset, [function_offset,
                                                               RelocationAttributes.call_to_resolve])
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
                    relocation=relocation,
                    shellcode_data=shellcode_data
                )
            else:
                raise Exception("Relocation not supported yet: {}".format(
                    relocation.entry.r_info_type
                ))
        return shellcode_data

    def do_irelative_rel_plt_got_plt(self, shellcode, got_plt, relocation):
        virtual_offset = shellcode.make_relative(relocation.entry.r_offset)
        function_offset_rl = shellcode.address_utils.section_get_ptr_at_address(
            section=got_plt,
            address=relocation.entry.r_offset,
            alignment=got_plt.header.sh_entsize
        )
        relocation_entry_relative = shellcode.make_relative(relocation.entry.r_offset)
        function_offset = shellcode.make_relative(function_offset_rl)

        hdr = "GLIBC_R"

        if shellcode.args.start_method != StartFiles.glibc:
            hdr = "IRELATIVE_CALL_TO_RESOLVE"
            shellcode.add_to_relocation_table(virtual_offset,
                                              [function_offset,
                                               RelocationAttributes.call_to_resolve]
                                              )
        else:
            shellcode.add_to_relocation_table(virtual_offset, function_offset)

        self.logger.info("| {} | Relative(*{}={}()) Absolute(*{}={}())".format(
            hdr,
            hex(virtual_offset),
            hex(function_offset),
            hex(shellcode.address_utils.make_absolute(virtual_offset)),
            hex(shellcode.address_utils.make_absolute(function_offset))
        ))
        if shellcode.args.start_method == StartFiles.glibc:
            """
                If so the elf header contain references to those function, 
                we must found those references,
                
            """
            stop_at = shellcode.linker_base_address
            for index in xrange(0, stop_at, shellcode.ptr_size):
                entry = shellcode.unpack_ptr(
                    shellcode.shellcode_data[index: index + shellcode.ptr_size])
                # Here we try to locate this reference.
                if entry == relocation.entry.r_offset:
                    self.logger.info("| HEADER | Relative(*{}={}()) Absolute(*{}={}())".format(
                        hex(index),
                        hex(relocation_entry_relative),
                        hex(shellcode.address_utils.make_absolute(index)),
                        hex(shellcode.address_utils.make_absolute(relocation_entry_relative))
                    ))
                    shellcode.add_to_relocation_table(index, relocation_entry_relative)
                    address_not_relative = shellcode.loading_virtual_address + index

                    self.glibc_irelative_first_reference = min(self.glibc_irelative_first_reference,
                                                               address_not_relative)
                    self.glibc_last_reference = max(self.glibc_irelative_first_reference,
                                                    address_not_relative + shellcode.ptr_size * 2)

    def do_jmp_slot_relocation(self, shellcode,
                               got_plt,
                               relocation,
                               shellcode_data):
        # Already handled
        pass
