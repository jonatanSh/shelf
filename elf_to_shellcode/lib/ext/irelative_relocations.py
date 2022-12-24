from elf_to_shellcode.lib.consts import RelocationAttributes, StartFiles
import logging


class IrelativeRelocs(object):
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
            self.logger.info("| IRELATIVE | Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(virtual_offset),
                hex(function_offset),
                hex(shellcode.make_absolute(virtual_offset)),
                hex(shellcode.make_absolute(function_offset))
            ))
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
                    relocation=relocation,
                    shellcode_data=shellcode_data
                )
            else:
                raise Exception("Relocation not supported yet: {}".format(
                    relocation.entry.r_info_type
                ))
        self.fix_glibc_references(shellcode)
        return shellcode_data

    def fix_glibc_references(self, shellcode):
        if shellcode.start_file_method != StartFiles.glibc:
            return

        assert self.glibc_irelative_first_reference != 2 ** 32
        assert self.glibc_last_reference != 0

        """ here we should search for the opcode containing first reference, last reference
             and fix thoose opcodes
             ...eg :
             .text:0804A480 C7 C3 B4 81 04 08                       mov     ebx, offset off_80481B4
             .text:0804A486 C7 C7 24 82 04 08                       mov     edi, 8048224h
        """

        for entry in [self.glibc_irelative_first_reference, self.glibc_last_reference]:
            addresses = shellcode.disassembler.get_instruction_addresses(
                instruction_filter=self.get_glibc_instructions_filter(entry)
            )
            for address in addresses:
                self.logger.info("[!GLIBC] |InstructionPatch| Relative({}), Absolute({})".format(
                    hex(address),
                    hex(shellcode.make_absolute(address))
                ))
                shellcode.addresses_to_patch[address] = shellcode.make_relative(entry)

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

        if shellcode.start_file_method != StartFiles.glibc:
            hdr = "IRELATIVE"
            shellcode.addresses_to_patch[virtual_offset] = [function_offset,
                                                            RelocationAttributes.call_to_resolve]
        else:
            shellcode.addresses_to_patch[virtual_offset] = function_offset

        self.logger.info("| {} | Relative(*{}={}()) Absolute(*{}={}())".format(
            hdr,
            hex(virtual_offset),
            hex(function_offset),
            hex(shellcode.make_absolute(virtual_offset)),
            hex(shellcode.make_absolute(function_offset))
        ))
        if shellcode.start_file_method == StartFiles.glibc:
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
                        hex(shellcode.make_absolute(index)),
                        hex(shellcode.make_absolute(relocation_entry_relative))
                    ))
                    shellcode.addresses_to_patch[index] = relocation_entry_relative
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
