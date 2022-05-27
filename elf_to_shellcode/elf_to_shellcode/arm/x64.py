from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64


class ArmX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian):
        super(ArmX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_arm_x64.shellcode",
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
            if relocation.entry.r_info != 1:
                raise Exception("Relocation not supported yet: {}".format(relocation.entry.r_info))
        return shellcode_data

    def build_shellcode_from_header_and_code(self, header, code):
        # Now we are going to align our shellcode
        aarch64_alignment = (2 << 12)
        if len(header) > aarch64_alignment:
            alignment = len(header) % aarch64_alignment
        else:
            alignment = aarch64_alignment - len(header)
        padding = '\x00' * alignment
        header_moved = self.move_header_by_offset(header,
                                                  offset=len(padding))

        constructed = header_moved + padding + code
        return constructed


arm_x64_make_shellcode = create_make_shellcode(ArmX64Shellcode)
