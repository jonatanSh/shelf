from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode


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
                '.got.plt': {'align_by': 'sh_entsize', 'relocate_all': True},
            }
        )

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
