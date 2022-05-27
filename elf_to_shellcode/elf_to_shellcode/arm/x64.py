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
        constructed_without_padding = header + code
        loader_base = self.get_loader_base_address(constructed_without_padding)
        nop_opcode = '\x1f\x20\x03\xd5'
        if len(header) > aarch64_alignment:
            alignment = len(header) % aarch64_alignment
        else:
            alignment = aarch64_alignment - len(header)
        assert alignment % len(nop_opcode) == 0, "Alignment error"
        alignment /= len(nop_opcode)
        padding = nop_opcode * alignment
        constructed = header + padding + code
        return self.set_loader_base_address(constructed,
                                            loader_base + len(padding))


arm_x64_make_shellcode = create_make_shellcode(ArmX64Shellcode)