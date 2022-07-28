from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64
from elf_to_shellcode.lib.ext.irelative_relocations import IrelativeRelocs


# Refernce: https://static1.squarespace.com/static/59c4375b8a02c798d1cce06f/t/59d55a7bf5e2319471bb94a4/1507154557709/ELF+for+ARM64.pdf

class ArmX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(ArmX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            arch="arm64",
            mini_loader_little_endian="mini_loader_arm_x64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0x8899aabbccddeeff,
            ptr_fmt="Q",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            },
            support_dynamic=False,
            **kwargs
        )
        self.irelative = IrelativeRelocs(ENUM_RELOC_TYPE_AARCH64['R_AARCH64_TLS_DTPMOD32'])
        self.add_relocation_handler(self.irelative.relocation_for_rela_plt_got_plt)

    def build_shellcode_from_header_and_code(self, header, code):
        # Now we are going to align our shellcode
        aarch64_alignment = (2 << 12)
        if len(header) > aarch64_alignment:
            alignment = len(header) % aarch64_alignment
        else:
            alignment = aarch64_alignment - len(header)
        padding = b'\x00' * alignment
        header_moved = self.move_header_by_offset(header,
                                                  offset=len(padding))

        constructed = header_moved + padding + code
        return constructed


arm_x64_make_shellcode = create_make_shellcode(ArmX64Shellcode)
