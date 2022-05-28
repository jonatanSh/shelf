from elf_to_shellcode.elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_i386
from elf_to_shellcode.elf_to_shellcode.lib.ext.irelative_relocations import IrelativeRelocs
from elf_to_shellcode.elf_to_shellcode.lib.consts import StartFiles


class IntelX32Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, endian, **kwargs):
        super(IntelX32Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            endian=endian,
            mini_loader_little_endian="mini_loader_x32{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            supported_start_methods=[
                StartFiles.no_start_files,
                StartFiles.glibc
            ],
            **kwargs
        )
        self.irelative = IrelativeRelocs(ENUM_RELOC_TYPE_i386['R_386_IRELATIVE'])
        self.add_relocation_handler(self.irelative.relocation_for_rel_plt_got_plt)


intel_x32_make_shellcode = create_make_shellcode(IntelX32Shellcode)
