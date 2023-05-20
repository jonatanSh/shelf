from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from shelf.lib.shellcode import Shellcode, create_make_shellcode
from shelf.intel.intel_irelative_relocations import IntelIrelativeRelocs
from shelf.intel.x64_dynamic_relocations import X64DynamicRelocations
from shelf.lib.consts import ShellcodeMagics


class IntelX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(IntelX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="x64",
            mini_loader_little_endian="mini_loader_x64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=ShellcodeMagics.arch64.value,
            ptr_fmt="Q",

            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            },
            support_dynamic=True,
            **kwargs
        )
        self.irelative = IntelIrelativeRelocs(ENUM_RELOC_TYPE_x64['R_X86_64_IRELATIVE'])
        self.add_relocation_handler(self.irelative.relocation_for_rela_plt_got_plt)
        self.dynamic_handler = X64DynamicRelocations(shellcode=self)
        self.add_relocation_handler(self.dynamic_handler.handle)


intel_x64_make_shellcode = create_make_shellcode(IntelX64Shellcode)
