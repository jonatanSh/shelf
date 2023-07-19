from shelf.lib.shellcode import Shellcode, create_make_shellcode
from shelf.riscv.riscv64_dynamic_relocations import Riscv64DynamicRelocations
from shelf.lib.consts import ShellcodeMagics


class Riscv64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(Riscv64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="riscv64",
            mini_loader_little_endian="mini_loader_riscv64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=ShellcodeMagics.arch64.value,
            ptr_fmt="Q",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            support_dynamic=True,
            **kwargs
        )
        self.dynamic_handler = Riscv64DynamicRelocations(shellcode=self)
        self.add_relocation_handler(self.dynamic_handler.handle)


riscv64_make_shellcode = create_make_shellcode(Riscv64Shellcode)
