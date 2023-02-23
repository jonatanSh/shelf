from elf_to_shellcode.lib.shellcode import Shellcode, create_make_shellcode
from elf_to_shellcode.arm.arm_32_dynamic_relocations import Arm32DynamicRelocations


class ArmX32Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(ArmX32Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="arm32",
            mini_loader_little_endian="mini_loader_arm_x32{}.shellcode",
            mini_loader_big_endian="mini_loader_arm_x32be{}.shellcode",
            shellcode_table_magic=0xaabbccdd,
            ptr_fmt="I",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
                '.got.plt': {'align_by': 'sh_entsize', 'relocate_all': True},

            },
            support_dynamic=True,
            add_dynamic_relocation_lib=False,
            **kwargs
        )
        self.dynamic_handler = Arm32DynamicRelocations(shellcode=self)
        self.add_relocation_handler(self.dynamic_handler.handle)


arm_x32_make_shellcode = create_make_shellcode(ArmX32Shellcode)
