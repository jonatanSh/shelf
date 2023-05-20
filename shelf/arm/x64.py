import logging

from shelf.lib.shellcode import Shellcode, create_make_shellcode
from shelf.arm.aarch64_dynamic_relocations import AArch64DynamicRelocations
from shelf.lib.consts import ShellcodeMagics


# Refernce: https://static1.squarespace.com/static/59c4375b8a02c798d1cce06f/t/59d55a7bf5e2319471bb94a4/1507154557709/ELF+for+ARM64.pdf

class ArmX64Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(ArmX64Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="arm64",
            mini_loader_little_endian="mini_loader_arm_x64{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=ShellcodeMagics.arch64.value,
            ptr_fmt="Q",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},
            },
            support_dynamic=True,
            **kwargs
        )
        self.dynamic_handler = AArch64DynamicRelocations(shellcode=self)
        self.add_relocation_handler(self.dynamic_handler.handle)

    def shellcode_handle_padding(self, shellcode_data):
        logging.info("Getting dummy header")
        dummy_header = self.shellcode_get_full_header(padding=0x0)

        # Now we are going to align our shellcode
        aarch64_alignment = (2 << 12)
        if len(dummy_header) > aarch64_alignment:
            alignment = aarch64_alignment - (len(dummy_header) % aarch64_alignment)
        else:
            alignment = aarch64_alignment - len(dummy_header)
        padding = b'\x00' * alignment
        logging.info("Aarch64 add alignment: {}, dummy header size: {}".format(
            hex(alignment),
            hex(len(dummy_header))
        ))
        return alignment, padding + shellcode_data


arm_x64_make_shellcode = create_make_shellcode(ArmX64Shellcode)
