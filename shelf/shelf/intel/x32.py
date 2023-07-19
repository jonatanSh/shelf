from shelf.lib.shellcode import Shellcode, create_make_shellcode
from elftools.elf.enums import ENUM_RELOC_TYPE_i386
from shelf.intel.intel_irelative_relocations import IntelIrelativeRelocs
from shelf.lib.consts import StartFiles
from shelf.intel.x32_dynamic_relocations import X32DynamicRelocations
from shelf.lib.consts import ShellcodeMagics
from shelf.intel.x32_opcodes_analysis import IntelX32OpcodesAnalyzer


def get_glibc_instructions_filter(address):
    def _filter(instruction):
        if hex(address) in instruction.op_str:
            return True
        return False

    return _filter


class IntelX32Shellcode(Shellcode):
    def __init__(self, elffile, shellcode_data, args, **kwargs):
        super(IntelX32Shellcode, self).__init__(
            elffile=elffile,
            shellcode_data=shellcode_data,
            args=args,
            arch="x32",
            mini_loader_little_endian="mini_loader_x32{}.shellcode",
            mini_loader_big_endian=None,
            shellcode_table_magic=ShellcodeMagics.arch32.value,
            ptr_fmt="I",
            sections_to_relocate={
                '.data.rel.ro': {'align_by': 'sh_addralign'},

            },
            supported_start_methods=[
                StartFiles.no_start_files,
                # StartFiles.glibc
            ],
            support_dynamic=True,
            **kwargs
        )
        self.irelative = IntelIrelativeRelocs(
            irelative_type=ENUM_RELOC_TYPE_i386['R_386_IRELATIVE'],
            jmp_slot_type=ENUM_RELOC_TYPE_i386['R_386_JUMP_SLOT'],
            get_glibc_instructions_filter=get_glibc_instructions_filter
        )
        self.add_relocation_handler(self.irelative.relocation_for_rel_plt_got_plt)
        self.dynamic_handler = X32DynamicRelocations(shellcode=self)
        self.add_relocation_handler(self.dynamic_handler.handle)
        self.deep_analysis = IntelX32OpcodesAnalyzer(self)
        self.add_shellcode_formatter(self.deep_analysis.analyze)


intel_x32_make_shellcode = create_make_shellcode(IntelX32Shellcode)
