from elf_to_shellcode.elf_to_shellcode.lib.consts import RelocationAttributes
from elf_to_shellcode.elf_to_shellcode.lib.consts import RELOC_TYPES
import logging


class DynamicRelocations(object):
    def __init__(self, reloc_types):
        self.handlers = {}
        self.handlers['JMPREL'] = self.handle_jmp_slot_relocs
        self.handlers["REL"] = self.handle_rels
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reloc_types = reloc_types

    def handle(self, shellcode, shellcode_data):

        # This case is already integrated in to the default relocation algorithm
        dynsym = shellcode.elffile.get_section_by_name(".dynsym")
        dynamic = shellcode.elffile.get_section_by_name('.dynamic')
        if not dynamic:
            return shellcode_data
        assert dynsym
        relocation_table = dynamic.get_relocation_tables()
        relocs = relocation_table.keys()
        for reloc_type in relocs:
            handler = self.handlers.get(reloc_type, None)
            if not handler:
                self.logger.error("[HandlerNotFound] {}".format(
                    reloc_type
                ))
                raise Exception("Not supported")
            else:
                logging.info("Relocation types: {}".format(
                    relocation_table.keys()
                ))
                handler(shellcode=shellcode,
                        table=relocation_table[reloc_type],
                        dynsym=dynsym)
        self.handle_other_dynamic_relocations(shellcode=shellcode)
        return shellcode_data

    def handle_other_dynamic_relocations(self, shellcode):
        rel_dyn = shellcode.elffile.get_section_by_name('.rel.dyn')
        rel_plt = shellcode.elffile.get_section_by_name('.rel.plt')
        if rel_dyn:
            self.handle_rel_dyn(shellcode, rel_dyn)

    def handle_rel_dyn(self, shellcode, rel_dyn):
        dynsym = shellcode.elffile.get_section_by_name(".dynsym")

        for entry in rel_dyn.iter_relocations():
            entry = entry.entry
            if entry.r_info_type == self.reloc_types[RELOC_TYPES.RELATIVE]:
                offset = shellcode.make_relative(entry.r_offset)
                self.logger.info("[REL_RELATIVE] Relative({}) Absolute({})".format(
                    hex(offset),
                    hex(shellcode.make_absolute(offset)),
                ))
                shellcode.addresses_to_patch[offset] = [0, RelocationAttributes.relative]
            elif entry.r_info_type in [2, 14]:
                continue
            elif entry.r_info_type in [
                self.reloc_types[RELOC_TYPES.GLOBAL_SYM],
                self.reloc_types[RELOC_TYPES.GLOBAL_DAT]
            ]:
                sym = dynsym.get_symbol(entry.r_info_sym)
                offset = shellcode.make_relative(entry.r_offset)
                r_address = shellcode.make_relative(sym.entry.st_value)
                self.logger.info("[SYM_R|{}] Relative(*{}={}) Absolute(*{}={})".format(
                    sym.name,
                    hex(offset),
                    hex(r_address),
                    hex(shellcode.make_absolute(offset)),
                    hex(shellcode.make_absolute(r_address))
                ))
                shellcode.addresses_to_patch[offset] = r_address

            else:
                self.logger.error("[R_TYPE_NOT_SUPPORTED]: {}, only {} are supported".format(
                    entry,
                    self.reloc_types
                ))
                assert False

    def handle_jmp_slot_relocs(self, shellcode,
                               table,
                               dynsym):
        for relocation in table.iter_relocations():
            entry = relocation.entry
            offset = shellcode.make_relative(entry.r_offset)
            symbol_obj = dynsym.get_symbol(entry.r_info_sym)
            symbol_name = symbol_obj.name
            r_address = symbol_obj.entry.st_value
            """
            Jump slot for local elf symbol.
            the elf is compiled as -shared
            """
            if r_address:
                r_address = shellcode.make_relative(r_address)
                self.logger.info("[JMP_SL_LC] Relative(*{}={}) Absolute(*{}={})".format(
                    hex(offset),
                    hex(r_address),
                    hex(shellcode.make_absolute(offset)),
                    hex(shellcode.make_absolute(r_address))
                ))
                shellcode.addresses_to_patch[offset] = r_address
                continue

            """
            External symbol
            Trying to resolve
            """
            if not shellcode.loader_symbols.has_symbol(symbol_name):
                self.logger.info("[SymNotFound] {}".format(
                    symbol_name
                ))
                continue
            jmp_slot_address = shellcode.loader_symbols.get_relative_symbol_address(
                symbol_name=symbol_name
            )
            self.logger.info("[JMP_SL] Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(offset),
                hex(jmp_slot_address),
                hex(shellcode.make_absolute(offset)),
                hex(shellcode.make_absolute(jmp_slot_address))
            ))
            shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                    RelocationAttributes.relative_to_loader_base]

    def handle_rels(self,
                    shellcode,
                    table,
                    dynsym):
        for entry in table.iter_relocations():
            entry = entry.entry
            symbol_obj = dynsym.get_symbol(entry.r_info_sym)
            v_offset = shellcode.make_relative(symbol_obj.entry.st_value)
            offset = shellcode.make_relative(entry.r_offset)
            if entry.r_info_type == self.reloc_types[RELOC_TYPES.JMP_SLOT]:
                sym_type = symbol_obj.entry.st_info.type
                if sym_type == "STT_FUNC":
                    shellcode.addresses_to_patch[offset] = v_offset
                elif sym_type == "STT_LOOS":
                    shellcode.addresses_to_patch[offset] = [v_offset,
                                                            RelocationAttributes.call_to_resolve]
                elif sym_type == "STT_NOTYPE":
                    self.logger.error("Sym type: STT_NOTYPE error")
                else:
                    self.logger.error("Unknown symtype: {} {}".format(symbol_obj.name, sym_type))
                    assert False
                self.logger.info("[JMP_SL_{}] Relative(*{}={}()) Absolute(*{}={}())".format(
                    sym_type,
                    hex(offset),
                    hex(v_offset),
                    hex(shellcode.make_absolute(offset)),
                    hex(shellcode.make_absolute(v_offset))
                ))
            # Think about, those, they are already handled because the code is bad for now
            elif entry.r_info_type in [self.reloc_types[RELOC_TYPES.GLOBAL_SYM],
                                       self.reloc_types[RELOC_TYPES.RELATIVE],
                                       self.reloc_types[RELOC_TYPES.GLOBAL_DAT],
                                       2, 14]:
                continue
            else:
                self.logger.error("[R_TYPE_NOT_SUPPORTED]: {}, only {} are supported".format(
                    entry,
                    self.reloc_types
                ))
                assert False
