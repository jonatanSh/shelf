from elf_to_shellcode.lib.consts import RelocationAttributes
from elf_to_shellcode.lib.consts import RELOC_TYPES
import logging


class DynamicRelocations(object):
    def __init__(self, shellcode, reloc_types):
        self.handlers = {
            'JMPREL': self.handle_jmp_slot_relocs,
            "REL": self.handle_rels
        }
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reloc_types = reloc_types

        self.entry_handlers = {
            self.reloc_types.get(RELOC_TYPES.RELATIVE): self.reloc_relative_handle,
            self.reloc_types.get(RELOC_TYPES.GLOBAL_SYM): self.global_sym_dat_handle,
            self.reloc_types.get(RELOC_TYPES.GLOBAL_DAT): self.global_sym_dat_handle,
            self.reloc_types.get(RELOC_TYPES.JMP_SLOT): self.jmp_slot_reloc_handle,
        }

        self.entry_handlers.update(
            self.reloc_types.get(RELOC_TYPES.ARCH_SPECIFIC, {})
        )
        self.shellcode = shellcode

    def call_entry_handler(self, entry, shellcode, dynsym):
        if entry.r_info_type in self.reloc_types[RELOC_TYPES.DO_NOT_HANDLE]:
            self.logger.warn("Not calling handler for entry: {}, marked as do not handle".format(
                entry
            ))
            return
        entry_handler = self.entry_handlers.get(entry.r_info_type, None)
        if not entry_handler:
            self.logger.error("Entry handler for: {} not found, available: {}".format(
                entry,
                self.entry_handlers.keys()
            ))
            assert False
        logging.info("Calling entry handler: {}".format(entry_handler.__name__))
        entry_handler(entry=entry, shellcode=shellcode, dynsym=dynsym)

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
                logging.info("Handling relocation types: {}, handler: {}".format(
                    relocation_table.keys(),
                    handler.__name__
                ))
                handler(shellcode=shellcode,
                        table=relocation_table[reloc_type],
                        dynsym=dynsym)
        self.handle_other_dynamic_relocations(shellcode=shellcode)
        return shellcode_data

    def handle_other_dynamic_relocations(self, shellcode):
        rel_dyn = shellcode.elffile.get_section_by_name('.rel.dyn')
        if rel_dyn:
            self.handle_rel_dyn(shellcode, rel_dyn)

    def reloc_relative_handle(self, shellcode, entry, **kwargs):
        offset = shellcode.make_relative(entry.r_offset)
        self.logger.info("[REL_RELATIVE] Relative({}) Absolute({})".format(
            hex(offset),
            hex(shellcode.make_absolute(offset)),
        ))
        shellcode.addresses_to_patch[offset] = [0, RelocationAttributes.relative]

    def global_sym_dat_handle(self, shellcode, dynsym, entry):
        sym = dynsym.get_symbol(entry.r_info_sym)
        offset = shellcode.make_relative(entry.r_offset)
        r_address = shellcode.make_relative(sym.entry.st_value)
        if shellcode.loader_symbols.has_symbol(sym.name):
            jmp_slot_address = shellcode.loader_symbols.get_relative_symbol_address(
                symbol_name=sym.name
            )
            shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                    RelocationAttributes.relative_to_loader_base]
            return
        self.logger.info("[SYM_R|{}] Relative(*{}={}) Absolute(*{}={})".format(
            sym.name,
            hex(offset),
            hex(r_address),
            hex(shellcode.make_absolute(offset)),
            hex(shellcode.make_absolute(r_address))
        ))
        shellcode.addresses_to_patch[offset] = r_address

    def handle_rel_dyn(self, shellcode, rel_dyn):
        dynsym = shellcode.elffile.get_section_by_name(".dynsym")

        for entry in rel_dyn.iter_relocations():
            entry = entry.entry
            self.call_entry_handler(
                entry=entry,
                dynsym=dynsym,
                shellcode=shellcode
            )

    def jmp_slot_reloc_handle(self, shellcode, entry, dynsym):
        entry = entry
        symbol_obj = dynsym.get_symbol(entry.r_info_sym)
        v_offset = shellcode.make_relative(symbol_obj.entry.st_value)
        offset = shellcode.make_relative(entry.r_offset)
        sym_type = symbol_obj.entry.st_info.type
        if shellcode.loader_symbols.has_symbol(symbol_obj.name):
            jmp_slot_address = shellcode.loader_symbols.get_relative_symbol_address(
                symbol_name=symbol_obj.name
            )
            self.logger.info("[JMP_SL] Relative(*{}={}()) Absolute(*{}={}())".format(
                hex(offset),
                hex(jmp_slot_address),
                hex(shellcode.make_absolute(offset)),
                hex(shellcode.make_absolute(jmp_slot_address))
            ))
            shellcode.addresses_to_patch[offset] = [jmp_slot_address,
                                                    RelocationAttributes.relative_to_loader_base]
            return
        if not symbol_obj.entry.st_value:
            name = symbol_obj.name
            if name not in [
                '_pthread_cleanup_pop_restore',
                '__pthread_unwind',
                '_Unwind_Resume'
            ]:
                self.logger.error("Symbol not found: {}".format(name))
                assert False
            else:
                self.logger.error("LIBC Symbol not found: {}".format(name))
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

    def handle_jmp_slot_relocs(self, shellcode,
                               table,
                               dynsym):
        for relocation in table.iter_relocations():
            entry = relocation.entry
            self.jmp_slot_reloc_handle(
                shellcode=shellcode,
                entry=entry,
                dynsym=dynsym
            )

    def handle_rels(self,
                    shellcode,
                    table,
                    dynsym):
        for entry in table.iter_relocations():
            entry = entry.entry
            self.call_entry_handler(
                entry=entry,
                dynsym=dynsym,
                shellcode=shellcode
            )
