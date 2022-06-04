#include "./loader_generic.h"

void loader_main(int argc, char ** argv, char ** envp) {
    size_t pc;
    size_t table_start;
    size_t table_size = 0;
    struct relocation_table * table;
    size_t base_address;
    size_t magic;
    size_t total_argv_envp_size = 0;
    get_pc();
    #ifndef TABLE_MAGIC
        #ifndef GET_TABLE_MAGIC
            #error Table magic unknown
        #endif
        GET_TABLE_MAGIC();
    #else
        magic = TABLE_MAGIC;
    #endif

    for(size_t i = 0; i < MAX_SEARCH_DEPTH; i+=ARCH_OPCODE_SIZE) {
        pc += ARCH_OPCODE_SIZE;
        if(*((size_t*)pc) == magic) {
            break;
        }
    }
    // If we got here then we found the table
    table = (struct relocation_table *)pc;
    if(table->magic != magic) {
        goto error;
    }
    // Size of table header + entries + entry point
    base_address = (size_t)(table);
    base_address += sizeof(struct relocation_table) + table->total_size + sizeof(size_t);
    void * entry_ptr = (void *)(((size_t)table) + sizeof(struct relocation_table));
    // We consider the table size and the entry point as parsed
    size_t parsed_entries_size = 0;
    while(parsed_entries_size < table->total_size) {
        struct table_entry * entry = (struct table_entry *)entry_ptr;
        struct entry_attributes * attributes = (struct entry_attributes*)((void*)entry+sizeof(size_t)*3);
        // Now parsing the entry
        size_t f_offset = entry->f_offset + base_address;
        size_t v_offset = entry->v_offset + base_address; 
        
        if(entry->size > sizeof(size_t) * 3) {
            // We have relocation attributes
            // Can't use jump tables in loader :(
            if(attributes->attribute_1 == IRELATIVE) {
                v_offset = (size_t)((IRELATIVE_T)(v_offset))();
            }
        }
        // Fixing the entry
        *((size_t*)f_offset) = v_offset;

        parsed_entries_size += entry->size;
        entry_ptr += entry->size;
    }
    void * entry_point = (void *)(*(size_t*)(entry_ptr) + base_address);

#ifdef SUPPORT_START_FILES
        int looking_at_argv = 0;
        int index = 0;
        while(1) {
            if(looking_at_argv == 0) {
                if(argv[index] != 0) {
                    index+=1;
                    total_argv_envp_size+=1;
                }
                else {
                    index = 0;
                    looking_at_argv = 1;
                }
            }
            else {
                if(envp[index] != 0) {
                    total_argv_envp_size+=1;
                    index+=1;
                }
                else {
                    break;
                }
            }
        }
        total_argv_envp_size += 2; // for null terminators
        // Now overriding the auxiliary vector to point to the first pht_entry
        argv[total_argv_envp_size++]=(entry_ptr + table->elf_header_size);
#endif
    call_main(entry_point, argc, argv, total_argv_envp_size);

error:
exit:
    return;
}