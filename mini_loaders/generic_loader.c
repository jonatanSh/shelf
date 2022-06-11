#include "./loader_generic.h"

/*
    Macro insted of functions:
        we must use macros we dont want to generate internal calls in the loader

    Loader entry point
    argc = number of arguments
    argv = argument vector
    envp = enviroment variables
    loader_magic used with pc, if present and equal to the arch magic table magic
    pc is taken from the arguments and not calculated
*/
void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc) {
    size_t table_start;
    size_t table_size = 0;
    struct relocation_table * table;
    size_t base_address;
    size_t loader_base;
    size_t magic;
    size_t total_argv_envp_size = 0;
    resolve_table_magic();
    /*
        Otherwise loader has be called with pc
    */
    if(loader_magic != magic) {
        get_pc();
        advance_pc_to_magic();        
    }
    // If we got here then we found the table
    table = (struct relocation_table *)pc;
    if(table->magic != magic) {
        goto error;
    }
    // Size of table header + entries + entry point
    base_address = (size_t)(table);
    base_address += sizeof(struct relocation_table) + table->total_size + sizeof(size_t);
    loader_base =(size_t)((void *)(table) - table->elf_information.loader_size);
    void * entry_ptr = (void *)(((size_t)table) + sizeof(struct relocation_table));
    // We consider the table size and the entry point as parsed
    size_t parsed_entries_size = 0;
    while(parsed_entries_size < table->total_size) {
        struct table_entry * entry = (struct table_entry *)entry_ptr;
        struct entry_attributes * attributes = (struct entry_attributes*)((void*)entry+sizeof(size_t)*3);
        // Now parsing the entry
        size_t f_offset = entry->f_offset + base_address;
        size_t v_offset = entry->v_offset + base_address; 
        
        /*
            DO NOT USE SWITCH CASE HERE
            it will create a relocatable section
        */
        if(entry->size > sizeof(size_t) * 3) {
            // We have relocation attributes
            // Can't use jump tables in loader :(
            if(attributes->attribute_1 == IRELATIVE) {
                v_offset = (size_t)((IRELATIVE_T)(v_offset))();
            }
            else if(attributes->attribute_1 == RELATIVE_TO_LOADER_BASE) {
                v_offset = (size_t)(entry->v_offset + loader_base);
            }
            else if(attributes->attribute_1 == RELATIVE) {
                v_offset = (size_t)(*((size_t*)f_offset)) + base_address;
            }
            else {
                goto error;
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
        total_argv_envp_size = argc + 1; // for null terminator
        while(argv[total_argv_envp_size]) {
            total_argv_envp_size ++;
        }
        total_argv_envp_size += 1; // for envp null terminator       
        // Now overriding the auxiliary vector to point to the first pht_entry
        argv[total_argv_envp_size] = (entry_ptr + table->elf_information.elf_header_size);
#endif
    call_main(entry_point, argc, argv, total_argv_envp_size);

error:
exit:
    return;
}

#ifdef SUPPORT_DYNAMIC_LOADER

int get_elf_information(struct relocation_table **info) {
    size_t pc;
    size_t magic;
    struct relocation_table * table;
    int status = ERROR;
    call_get_pc();
    resolve_table_magic();
    advance_pc_to_magic();
    table = (struct relocation_table *)pc;
    if(table->magic != magic) {
        goto error;
    }

    *info = table;
    status = OK;

error:
    return status;


}

#endif