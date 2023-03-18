#include "./generic_loader.h"
#include "eshelf/eshelf.h"

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


#ifdef ESHELF
    static size_t __loader_symbol__shellcode_entry = 0xdeadbeff;
#endif
#ifdef ESHELF
void main(int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic, size_t pc) {
    loader_main(argc, argv,envp,loader_magic, pc);
}
#endif
void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc) {
    size_t table_start;
    size_t table_size = 0;
    struct relocation_table * table;
    size_t magic;
    size_t total_argv_envp_size = 0;
    size_t total_header_plus_table_size = 0;
    long long int _out;
    size_t _dispatcher_out;
    size_t return_address;
    size_t shellcode_main_relative;
    struct addresses addresses;
    ARCH_FUNCTION_ENTER(&return_address);
#ifdef DEBUG
    TRACE("Loader in debug mode!");
    long long int mini_loader_status = 0;
#endif

#ifdef ESHELF
    TRACE("Loader support: ESHELF");
#endif
#ifdef SUPPORT_DYNAMIC_LOADER
    TRACE("Loader support: SUPPORT_DYNAMIC_LOADER");
#endif
#ifdef SUPPORT_HOOKS
    TRACE("Loader support: SUPPORT_HOOKS");
#endif
    TRACE("Mini loader loaded");
    resolve_table_magic();
    /*
        Otherwise loader has be called with pc
    */
    TRACE("Loader magic is 0x%x, required table magic is 0x%x",
    loader_magic, magic);
    if(loader_magic != magic) {
        #ifndef ESHELF
            get_pc();
        #else
            /* 
                On eshelf mode we set __loader_symbol__shellcode_entry 
                to point to the start of the relocation table
            */
            pc = __loader_symbol__shellcode_entry;
        #endif
        advance_pc_to_magic();
    }
    TRACE("Found table at: 0x%x", pc);
    // If we got here then we found the table
    table = (struct relocation_table *)pc;
    TRACE("Found table, magic = 0x%x, excpecting 0x%x", table->magic, magic);
    ASSERT(table->magic == magic, INVALID_MAGIC);
    total_header_plus_table_size = table->total_size;
    total_header_plus_table_size += table->header_size;
#ifdef SUPPORT_HOOKS
    addresses.hooks_base_address = (size_t)(table);
    addresses.hooks_base_address += sizeof(struct relocation_table) + total_header_plus_table_size;
    TRACE("Adding hooks shellcode sizes to total_header_plus_table_size shellcode size = 0x%x", table->hook_descriptor.size_of_hook_shellcode_data);
    total_header_plus_table_size += table->hook_descriptor.size_of_hook_shellcode_data;
    DISPATCH_HOOKS(addresses.hooks_base_address, startup_hooks);
#endif
    // Size of table header + entries + entry point
    addresses.base_address = (size_t)(table);
    addresses.base_address += sizeof(struct relocation_table) + total_header_plus_table_size;
    addresses.base_address += table->padding;
    addresses.loader_base =(size_t)((void *)(table) - table->elf_information.loader_size) -  table->padding_between_table_and_loader;
    TRACE("loader_base = 0x%x, base_address = 0x%x", addresses.loader_base, addresses.base_address);
    // We consider the table size and the entry point as parsed
    TRACE("Starting to parse table, total size = 0x%x", total_header_plus_table_size);
    // handling relocation table
    LOADER_DISPATCH(loader_handle_relocation_table, table, &addresses, &shellcode_main_relative, 0x0);
    ASSERT((_dispatcher_out == 0x0), _out);
    // Dispatcher out is the function return value;
    void * entry_point = (void *)((size_t)shellcode_main_relative + addresses.base_address);

    TRACE("Shellcode entry point = 0x%x", entry_point);
    TRACE("Calling shellcode main");
    call_function(entry_point, entry_point, argc, argv, (total_argv_envp_size + 1) * 4);
#ifdef ARCH_GET_FUNCTION_OUT
    ARCH_GET_FUNCTION_OUT();
#endif

// We ifdef everything here for compact loader
#ifdef DEBUG
    // If we got here then just exit normaly, and do not set error code
    goto exit;
#endif 

error:
#ifdef DEBUG
    // This will set the mini loader status as the exit code
    _out = mini_loader_status;
#endif
exit:
#ifdef ESHELF
    TRACE("ESHELF exit, RC is irrelevant");
#endif
    TRACE("Mini loader exit, _out=0x%x", _out);
    TEARDOWN(1);
    ARCH_FUNCTION_EXIT(return_address);
    ARCH_RETURN(_out);
/*
Some arches still doesn't support ARCH_RETURN
Think about how to fix this, currently it triggers compiler errors
#ifdef DEBUG
    return _out;
#endif
*/
}

STATUS loader_handle_relocation_table(struct relocation_table * table, struct addresses * addresses, size_t * out) {
    size_t parsed_entries_size = 0;
    size_t return_address;
    size_t entries_for_attribute = 0;
    void * entry_ptr = (void *)(((size_t)table) + sizeof(struct relocation_table));
    ARCH_FUNCTION_ENTER(&return_address);
    struct entry_attributes * attributes;
    while(parsed_entries_size < table->total_size) {
        #ifdef DEBUG
        TRACE("TableParser (table->total_size=0x%x, parsed_entries_size=0x%x)",
            table->total_size,
            parsed_entries_size
        );
        #endif
        if(entries_for_attribute == 0) {
            attributes = (struct entry_attributes*)(entry_ptr + parsed_entries_size);
            entries_for_attribute = attributes->number_of_entries_related_to_attribute;
            parsed_entries_size += sizeof(struct entry_attributes);
            TRACE("found relocation attributes, num of relocations = 0x%x, relocation_type=0x%x",
            attributes->number_of_entries_related_to_attribute, attributes->relocation_type);
        }
        struct table_entry * entry = (struct table_entry *)(entry_ptr + parsed_entries_size);

        // Now parsing the entry
        size_t f_offset = entry->f_offset + addresses->base_address;
        size_t v_offset = entry->v_offset + addresses->base_address; 
        #ifdef DEBUG
            TRACE("Parssing Entry(f_offset=0x%x, v_offset=0x%x, relocation_type=0x%x)",
                entry->f_offset, entry->v_offset,attributes->relocation_type);
        #endif    
        /*
            DO NOT USE SWITCH CASE HERE
            it will create a relocatable section
        */
        if(attributes->relocation_type != GENERIC_RELOCATE) {
            // We have relocation attributes
            // Can't use jump tables in loader :(
            size_t attribute_val = 0;
            if(attributes->relocation_type == IRELATIVE) {
                #ifdef DEBUG
                    TRACE("Loader IRELATIVE fix: 0x%x=0x%x()", v_offset, v_offset);
                    TRACE_ADDRESS(v_offset, 24);
                #endif
                attribute_val = (size_t)((IRELATIVE_T)(v_offset))();
                #ifdef DEBUG
                    TRACE("Loader IRELATIVE returned: 0x%x", attribute_val);
                #endif
                v_offset = attribute_val;
            }
            else if(attributes->relocation_type == RELATIVE_TO_LOADER_BASE) {
                attribute_val = (size_t)(entry->v_offset + addresses->loader_base);
                #ifdef DEBUG
                    TRACE("Loader RELATIVE_TO_LOADER_BASE fix: 0x%x=0x%x()", v_offset, attribute_val);
                #endif
                v_offset = attribute_val;
            }
            else if(attributes->relocation_type == RELATIVE) {
                attribute_val = (size_t)(*((size_t*)f_offset)) + addresses->base_address;
                #ifdef DEBUG
                    TRACE("Loader RELATIVE fix: 0x%x=0x%x()", v_offset, attribute_val);
                #endif
                v_offset = attribute_val;
            }
            else {
                return INVALID_ATTRIBUTE;
            }
        }
        #ifdef DEBUG
            TRACE("Loader set *((size_t*)0x%x) = 0x%x", f_offset, v_offset);
        #endif
        // Fixing the entry
#ifdef SUPPORT_HOOKS
        DISPATCH_HOOKS(addresses->hooks_base_address, pre_relocate_write_hooks);
#endif
        *((size_t*)f_offset) = v_offset;

        parsed_entries_size += sizeof(struct table_entry);
        if(attributes) {
            entries_for_attribute -= 1;
        }
    }
    *out = *(size_t*)(size_t)(entry_ptr + parsed_entries_size);
    TRACE("shellcode main located at relative %x", *out);
    goto success;
error:
    return ERROR;
success:
    ARCH_FUNCTION_EXIT(return_address);
    return 0x0;
}

#ifdef SUPPORT_DYNAMIC_LOADER

int get_elf_information(struct relocation_table **info) {
    size_t pc;
    size_t magic;
    struct relocation_table * table;
    int status = ERROR;
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);

    resolve_table_magic();
/* If eshelf then get pc was never called and
    there are no such labels as get pc and we must call get_pc
*/
#ifndef ESHELF
    call_get_pc();
#else
    get_pc();
#endif
    advance_pc_to_magic();
    table = (struct relocation_table *)pc;
    if(table->magic != magic) {
        goto error;
    }

    *info = table;
    status = OK;

    ARCH_FUNCTION_EXIT(return_address);
error:
    return status;


}

#endif