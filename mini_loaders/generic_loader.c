typedef unsigned int size_t;
#define ARCH_OPCODE_SIZE 4 
#define MAX_SEARCH_DEPTH 0xffe
#define TABLE_MAGIC 0xaabbccdd

struct table_entry {
    size_t size;
    size_t f_offset;
    size_t v_offset;
};
struct relocation_table {
    size_t magic;
    size_t total_size;
};


#define get_pc() {      \
    size_t out;                     \
    asm(                            \
        "addiu $sp, $sp, -4\n"      \
        "sw $ra, 0($sp)\n"          \
        "bal get_pc_internal\n"     \
        "lw $ra, 0($sp)\n"          \
        "addiu $sp,4\n"             \
        "b next\n"                  \
        "get_pc_internal:\n"        \
        "move $v0, $ra\n"           \
        "jr $ra\n"                  \
        "next:"                     \
        : "=r"(out) :               \
                                    \
    );                              \
    pc = out;                       \
}                                   \

#define call_main(main_ptr) {                           \
   register size_t t9 asm("t9") = (size_t)(main_ptr);   \
   asm(                                                 \
       "addiu $sp, $sp, -4\n"                           \
       "sw $ra, 0($sp)\n"                               \
       "jalr $t9\n"                                     \
       "lw $ra, 0($sp)\n"                               \
       "addiu $sp, $sp, 4\n"                            \
       :  :                                             \
       "r"(t9)                                          \
   );                                                   \
}                                                       \

void loader_main() {
    size_t pc;
    size_t table_start;
    size_t table_size = 0;
    struct relocation_table * table;
    size_t base_address;
    get_pc();

    for(size_t i = 0; i < MAX_SEARCH_DEPTH; i+=ARCH_OPCODE_SIZE) {
        pc += ARCH_OPCODE_SIZE;
        if(*((size_t*)pc) == TABLE_MAGIC) {
            break;
        }
        if(i==MAX_SEARCH_DEPTH-1) {
            goto error;
        }
    }
    // If we got here then we found the table
    table = (struct relocation_table *)pc;
    // Size of table header + entries + entry point
    base_address = (size_t)(table);
    base_address += sizeof(struct relocation_table) + table->total_size + sizeof(size_t);
    void * entry_ptr = (void *)(((size_t)table) + sizeof(struct relocation_table));
    // We consider the table size and the entry point as parsed
    size_t parsed_entries_size = 0;
    while(parsed_entries_size < table->total_size) {
        struct table_entry * entry = (struct table_entry *)entry_ptr;
        // Now parsing the entry
        size_t f_offset = entry->f_offset + base_address;
        size_t v_offset = entry->v_offset + base_address; 
        // Fixing the entry
        *((size_t*)f_offset) = v_offset;

        parsed_entries_size += entry->size;
        entry_ptr += entry->size;
    }
    void * entry_point = (*(size_t*)(entry_ptr) + base_address);
    call_main(entry_point);

error:
exit:
    return;
}