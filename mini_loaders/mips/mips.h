#ifndef LOADER_MIPS
#define LOADER_MIPS
typedef unsigned int size_t;

#define ARCH_OPCODE_SIZE 4 
#define TABLE_MAGIC 0xaabbccdd

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


#endif