#ifndef LOADER_MIPS
#define LOADER_MIPS
typedef unsigned int size_t;

#define ARCH_OPCODE_SIZE 4 
#define TABLE_MAGIC 0xaabbccdd
#define ARCH_CALL_GET_PC "bal get_pc_internal\n"

#define get_pc() {      \
    asm(                            \
        "bal get_pc_internal\n"     \
        "b next\n"                  \
        "get_pc_internal:\n"        \
        "move $v0, $ra\n"           \
        "jr $ra\n"                  \
        "next:"                     \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr, argc, argv, total_args) {                           \
   register size_t t9 asm("t9") = (size_t)(main_ptr);           \
   register size_t a0 asm("a0") = (size_t)(main_ptr);           \
   register size_t a1 asm("a1") = (size_t)(argc);               \
   register size_t a2 asm("a2") = (size_t)(argv);               \
   register size_t a3 asm("a3") = (size_t)((total_args+1) * 4); \
   asm(                                                         \
       "addiu $sp, $sp, -4\n"                                   \
       "sw $ra, 0($sp)\n"                                       \
       "jalr $t9\n"                                             \
       "lw $ra, 0($sp)\n"                                       \
       "addiu $sp, $sp, 4\n"                                    \
       :  :                                                     \
       "r"(t9)                                                  \
   );                                                           \
}                                                               \


#define ARCH_FUNCTION_ENTER(ra) {            \
    register size_t a0 asm("a0");           \
    asm(                                    \
        "move $a0, $ra\n"                    \
        : :                                 \
        "r"(a0)                             \
    );                                      \
    *ra = a0;                               \
}                                           \

#define ARCH_FUNCTION_EXIT(ra) {             \
   register size_t a0 asm("a0") = (size_t)(ra);\
    asm(                                    \
        "move $ra, $a0\n"                     \
        : :                                 \
        "r"(a0)                             \
    );                                      \
}                                           \

#endif