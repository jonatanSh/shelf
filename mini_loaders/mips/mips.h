#ifndef LOADER_MIPS
#define LOADER_MIPS

#define ARCH_OPCODE_SIZE 4 
#define TABLE_MAGIC 0xaabbccdd
#define ARCH_CALL_GET_PC "bal get_pc_internal\n"

#define ARCH_STORE_REGS() {             \
    asm(                                \
       "addiu $sp, $sp, -104\n"         \
        "sw $t0, 0($sp)\n"              \
        "sw $t1, 4($sp)\n"              \
        "sw $t2, 8($sp)\n"              \
        "sw $t3, 12($sp)\n"             \
        "sw $t4, 16($sp)\n"             \
        "sw $t5, 20($sp)\n"             \
        "sw $t6, 24($sp)\n"             \
        "sw $t7, 28($sp)\n"             \
        "sw $t8, 32($sp)\n"             \
        "sw $t9, 36($sp)\n"             \
        "sw $s0, 40($sp)\n"             \
        "sw $s1, 44($sp)\n"             \
        "sw $s2, 48($sp)\n"             \
        "sw $s3, 52($sp)\n"             \
        "sw $s4, 56($sp)\n"             \
        "sw $s5, 60($sp)\n"             \
        "sw $s6, 64($sp)\n"             \
        "sw $s7, 68($sp)\n"             \
        "sw $s8, 72($sp)\n"             \
        "sw $gp, 76($sp)\n"             \
        "sw $fp, 80($sp)\n"             \
        "sw $at, 84($sp)\n"             \
        "sw $a0, 88($sp)\n"             \
        "sw $a1, 92($sp)\n"             \
        "sw $a2, 96($sp)\n"             \
        "sw $a3, 100($sp)\n"            \
        : :                             \
    );                                  \
}                                       \

#define ARCH_RESTORE_REGS() {             \
    asm(                                \
        "lw $t0, 0($sp)\n"              \
        "lw $t1, 4($sp)\n"              \
        "lw $t2, 8($sp)\n"              \
        "lw $t3, 12($sp)\n"             \
        "lw $t4, 16($sp)\n"             \
        "lw $t5, 20($sp)\n"             \
        "lw $t6, 24($sp)\n"             \
        "lw $t7, 28($sp)\n"             \
        "lw $t8, 32($sp)\n"             \
        "lw $t9, 36($sp)\n"             \
        "lw $s0, 40($sp)\n"             \
        "lw $s1, 44($sp)\n"             \
        "lw $s2, 48($sp)\n"             \
        "lw $s3, 52($sp)\n"             \
        "lw $s4, 56($sp)\n"             \
        "lw $s5, 60($sp)\n"             \
        "lw $s6, 64($sp)\n"             \
        "lw $s7, 68($sp)\n"             \
        "lw $s8, 72($sp)\n"             \
        "lw $gp, 76($sp)\n"             \
        "lw $fp, 80($sp)\n"             \
        ".set noat\n"                   \
        "lw $at, 84($sp)\n"             \
        "lw $a0, 88($sp)\n"             \
        "lw $a1, 92($sp)\n"             \
        "lw $a2, 96($sp)\n"             \
        "lw $a3, 100($sp)\n"            \
        "addiu $sp, $sp, 104\n"         \
        : :                             \
    );                                  \
}                                       \

#if defined(SUPPORT_HOOKS)
    #define HOOK_CALL_ENTER ARCH_STORE_REGS
#else
    #define HOOK_CALL_ENTER()
#endif

#if defined(SUPPORT_HOOKS)
    #define HOOK_CALL_EXIT ARCH_RESTORE_REGS
#else
    #define HOOK_CALL_EXIT()
#endif

#define ARCH_GET_FUNCTION_OUT() {   \
    asm(                            \
        "\n"                        \
        : "=r"(_out)                \
    );                              \
}                                   \

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
   HOOK_CALL_ENTER();                                           \
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
   HOOK_CALL_EXIT();                                            \
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

#define ARCH_FUNCTION_EXIT(ra) {          \
   register size_t a0 asm("a0") = (size_t)(ra); \
    asm(                                        \
        "move $ra, $a0\n"                       \
        : :                                     \
        "r"(a0)                                 \
    );                                          \
}                                               \


#define ARCH_RETURN(_out) {          \
   register size_t v0 asm("v0") = (size_t)(_out); \
   register size_t v1 asm("v1") = (size_t)(*(&_out+sizeof(size_t))); \
    asm(                                        \
        "move $v0, %0\n"                       \
        "move $v1, %1\n"                       \
        : :                                     \
        "r"(v0),"r"(v1)                         \
    );                                          \
}                                               \

#endif