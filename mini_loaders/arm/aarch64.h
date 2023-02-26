#ifndef LOADER_ARM_X64
#define LOADER_ARM_X64

#define ARCH_OPCODE_SIZE 2
#define TABLE_MAGIC 0x8899aabbccddeeff
#define ARCH_CALL_GET_PC "bl get_pc_internal\n"


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

#define ARCH_STORE_REGS() {             \
    asm(                                \
       "add sp,sp, #-80\n"               \
        "str x19, [sp]\n"               \
        "str x20, [sp, #8]\n"               \
        "str x21, [sp, #16]\n"               \
        "str x22, [sp, #24]\n"               \
        "str x23, [sp, #32]\n"               \
        "str x24, [sp, #40]\n"               \
        "str x25, [sp, #48]\n"               \
        "str x26, [sp, #56]\n"               \
        "str x27, [sp, #64]\n"               \
        "str x28, [sp, #72]\n"               \
        : :                                \
    );                                      \
}                                           \



#define ARCH_RESTORE_REGS() {             \
    asm(                                \
        "ldr x19, [sp]\n"               \
        "ldr x20, [sp, #8]\n"               \
        "ldr x21, [sp, #16]\n"               \
        "ldr x22, [sp, #24]\n"               \
        "ldr x23, [sp, #32]\n"               \
        "ldr x24, [sp, #40]\n"               \
        "ldr x25, [sp, #48]\n"               \
        "ldr x26, [sp, #56]\n"               \
        "ldr x27, [sp, #64]\n"               \
        "ldr x28, [sp, #72]\n"               \
         "add sp,sp, #80\n"               \
        : :                                \
    );                                      \
}                                           \


#define get_pc() {      \
    asm(                            \
        "bl get_pc_internal\n"      \
        "b next\n"                  \
        "get_pc_internal:\n"        \
        "mov %0, lr\n"              \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr, argc, argv, total_args) {                           \
   register size_t x0 asm("x0") = (size_t)(main_ptr); \
   register size_t x1 asm("x1") = (size_t)(argc); \
   register size_t x2 asm("x2") = (size_t)(argv); \
   register size_t x3 asm("x3") = (size_t)((total_args+1) * 8); \
   HOOK_CALL_ENTER();                                       \
   asm(                                                 \
        "add sp,sp, #-8\n"                              \
        "str lr, [sp]\n"                                \
        "blr x0\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #8\n"                              \
        :  :                                            \
        "r"(x0), "r"(x1), "r"(x2), "r"(x3)              \
   );                                                   \
   HOOK_CALL_EXIT();                                    \
}                                                       \


#endif