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

#define ARCH_FUNCTION_ENTER(ra) {            \
    register size_t x30 asm("x30");           \
    asm(                                    \
        "mov %0, x30\n"                    \
        : :                                 \
        "r"(x30)                             \
    );                                      \
    *ra = x30;                               \
}                                           \

#define ARCH_FUNCTION_EXIT(ra) {          \
   register size_t x30 asm("x30") = (size_t)(ra); \
    asm(                                        \
        "mov x30, %0\n"                       \
        : :                                     \
        "r"(x30)                                 \
    );                                          \
}                                               \


#define ARCH_RETURN(_out) {          \
   register size_t x0 asm("x0") = (size_t)(_out); \
   register size_t x1 asm("x1") = (size_t)(*(size_t*)(((char*)&_out)+sizeof(size_t))); \
    asm(                                        \
        "mov x0, %0\n"                       \
        "mov x1, %1\n"                       \
        : :                                     \
        "r"(x0),"r"(x1)                         \
    );                                          \
}                                               \


#define ARCH_STORE_REGS() {             \
    asm(                                \
       "add sp,sp, #-224\n"               \
        "str x2, [sp, #8]\n"               \
        "str x3, [sp, #16]\n"               \
        "str x4, [sp, #24]\n"               \
        "str x5, [sp, #32]\n"               \
        "str x6, [sp, #40]\n"               \
        "str x7, [sp, #48]\n"               \
        "str x8, [sp, #56]\n"               \
        "str x9, [sp, #64]\n"               \
        "str x10, [sp, #72]\n"               \
        "str x11, [sp, #80]\n"               \
        "str x12, [sp, #88]\n"               \
        "str x13, [sp, #96]\n"               \
        "str x14, [sp, #104]\n"               \
        "str x15, [sp, #112]\n"               \
        "str x16, [sp, #120]\n"               \
        "str x17, [sp, #128]\n"               \
        "str x18, [sp, #136]\n"               \
        "str x19, [sp, #144]\n"               \
        "str x20, [sp, #152]\n"               \
        "str x21, [sp, #160]\n"               \
        "str x22, [sp, #168]\n"               \
        "str x23, [sp, #176]\n"               \
        "str x24, [sp, #184]\n"               \
        "str x25, [sp, #192]\n"               \
        "str x26, [sp, #200]\n"               \
        "str x27, [sp, #208]\n"               \
        "str x28, [sp, #216]\n"               \
        : :                                \
    );                                      \
}                                           \



#define ARCH_RESTORE_REGS() {             \
    asm(                                \
        "ldr x2, [sp, #8]\n"               \
        "ldr x3, [sp, #16]\n"               \
        "ldr x4, [sp, #24]\n"               \
        "ldr x5, [sp, #32]\n"               \
        "ldr x6, [sp, #40]\n"               \
        "ldr x7, [sp, #48]\n"               \
        "ldr x8, [sp, #56]\n"               \
        "ldr x9, [sp, #64]\n"               \
        "ldr x10, [sp, #72]\n"               \
        "ldr x11, [sp, #80]\n"               \
        "ldr x12, [sp, #88]\n"               \
        "ldr x13, [sp, #96]\n"               \
        "ldr x14, [sp, #104]\n"               \
        "ldr x15, [sp, #112]\n"               \
        "ldr x16, [sp, #120]\n"               \
        "ldr x17, [sp, #128]\n"               \
        "ldr x18, [sp, #136]\n"               \
        "ldr x19, [sp, #144]\n"               \
        "ldr x20, [sp, #152]\n"               \
        "ldr x21, [sp, #160]\n"               \
        "ldr x22, [sp, #168]\n"               \
        "ldr x23, [sp, #176]\n"               \
        "ldr x24, [sp, #184]\n"               \
        "ldr x25, [sp, #192]\n"               \
        "ldr x26, [sp, #200]\n"               \
        "ldr x27, [sp, #208]\n"               \
        "ldr x28, [sp, #216]\n"               \
       "add sp,sp, #224\n"               \
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

#define call_function(main_ptr, a1, a2, a3, a4) {                           \
   register size_t x0 asm("x0") = (size_t)(a1); \
   register size_t x1 asm("x1") = (size_t)(a2); \
   register size_t x2 asm("x2") = (size_t)(a3); \
   register size_t x3 asm("x3") = (size_t)(a4); \
   register size_t x4 asm("x4") = (size_t)(main_ptr); \
   HOOK_CALL_ENTER();                                       \
   asm(                                                 \
        "add sp,sp, #-8\n"                              \
        "str lr, [sp]\n"                                \
        "blr x4\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #8\n"                              \
        :  :                                            \
        "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4)              \
   );                                                   \
   HOOK_CALL_EXIT();                                    \
}                                                       \




#endif