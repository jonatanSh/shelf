#ifndef LOADER_ARM_X64
#define LOADER_ARM_X64
typedef unsigned long long size_t;

#define ARCH_OPCODE_SIZE 2
#define TABLE_MAGIC 0x8899aabbccddeeff
#define get_pc() {      \
    asm(                            \
        "add sp, sp, #-8\n"         \
        "str lr, [sp]\n"            \
        "bl get_pc_internal\n"      \
        "ldr lr, [sp]\n"            \
        "add sp, sp, #8\n"          \
        "b next\n"                  \
        "get_pc_internal:\n"        \
        "mov %0, lr\n"              \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr) {                           \
   register size_t x0 asm("x0") = (size_t)(main_ptr); \
   asm(                                                 \
        "add sp,sp, #-8\n"                              \
        "str lr, [sp]\n"                                \
        "blr x0\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #8\n"                              \
        :  :                                            \
        "r"(x0)                                         \
   );                                                   \
}                                                       \


#endif