#ifndef LOADER_ARM_X64
#define LOADER_ARM_X64

#define ARCH_OPCODE_SIZE 2
#define TABLE_MAGIC 0x8899aabbccddeeff
#define ARCH_CALL_GET_PC "bl get_pc_internal\n"

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
   asm(                                                 \
        "add sp,sp, #-8\n"                              \
        "str lr, [sp]\n"                                \
        "blr x0\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #8\n"                              \
        :  :                                            \
        "r"(x0), "r"(x1), "r"(x2), "r"(x3)              \
   );                                                   \
}                                                       \


#endif