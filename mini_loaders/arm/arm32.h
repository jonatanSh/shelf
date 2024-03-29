#ifndef LOADER_ARM_X32
#define LOADER_ARM_X32


#define ARCH_OPCODE_SIZE 2
#define GET_TABLE_MAGIC() {     \
    asm(                        \
        "mov r0, #0xaa\n"       \
        "lsl r0, r0, #24\n"     \
        "mov r1, #0xbb\n"       \
        "lsl r1, r1, #16\n"     \
        "add r0, r1\n"          \
        "mov r1, #0xcc\n"       \
        "lsl r1, r1, #8\n"     \
        "add r0, r1\n"          \
        "add r0, #0xdd\n"       \
        "mov %0, r0\n"          \
        : "=r"(magic) :         \
    );                          \
}                               \

#define get_pc() {      \
    asm(                            \
        "mov %0, pc\n"\
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_get_pc get_pc

#define call_function(main_ptr, a1, a2, a3, a4, _out) {     \
   register size_t r0 asm("r0") = (size_t)(a1); \
   register size_t r1 asm("r1") = (size_t)(a2); \
   register size_t r2 asm("r2") = (size_t)(a3); \
   register size_t r3 asm("r3") = (size_t)(a4); \
   register size_t r4 asm("r4") = (size_t)(main_ptr); \
   asm(                                                 \
        "add sp,sp, #-4\n"                              \
        "str lr, [sp]\n"                                \
        "blx r4\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #4\n"                              \
        : "=r"(_out) :                                            \
        "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4)     \
   );                                                   \
}                                                       \


#endif