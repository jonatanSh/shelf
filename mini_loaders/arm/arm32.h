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

#define call_main(main_ptr, argc, argv, total_args) {                           \
   register size_t r0 asm("r0") = (size_t)(main_ptr); \
   register size_t r1 asm("r1") = (size_t)(argc); \
   register size_t r2 asm("r2") = (size_t)(argv); \
   register size_t r3 asm("r3") = (size_t)((total_args+1) * 4); \
   asm(                                                 \
        "add sp,sp, #-4\n"                              \
        "str lr, [sp]\n"                                \
        "blx r0\n"                                     \
        "ldr lr, [sp]\n"                                \
        "add sp, sp, #4\n"                              \
        :  :                                            \
        "r"(r0), "r"(r1), "r"(r2), "r"(r3)              \
   );                                                   \
}                                                       \


#endif