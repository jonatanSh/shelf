#ifndef LOADER_INTEL_X64
#define LOADER_INTEL_X64
typedef unsigned long long size_t;
#define ARCH_OPCODE_SIZE 1
#define GET_TABLE_MAGIC() {     \
    asm(                        \
        "mov rax, 0x8899aabbccddee00\n" \
        "add rax, 0xff\n"       \
        : "=r"(magic) :         \
    );                          \
}                               \

#define get_pc() {      \
    asm(                            \
        "call get_pc_internal\n"    \
        "jmp next\n"                \
        "get_pc_internal:\n"        \
        "mov rax, [rsp]\n"          \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr, argc, argv, envp) {                           \
   register size_t rax asm("rax") = (size_t)(main_ptr); \
   asm(                                                 \
        "call rax\n"                                    \
       :  :                                             \
       "r"(rax)                                         \
   );                                                   \
}                                                   \


#endif