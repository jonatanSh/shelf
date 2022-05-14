#ifndef LOADER_INTEL_X64
#define LOADER_INTEL_X64
typedef unsigned long long size_t;
#define SUPPORT_IRELATIVE
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
        "get_pc_internal:\n"        \
        "jmp next\n"                \
        "mov rax, [rsp]\n"          \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr) {                           \
   register size_t rax asm("rax") = (size_t)(main_ptr); \
   asm(                                                 \
        "call rax\n"                                    \
       :  :                                             \
       "r"(rax)                                         \
   );                                                   \
}                                                       \

#define RESOLVE_IRELATIVE(irelative_address) {      \
    asm(                                            \
        "push rbx\n"                                \
        "push rcx\n"                                \
        "push rdx\n"                                \
        "push rsi\n"                                \
        "call rax\n"                                \
        "pop rsi\n"                                 \
        "pop rdx\n"                                 \
        "pop rcx\n"                                 \
        "pop rbx\n"                                 \
        : "=r"(irelative_address) :                 \
        "r"(irelative_address)                      \
    );                                              \
}                                                   \

#endif