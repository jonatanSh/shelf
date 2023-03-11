#ifndef LOADER_INTEL_X64
#define LOADER_INTEL_X64

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

#define call_function(main_ptr, a1, a2, a3, a4) {                           \
   register size_t rdi asm("rdi") = (size_t)(a1);            \
   register size_t rsi asm("rsi") = (size_t)(a2);                \
   register size_t rdx asm("rdx") = (size_t)(a3);                \
   register size_t rcx asm("rcx") = (size_t)(a4);  \
   register size_t rax asm("rax") = (size_t)(main_ptr);  \
   asm(                                                            \
        "call rax\n"                                               \
       :  :                                                        \
       "r"(rdi),"r"(rsi),"r"(rdx),"r"(rcx),"r"(rax)                \
       : "rsp"\
   );                                                              \
}                                                                  \


#endif