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

#define call_main(main_ptr, argc, argv, total_args) {                           \
   register size_t rdi asm("rdi") = (size_t)(main_ptr);            \
   register size_t rsi asm("rsi") = (size_t)(argc);                \
   register size_t rdx asm("rdx") = (size_t)(argv);                \
   register size_t rcx asm("rcx") = (size_t)((total_args+1) * 4);  \
   asm(                                                            \
        "call rdi\n"                                               \
       :  :                                                        \
       "r"(rdi),"r"(rsi),"r"(rdx),"r"(rcx)                         \
   );                                                              \
}                                                                  \


#endif