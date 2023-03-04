#ifndef LOADER_INTEL_X32
#define LOADER_INTEL_X32

#define ARCH_TEADOWN (v) {  \
    asm("ret\n",            \
    ::)                     \
}                           \

#define ARCH_OPCODE_SIZE 1
#define GET_TABLE_MAGIC() {     \
    asm(                        \
        "mov eax, 0xaabbcc00\n" \
        "add eax, 0xdd\n"       \
        : "=r"(magic) :         \
    );                          \
}                               \

#define get_pc() {      \
    asm(                            \
        "call get_pc_internal\n"    \
        "jmp next\n"                \
        "get_pc_internal:\n"        \
        "mov eax, [esp]\n"          \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \


#define call_main_glibc(main_ptr, a1, a2, a3, a4) {                           \
   register size_t eax asm("eax") = (size_t)(a1); \
   register size_t ebx asm("ebx") = (size_t)(a2);     \
   register size_t ecx asm("ecx") = (size_t)(a3);     \
   register size_t esi asm("esi") = (size_t)(a4);     \
   register size_t edx asm("edx") = (size_t)(main_ptr);\
   asm(                                                 \
        "push_args:\n"                                  \
        "push [ecx+esi]\n"                              \
        "sub esi, 4\n"                                  \
        "cmp esi, 0\n"                                  \
        "jg push_args\n"                               \
        "push ebx\n"                                    \
        "jmp edx"                                  \
       :  :                                             \
       "r"(eax), "r"(ebx), "r"(ecx), "r"(esi), "r"(edx) \
   );                                                   \
}

#define call_function(main_ptr, a1, a2, a3, a4) {       \
   register size_t eax asm("eax") = (size_t)(main_ptr); \
   register size_t ebx asm("ebx") = (size_t)(a2);     \
   register size_t ecx asm("ecx") = (size_t)(a3);     \
   register size_t esi asm("esi") = (size_t)(a4);     \
   asm(                                                             \
        "push esi\n"                                    \
        "push ecx\n"                                    \
        "push ebx\n"                                    \
        "push eax\n"                                    \
        "call eax\n"                                    \
        "pop esi\n"                                     \
        "pop ecx\n"                                     \
        "pop ebx\n"                                     \
        /*This is important to save the return value*/  \
        "add esp, 4\n"                                  \
       :  :                                             \
       "r"(eax) , "r"(ebx), "r"(ecx), "r"(esi)          \
   );                                                   \
}                                                       \




#endif