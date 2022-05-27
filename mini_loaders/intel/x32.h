#ifndef LOADER_INTEL_X32
#define LOADER_INTEL_X32
typedef unsigned int size_t;


#ifdef SUPPORT_START_FILES
    #define call_main_stub "jmp eax\n"
#else
    #define call_main_stub "call eax\n"
#endif

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

#define call_main(main_ptr, argc, argv, total_args) {                           \
   register size_t eax asm("eax") = (size_t)(main_ptr); \
   register size_t ebx asm("ebx") = (size_t)(argc);     \
   register size_t ecx asm("ecx") = (size_t)(argv);     \
   register size_t esi asm("esi") = (size_t)((total_args+1) * 4);     \
   asm(                                                 \
        "push_args:\n"                                  \
        "push [ecx+esi]\n"                              \
        "sub esi, 4\n"                                  \
        "cmp esi, 0\n"                                  \
        "jg push_args\n"                               \
        "push ebx\n"                                    \
        call_main_stub                                  \
       :  :                                             \
       "r"(eax), "r"(ebx), "r"(ecx), "r"(esi) \
   );                                                   \
}                                                       \


#endif