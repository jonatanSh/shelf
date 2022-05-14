#ifndef LOADER_INTEL_X32
#define LOADER_INTEL_X32
typedef unsigned int size_t;

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
        "get_pc_internal:\n"        \
        "jmp next\n"                \
        "mov eax, [esp]\n"          \
        "ret\n"                     \
        "next:\n"                   \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_main(main_ptr) {                           \
   register size_t eax asm("eax") = (size_t)(main_ptr); \
   asm(                                                 \
        "call eax\n"                                    \
       :  :                                             \
       "r"(eax)                                         \
   );                                                   \
}                                                       \


#endif