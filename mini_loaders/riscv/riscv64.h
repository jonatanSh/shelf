#ifndef LOADER_RISCV64
#define LOADER_RISCV64
#include <stddef.h>

#define ARCH_OPCODE_SIZE 4
#define GET_TABLE_MAGIC() {     \
    asm(                        \
        "li %0, 0x8899aabbccddee00\n" \
        "addi %0, %0, 0xff\n"       \
        : "=r"(magic) :         \
    );                          \
}                               \

#define get_pc() {      \
    asm(                            \
        "jal get_pc_internal\n"     \
        "j next\n"                  \
        "get_pc_internal:\n"        \
        "move %0, ra\n"           \
        "jr ra\n"                  \
        "next:"                     \
        : "=r"(pc) :               \
                                    \
    );                              \
}                                   \

#define call_function(main_ptr, arg0, arg1, arg2, arg3) {           \
   register size_t a4 asm("a4") = (size_t)(main_ptr);           \
   register size_t a0 asm("a0") = (size_t)(arg0);               \
   register size_t a1 asm("a1") = (size_t)(arg1);               \
   register size_t a2 asm("a2") = (size_t)(arg2);               \
   register size_t a3 asm("a3") = (size_t)(arg3);               \
   asm(                                                         \
       "addi sp, sp, -4\n"                                   \
       "sw ra, 0(sp)\n"                                       \
       "jalr a4\n"                                             \
       "lw ra, 0(sp)\n"                                       \
       "addi sp, sp, 4\n"                                    \
       :  :                                                     \
       "r"(a4)                                                  \
   );                                                           \
}                                                               \

void startup_code(size_t main_ptr, int argc, void * argv);

#define ARCH_FUNCTION_ENTER(ra) {            \
    register size_t a0 asm("a0");           \
    asm(                                    \
        "move a0, ra\n"                    \
        : :                                 \
        "r"(a0)                             \
    );                                      \
    *ra = a0;                               \
}                                           \

#define ARCH_FUNCTION_EXIT(ra) {          \
   register size_t a0 asm("a0") = (size_t)(ra); \
    asm(                                        \
        "move ra, a0\n"                       \
        : :                                     \
        "r"(a0)                                 \
    );                                          \
}                                               \


#define ARCH_RETURN(_out) {          \
   register size_t a0 asm("a0") = (size_t)(_out); \
   register size_t a1 asm("a1") = (size_t)(*(&_out+sizeof(size_t))); \
    asm(                                        \
        "move a0, %0\n"                       \
        "move a1, %1\n"                       \
        : :                                     \
        "r"(a0),"r"(a1)                         \
    );                                          \
}                                               \

#endif