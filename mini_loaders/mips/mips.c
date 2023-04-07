#include "../generic_loader.h"
#include "mips.h"
#define GLIBC_STARTUP
void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x, argc=%x", main_ptr, argc);
    register size_t t9 asm("t9") = (size_t)(main_ptr);
    register size_t a0 asm("a0") = (size_t)(main_ptr);
    register size_t a1 asm("a1") = (size_t)(argc);
    register size_t a2 asm("a2") = (size_t)(argv);
#if !defined(GLIBC_STARTUP)
    asm volatile(
        "jalr $t9\n"
        : :
        "r"(t9), "r"(a0), "r"(a1), "r"(a2)
        : "ra"
    );
#elif defined(GLIBC_STARTUP)
    /* 
        Stack layout:
        [argc]
        [argv]
        NULL
        [envp]
        NULL
        
        A3 stores the total pointers in the stack
    */ 
    register size_t a3 asm("a3") = (size_t)(GLIBC_STACK_SIZE(argc));

    TRACE("Glbic startup is defiend ! stack space = %x", a3);
    asm volatile(
        /*
            In the beging of this routine we substract from the stack.
            first we substract the size of GLIB_STACK_SIZE
            then we make room for the variables we save on the stack.
        */
        "subu $sp, $sp, $a3\n"
        "addiu $sp, $sp, -28\n"
        "sw $a0, 0($sp)\n"
        "sw $a1, 4($sp)\n"
        "sw $a2, 8($sp)\n"
        "sw $a3, 12($sp)\n"
        "sw $t7, 16($sp)\n"
        "sw $t8, 20($sp)\n"
        "sw $t9, 24($sp)\n"


        // Now we are going to load all the variables from the stack
        "lw $a0, 0($sp)\n"
        "lw $a1, 4($sp)\n"
        "lw $a2, 8($sp)\n"
        "lw $a3, 12($sp)\n"
        "lw $t7, 16($sp)\n"
        "lw $t8, 20($sp)\n"
        "lw $t9, 24($sp)\n"
        // Jumping to the prodcedure
        "jalr $t9\n"
        /* Restore all variables here */
        "lw $a3, 12($sp)\n"
        "addiu $sp, $sp, 28\n"
        "addu $sp, $sp, $a3\n"
        : :
        "r"(t9), "r"(a0), "r"(a1), "r"(a2), "r"(a3)
        : "ra"
    );
#endif
    ARCH_FUNCTION_EXIT(return_address);
}