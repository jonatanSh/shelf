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
        "subu $sp, $sp, $a3\n" // Substract from stack
        "addiu $sp, $sp, -24\n"
        "sw $a3, 0($sp)\n"
        "sw $t9, 4($sp)\n" // Store t9 into the stack
        "sw $a1, 8($sp)\n" // Store a1 into the stack
        "move $a1, $a2\n" // Get argument vector
        "sw $a2, 12($sp)\n" // Save a2
        "sw $t8, 16($sp)\n"
        "sw $t7, 20($sp)\n"
        "move $t9, $zero\n"
        "addiu $sp, $sp, 24\n" // Moving the stack for the args space
        "sub $s3, 12\n" // All 3 last pointers are null !
        "loop:\n"
        /*
            Here we are going to push all the variables to the stack accordingly
        */
        "addu $a2, $a1, $t9\n" // Points to the current argument
        "addu $t7, $sp, $t9\n" // Current sp
        "sw $a2, 0($t7)\n" // Save that address
        "addiu $t9, $t9, 4\n" // Advance the counter
        "bne $t9, $a3, loop\n"
        "sw $zero, 4($t7)\n" // First null
        "sw $zero, 8($t7)\n" // First null
        "sw $zero, 12($t7)\n" // First null
        "addiu $sp, $sp, -24\n" // Restoring
        "lw $t7, 20($sp)\n"
        "lw $t8, 16($sp)\n"        
        "lw $a2, 12($sp)\n" // Load a2
        "lw $a1, 8($sp)\n" // Load a1 from the stack
        "lw $t9, 4($sp)\n" // Get stored t9
        "jalr $t9\n"
        "lw $a3, 0($sp)\n"
        "addiu $sp, $sp, 24\n"
        "addu $sp, $sp, $a3\n"
        : :
        "r"(t9), "r"(a0), "r"(a1), "r"(a2), "r"(a3)
        : "ra"
    );
#endif
    ARCH_FUNCTION_EXIT(return_address);
}