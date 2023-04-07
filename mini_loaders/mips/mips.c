#include "../generic_loader.h"
#include "mips.h"
#define GLIBC_STARTUP

#ifdef GLIBC_STARTUP
    static size_t original_sp = 0x0;
#endif

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
    size_t* elf_sp;
    size_t elf_stack_frame_size;
    size_t i = 0;
    size_t elf_stack_ctr = 0x0;
    size_t my_sp;
    elf_stack_frame_size = GLIBC_STACK_SIZE(argc);
    get_stack_pointer(my_sp);
    original_sp = my_sp;
    elf_sp = original_sp - elf_stack_frame_size;
    
    register size_t a3 asm("a3") = (size_t)(elf_stack_frame_size);
    TRACE("Glbic startup is defiend ! stack space = 0x%x,sp=0x%0x, elf_sp=0x%0x",
     a3, original_sp, elf_sp);
    elf_sp[elf_stack_ctr++] = argc;
    while(i++ < argc) {
        elf_sp[elf_stack_ctr++] = ((size_t*)(argv))[i-1]; 
    }
    // Null for argv
    elf_sp[elf_stack_ctr++] = 0x0;
    // Null for envp
    elf_sp[elf_stack_ctr++] = 0x0;

    

    a3 = elf_sp;
    // Finally call main
    asm volatile(
        "move $sp, $a3\n"
        "jalr $t9\n"
        : :
        "r"(t9), "r"(a0), "r"(a1), "r"(a2), "r"(a3)
        : "ra"
    );
    a3 = original_sp;
    asm volatile(
        "move $sp, $a3\n"
        : :
        "r"(a3)
    );

#endif
    ARCH_FUNCTION_EXIT(return_address);
}