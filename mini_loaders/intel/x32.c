#include "../generic_loader.h"
#include "x32.h"

void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x", main_ptr);
    register size_t eax asm("eax") = (size_t)(main_ptr);
    register size_t ebx asm("ebx") = (size_t)(argc);
    register size_t ecx asm("ecx") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "push ecx\n"
        "push ebx\n"
        "push eax\n"
        "call eax\n"
        "pop ecx\n"
        "pop ebx\n"
        "add esp, 4\n" 
        : :
        "r"(eax), "r"(ebx), "r"(ecx)
        :
    );
#endif
    ARCH_FUNCTION_EXIT(return_address);
}