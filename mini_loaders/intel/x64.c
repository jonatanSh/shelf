#include "../generic_loader.h"
#include "x64.h"

void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x", main_ptr);
    register size_t rdi asm("rdi") = (size_t)(main_ptr);
    register size_t rsi asm("rsi") = (size_t)(argc);
    register size_t rdx asm("rdx") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "call rdi\n"
        : :
        "r"(rdi), "r"(rsi), "r"(rdx)
        :
    );
#endif
    ARCH_FUNCTION_EXIT(return_address);
}