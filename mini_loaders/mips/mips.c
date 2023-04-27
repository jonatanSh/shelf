#include "../generic_loader.h"
#include "mips.h"

void loader_call_main(size_t main_ptr, int argc, void * argv) {
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call %x", main_ptr);
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
#endif
}