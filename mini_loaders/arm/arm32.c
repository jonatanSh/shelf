#include "../generic_loader.h"
#include "arm32.h"

void loader_call_main(size_t main_ptr, int argc, void * argv) {
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call 0x%x", main_ptr);
    register size_t r0 asm("r0") = (size_t)(main_ptr);
    register size_t r1 asm("r1") = (size_t)(argc);
    register size_t r2 asm("r2") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "blx r0\n"
        : :
        "r"(r0), "r"(r1), "r"(r2)
        : "lr"
    );
#endif
}