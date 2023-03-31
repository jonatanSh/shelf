#include "../generic_loader.h"
#include "arm32.h"

void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x", main_ptr);
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
    ARCH_FUNCTION_EXIT(return_address);
}