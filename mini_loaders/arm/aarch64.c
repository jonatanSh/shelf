#include "../generic_loader.h"
#include "arm32.h"

void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    size_t _out;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x", main_ptr);
    register size_t x0 asm("x0") = (size_t)(main_ptr);
    register size_t x1 asm("x1") = (size_t)(argc);
    register size_t x2 asm("x2") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "blr x0\n"
        : "=r"(_out) :
        "r"(x0), "r"(x1), "r"(x2)
        : "x30"
    );
#endif
    ARCH_FUNCTION_EXIT(return_address);
    ARCH_RETURN(_out);
}