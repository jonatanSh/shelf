#include "../generic_loader.h"
#include "aarch64.h"

size_t loader_call_main(size_t main_ptr, int argc, void * argv) {
    size_t _out;
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call 0x%llx", main_ptr);
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
    return _out;
}