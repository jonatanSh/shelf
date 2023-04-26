#include "../generic_loader.h"
#include "riscv64.h"

void startup_code(size_t main_ptr, int argc, void * argv) {
    size_t return_address;
    size_t _out;
    ARCH_FUNCTION_ENTER(&return_address);
    TRACE("Inside startup code going to call %x", main_ptr);
    register size_t a4 asm("a4") = (size_t)(main_ptr);
    register size_t a0 asm("a0") = (size_t)(main_ptr);
    register size_t a1 asm("a1") = (size_t)(argc);
    register size_t a2 asm("a2") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "jalr a4\n"
        : "=r"(_out) :
        "r"(a4), "r"(a0), "r"(a1), "r"(a2)
        : "ra"
    );
#endif
    ARCH_RETURN(_out);
    ARCH_FUNCTION_EXIT(return_address);
}