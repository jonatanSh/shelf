#include "../generic_loader.h"
#include "riscv64.h"

size_t loader_call_main(size_t main_ptr, int argc, void * argv) {
    size_t _out;
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call 0x%llx", main_ptr);
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
    TRACE("startup code main return: 0x%llx", _out);
    return _out;
}