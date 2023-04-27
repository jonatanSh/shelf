#include "../generic_loader.h"
#include "x64.h"

size_t loader_call_main(size_t main_ptr, int argc, void * argv) {
    size_t _out;
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call 0x%llx", main_ptr);
    register size_t rdi asm("rdi") = (size_t)(main_ptr);
    register size_t rsi asm("rsi") = (size_t)(argc);
    register size_t rdx asm("rdx") = (size_t)(argv);

#if !defined(GLIBC_STARTUP)
    asm volatile(
        "call rdi\n"
        : "=r"(_out) :
        "r"(rdi), "r"(rsi), "r"(rdx)
        :
    );
#endif
    return _out;
}