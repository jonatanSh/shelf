#include "../generic_loader.h"
#include "x32.h"

size_t loader_call_main(size_t main_ptr, int argc, void * argv) {
    size_t _out;
    ARCH_FUNCTION_ENTER();
    TRACE("Inside startup code going to call 0x%x", main_ptr);
    TRACE_ADDRESS(main_ptr, 24);
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
        : "=r"(_out) :
        "r"(eax), "r"(ebx), "r"(ecx)
        :
    );
#endif
    return _out;
}