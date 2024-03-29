#ifndef GENERIC_LOADER
#define GENERIC_LOADER
#include <stddef.h>
#include "debug.h"
#include "../osals/debug.h"
#include "hooks.h"

// I should check this more carfually.
#define MAX_SEARCH_DEPTH 0x10000


#if defined(__x86_64__) || defined(_M_X64)
    #include "./intel/x64.h"
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #include "./intel/x32.h"
#elif defined(__arm__)
    #include "./arm/arm32.h"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #include "./arm/aarch64.h"
#elif defined(mips) || defined(__mips__) || defined(__mips)
    #include "./mips/mips.h"
#elif defined(__riscv) && defined(__riscv_xlen) && (__riscv_xlen == 64)
    #include "riscv/riscv64.h"
#elif defined(__sh__)
    #error Not Supported
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
    #error Not Supported
#elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
    #error Not Supported
#elif defined(__sparc__) || defined(__sparc)
    #error Not Supported
#elif defined(__m68k__)
    #error Not Supported
#else
    #error Not Supported
#endif



typedef size_t loader_off_t;

#define RELOCATION_BITMASK_NEGATIVE_F_OFFSET (2 << 0)
#define RELOCATION_BITMASK_NEGATIVE_V_OFFSET (2 << 1)

struct table_entry {
    loader_off_t f_offset;
    loader_off_t v_offset;
    loader_off_t bitmask;
};
struct entry_attributes {
    size_t number_of_entries_related_to_attribute;
    size_t relocation_type;
};

enum RELOCATION_ATTRIBUTES {
    GENERIC_RELOCATE = (1 << 0),
    IRELATIVE = (1 << 1),
    RELATIVE_TO_LOADER_BASE = (1 << 2),
    RELATIVE = (1 << 3),
};

typedef void * (*IRELATIVE_T)();


#ifndef TABLE_MAGIC
    #define resolve_table_magic GET_TABLE_MAGIC 
#else
    #define resolve_table_magic() {magic=TABLE_MAGIC;}
#endif

#define advance_pc_to_magic() {                                             \
    size_t i;                                                               \
    TRACE("Pc at search start = 0x%llx, opcode=0x%llx", pc, *((size_t*)pc));                                   \
    for(i = 0; i < MAX_SEARCH_DEPTH; i+=ARCH_OPCODE_SIZE) {                 \
        if(*((size_t*)pc) == magic) {                                       \
            break;                                                          \
        }                                                                   \
        /* Do not write pc+=ARCH_OPCODE_SIZE here, because in some arch \
        Such as mips it produce buggy code*/  \
        pc = pc + ARCH_OPCODE_SIZE;                                             \
    }                                                                       \
    if(i > MAX_SEARCH_DEPTH - 1) {                                          \
        TRACE("Pc search exceded max limit in advance_pc_to_magic macro");  \
    }                                                                       \
    TRACE("Pc at search end = 0x%llx", pc);                                     \
}                                                                           \


#ifndef ARCH_CALL_GET_PC
    #define ARCH_CALL_GET_PC "call get_pc_internal\n"
#endif

#define call_get_pc_generic() {     \
    asm(                            \
        ARCH_CALL_GET_PC            \
        : "=r"(pc) :                \
    );                              \
}                                   \

#ifndef call_get_pc
    #define call_get_pc call_get_pc_generic
#endif

#ifndef ARCH_FUNCTION_ENTER
    #define ARCH_FUNCTION_ENTER()
#endif

#ifndef ARCH_FUNCTION_EXIT
    #define ARCH_FUNCTION_EXIT()
#endif

#ifndef ARCH_TEARDOWN
    #define ARCH_TEARDOWN
#endif

#ifndef ARCH_RETURN
    #define ARCH_RETURN
#endif

#define ARCH_GET_FUNCTION_OUT() {   \
    asm(                            \
        "\n"                        \
        : "=r"(_out)                \
    );                              \
}                                   \

#include "../headers/mini_loader.h"


#define _SET_STATUS(status) {           \
    mini_loader_status = status;        \
    mini_loader_status += __LINE__; \
}                                       \

#ifdef DEBUG
    #define SET_STATUS _SET_STATUS
#else
    #define SET_STATUS
#endif

/* We need to know which hooks where intalized */
#define HOOK_ADDRESS(h) ((h->relative_address - 0xff))

#define LOADER_DISPATCH(function, a1, a2, a3, a4) {                                                                                     \
    TRACE("Dispatching: %s, relative %x, absoulte %x", #function, table->functions.function, (table->functions.function+addresses.loader_base));  \
    call_function((table->functions.function+addresses.loader_base), a1, a2, a3, a4, _dispatcher_out);                                                             \
    TRACE("%s -> _dispatcher_out = %x", #function, _dispatcher_out);                                                                    \
}                                                                                                                                       \

#define _DISPATCH_HOOKS(hooks_base_address, hooks_type, a1, a2, _hook_out) {                                                                         \
    TRACE("HookDispatcher %s, hooks base address = 0x%x", #hooks_type, hooks_base_address);                                         \
    for(size_t i = 0; i < MAX_NUMBER_OF_HOOKS; i++) {                                                                           \
        struct hook * hook = &(table->hook_descriptor.hooks_type[i]);                                                           \
        size_t hook_address = hooks_base_address + HOOK_ADDRESS(hook);                                                      \
        if(hook->relative_address == 0x0) {                                                                                               \
            TRACE("Hook address is null -> not dispatching");                                                                                      \
        }                                                                                                                       \
        else {                                                                                                                      \
            size_t hook_attributes = (hook_address+hook->shellcode_size);                                                           \
            TRACE("Hook relative address = 0x%x, hook address = 0x%x, hook attributes %x", HOOK_ADDRESS(hook), hook_address,    \
            hook_attributes);                                                                                                       \
            TRACE_ADDRESS(hook_address, 24);                                                                                        \
            TRACE_ADDRESS(hook_attributes, 24);                                                                                     \
            call_function(hook_address, table, hook_attributes, a1, a2, _hook_out);                                                          \
        }                                                                                                                       \
    }                                                                                                                           \
}

#ifdef SUPPORT_HOOKS
    #define DISPATCH_HOOKS _DISPATCH_HOOKS
#else
    #define DISPATCH_HOOKS
#endif

#endif