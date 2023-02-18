#ifndef LOADER_GENERIC
#define LOADER_GENERIC
#include <stddef.h>
#include "debug.h"
#include "../osals/debug.h"

// I should check this more carfually.
#define MAX_SEARCH_DEPTH 0x800


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

struct table_entry {
    size_t size;
    loader_off_t f_offset;
    loader_off_t v_offset;
};
struct entry_attributes {
    size_t attribute_1;
};

enum RELOCATION_ATTRIBUTES {
    IRELATIVE = 1,
    RELATIVE_TO_LOADER_BASE = 2,
    RELATIVE = 3,
};

typedef void * (*IRELATIVE_T)();


#ifndef TABLE_MAGIC
    #define resolve_table_magic GET_TABLE_MAGIC 
#else
    #define resolve_table_magic() {magic=TABLE_MAGIC;}
#endif

#define advance_pc_to_magic() {                                             \
    size_t i;                                                               \
    TRACE("Pc at search start = %x", pc);                                   \
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
    TRACE("Pc at search end = %x", pc);                                     \
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
    #define ARCH_FUNCTION_ENTER
#endif

#ifndef ARCH_FUNCTION_EXIT
    #define ARCH_FUNCTION_EXIT
#endif

#ifndef ARCH_TEARDOWN
    #define ARCH_TEARDOWN
#endif

#ifndef ARCH_RETURN
    #define ARCH_RETURN
#endif

#include "../headers/mini_loader.h"


#define _SET_STATUS(status) {           \
    mini_loader_status = status;        \
}                                       \

#ifdef DEBUG
    #define SET_STATUS _SET_STATUS
#else
    #define SET_STATUS
#endif



#endif