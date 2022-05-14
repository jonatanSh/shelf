#ifndef LOADER_GENERIC
#define LOADER_GENERIC

#define MAX_SEARCH_DEPTH 0x200


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



struct table_entry {
    size_t size;
    size_t f_offset;
    size_t v_offset;
};
struct relocation_table {
    size_t magic;
    size_t total_size;
};

struct entry_attributes {
    size_t attribute_1;
};

enum RELOCATION_ATTRIBUTES {
    IRELATIVE = 1
};

typedef void * (*IRELATIVE_T)();


#endif