#ifndef LOADER_GENERIC
#define LOADER_GENERIC

#define MAX_SEARCH_DEPTH 0xffe


#if defined(__x86_64__) || defined(_M_X64)
    #include "./intel/x64.h"
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #include "./intel/x32.h"
#elif defined(__ARM_ARCH_2__)
    #error Not Supported
#elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    #error Not Supported
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    #error Not Supported
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    #error Not Supported
#elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
    #error Not Supported
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    #error Not Supported
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    #error Not Supported
#elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    #error Not Supported
#elif defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    #error Not Supported
#elif defined(__ARM_ARCH_7M__)
    #error Not Supported
#elif defined(__ARM_ARCH_7S__)
    #error Not Supported
#elif defined(__aarch64__) || defined(_M_ARM64)
    #error Not Supported
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

#endif