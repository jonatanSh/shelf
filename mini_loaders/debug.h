#ifndef DEBUG_HEADER
#define DEBUG_HEADER

#if defined(ESHELF) || defined(HOOK_OSAL)
    #define TRACE_FORMAT "[INFO] %s %s(line:%u):\x00"
    #define TRACE_TERMINATOR "\n"
    #define TRACE(fmt, ...) trace_handler(TRACE_TERMINATOR,__FILE__, __FUNCTION__ ,__LINE__, TRACE_FORMAT, fmt, ##__VA_ARGS__)
    #define WRITE(fmt, ...) trace_handler(NULL,__FILE__, __FUNCTION__ ,__LINE__, NULL, fmt, ##__VA_ARGS__)
    #define TEARDOWN exit
#else
    #define TRACE
    #define WRITE
    #define TEARDOWN ARCH_TEARDOWN
#endif

#define TRACE_ADDRESS(address, size) {                          \
    TRACE("Displaying address %x, size %x", address, size);     \
    for(int _j = 0; _j < size; _j++) {                          \
        WRITE("0x%02x ", *(unsigned char*)(address+_j));        \
    }                                                           \
    WRITE("\n");                                                \
}                                                               \


#define ASSERT(expr, status) {                          \
    if(!(expr)) {                                       \
        TRACE("Asseration failed: %s", #expr);          \
        SET_STATUS((status << 24));     \
        goto error;                                     \
    }                                                   \
}                                                       \

#define _ASSERT(expr, new_status) {                     \
    if(!(expr)) {                                       \
        TRACE("Asseration failed: %s", #expr);          \
        status = new_status;                            \
        goto error;                                     \
    }                                                   \
}                                                       \

#endif