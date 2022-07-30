#ifndef ESHELF_DEBUG
#define ESHELF_DEBUG
#include "../../osals/debug.h"

void sys_exit(int status);


#ifdef ESHELF
    #define TRACE_FORMAT "[INFO] %s %s(line:%u):\x00"
    #define TRACE(fmt, ...) trace_handler(__FILE__, __FUNCTION__ ,__LINE__, TRACE_FORMAT, fmt, ##__VA_ARGS__)
    #define TEARDOWN sys_exit
#else
    #define TRACE
    #define TEARDOWN(status)
#endif

#define ASSERT(expr) {                          \
    if(!(expr)) {                               \
        TRACE("Asseration failed: %s", #expr);  \
        goto error;                             \
    }                                           \
}                                               \

#endif