#ifndef ESHELF_DEBUG
#define ESHELF_DEBUG
#include "../../osals/debug.h"

#ifdef ESHELF
    #define TRACE_FORMAT "[INFO] %s %s(line:%u):\n\x00"
    #define TRACE(fmt, ...) trace_handler(__FILE__, __FUNCTION__ ,__LINE__, TRACE_FORMAT, fmt, ##__VA_ARGS__)
#else
    #define TRACE
#endif

#endif