#ifndef OSAL_DEBUG
#define OSAL_DEBUG
#define MAX_DEBUG_BUFFER 0xffff
void trace_handler(const char * terminator, const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...);

#endif