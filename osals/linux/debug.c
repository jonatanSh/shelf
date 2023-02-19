#include <stdarg.h>
#include "../debug.h"

#ifndef WITH_LIBC
    #include "./syscalls_wrapper/unistd.h"
    #include "../sprintf.h"
    #include "../string.h"
#else
    #include <string.h>
    #include <stdio.h>
    #include <unistd.h>
#endif


void trace_handler(const char * terminator,const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];
    // Setting the first char as a null terminator
    // This is important
    debug_buffer[0] = 0x0; 


    if(trace_format) {
        sprintf(debug_buffer,
            trace_format,
            file,
            func,
            line);
    }
    
    va_start (ap, fmt);
    vsprintf(debug_buffer + strlen(debug_buffer),
        fmt,
        ap);
    va_end (ap);
    write(1, debug_buffer, strlen(debug_buffer));
    if(terminator) {
        write(1, terminator, strlen(terminator));
    }

}
